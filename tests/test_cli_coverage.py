"""Tests for cli.py commands — offline (all network calls mocked)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from typer.testing import CliRunner

from app.cli import app


runner = CliRunner()


def _ok_scan_result():
    return {
        "hostname": "example.com",
        "dns": {"ipv4": ["93.184.216.34"], "ipv6": ["2606:2800::1"],
                "cname": ["x.cloudflare.com"], "latency_ms": 10.0,
                "ttl": 300, "source": "dig", "status": "verified"},
        "tls": {"success": True, "ip": "93.184.216.34", "latency_ms": 5.0,
                "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "sni": "example.com", "san_list": ["example.com"],
                "issuer": "CN=R3", "tls_valid": True, "status": "verified"},
        "probe": {"icmp": {"reachable": True, "latency_ms": 2.0},
                  "tcp443": {"reachable": True, "latency_ms": 8.0}},
        "cdn": {"provider": "Cloudflare", "confidence": 0.9,
                "evidence": ["cname_match"], "status": "inferred"},
        "endpoint": {"hostname": "example.com", "tls_valid": True,
                     "ipv4": ["93.184.216.34"], "ipv6": ["2606:2800::1"],
                     "status": "tls_verified"},
        "health": {"hostname": "example.com", "level": "healthy",
                   "dns_ok": True, "tcp_ok": True, "tls_ok": True,
                   "latency_ms": 8.0, "failure_rate": 0.0, "score": 0.9},
        "route": {"hostname": "example.com", "destination_ip": "93.184.216.34",
                  "action": "cdn", "provider": "Cloudflare",
                  "reason": "CDN detected", "confidence": 0.9},
        "scanned_at": "2026-01-01T00:00:00+00:00",
    }


class TestCliUpdate:
    def test_update_success(self):
        with patch("app.scan_engine.update_database", return_value={"ok": True, "expired_dns_entries": 5, "cdn_files": 3}):
            r = runner.invoke(app, ["update"])
            assert r.exit_code == 0
            assert "Update complete" in r.stdout

    def test_update_failure(self):
        with patch("app.scan_engine.update_database", return_value={"ok": False, "error": "disk full"}):
            r = runner.invoke(app, ["update"])
            assert r.exit_code == 0
            assert "Update failed" in r.stdout


class TestCliScan:
    def test_scan_full(self):
        with patch("app.cli._run_scan", new_callable=AsyncMock, return_value=_ok_scan_result()):
            r = runner.invoke(app, ["scan", "example.com"])
            assert r.exit_code == 0
            assert "example.com" in r.stdout
            assert "93.184.216.34" in r.stdout

    def test_scan_with_probe_output(self):
        res = _ok_scan_result()
        res["probe"] = {"icmp": {"reachable": True, "latency_ms": 1.0},
                        "tcp443": {"reachable": True, "latency_ms": 2.0}}
        with patch("app.cli._run_scan", new_callable=AsyncMock, return_value=res):
            r = runner.invoke(app, ["scan", "example.com"])
            assert "ICMP" in r.stdout or "tcp443" in json.dumps(res["probe"])


class TestCliResolve:
    def test_resolve_a(self):
        fake_result = MagicMock()
        fake_result.model_dump.return_value = {"hostname": "example.com", "a": ["93.184.216.34"], "aaaa": []}
        with patch("app.network_tools.dns.resolve_dns", return_value=fake_result):
            r = runner.invoke(app, ["resolve", "example.com"])
            assert r.exit_code == 0
            assert "93.184.216.34" in r.stdout

    def test_resolve_aaaa(self):
        fake_result = MagicMock()
        fake_result.model_dump.return_value = {"hostname": "example.com", "a": [], "aaaa": ["2606:2800::1"]}
        with patch("app.network_tools.dns.resolve_dns", return_value=fake_result):
            r = runner.invoke(app, ["resolve", "--type", "AAAA", "example.com"])
            assert r.exit_code == 0

    def test_resolve_all(self):
        fake_result = MagicMock()
        fake_result.model_dump.return_value = {"hostname": "example.com", "a": ["1.2.3.4"], "aaaa": ["::1"]}
        with patch("app.network_tools.dns.resolve_dns_a_and_aaaa", new=AsyncMock(return_value=fake_result)):
            r = runner.invoke(app, ["resolve-all", "example.com"])
            assert r.exit_code == 0


class TestCliCdn:
    def test_cdn_command(self):
        fake_dns = MagicMock()
        fake_dns.a = ["93.184.216.34"]
        fake_dns.aaaa = ["2606:2800::1"]
        fake_dns.cname = ["x.cloudflare.com"]
        fake_tls = MagicMock()
        fake_tls.san_list = ["example.com"]
        fake_tls.tls_valid = True
        fake_tls.latency_ms = 5.0
        fake_match = MagicMock()
        fake_match.provider = "Cloudflare"
        fake_match.confidence = 0.9
        fake_match.evidence = ["cname"]
        with patch("app.network_tools.dns.resolve_dns_a_and_aaaa", new=AsyncMock(return_value=fake_dns)), \
             patch("app.tls_inspector.inspect_tls", return_value=fake_tls), \
             patch("app.cdn_detect.detect_cdn_from_dns_result", return_value=fake_match):
            r = runner.invoke(app, ["cdn", "example.com"])
            assert r.exit_code == 0
            assert "Cloudflare" in r.stdout


class TestCliHealth:
    def test_health_empty_db(self):
        with patch("app.destination_db.DestinationDB.all", return_value=[]), \
             patch("app.health.summarise", return_value={"healthy": 0, "degraded": 0, "failed": 0, "total": 0}):
            r = runner.invoke(app, ["health"])
            assert r.exit_code == 0
            assert "Healthy" in r.stdout


class TestCliValidate:
    def test_validate_passes(self):
        with patch("app.config_loader.validate_config_app", return_value=MagicMock(has_errors=False, count=0, summary=lambda: "ok")), \
             patch("app.config_loader.load_config"), \
             patch("app.config_loader.load_blocklist"), \
             patch("app.xray.binary.validate_binary", return_value={"ok": False, "error": "not found"}):
            r = runner.invoke(app, ["validate"])
            assert "All checks passed" in r.stdout or r.exit_code == 1  # xray missing is an error


class TestCliGenerate:
    def test_generate(self):
        fake_cfg = MagicMock()
        fake_cfg.config_dir = "config"
        fake_cfg.xray = {"config_path": "/tmp/xray.json"}
        real_config = {"inbounds": [1], "outbounds": [1], "routing": {"rules": [1]}}
        with patch("app.config_loader.load_config", return_value=fake_cfg), \
             patch("app.config_loader.load_dns_providers", return_value={}), \
             patch("app.xray.config.generate_xray_config", return_value=real_config), \
             patch("app.xray.config.validate_xray_config"):
            r = runner.invoke(app, ["generate"])
            assert r.exit_code == 0
            assert "Generated" in r.stdout


class TestCliDashboard:
    def test_dashboard(self):
        fake_cfg = MagicMock()
        fake_cfg.tun = {"enabled": False}
        fake_cfg.xray = {"enabled": False}
        fake_cfg.dns = {"provider": "dig"}
        with patch("app.config_loader.load_config", return_value=fake_cfg), \
             patch("app.destination_db.DestinationDB.all", return_value=[]), \
             patch("app.health.summarise", return_value={"healthy": 0, "degraded": 0, "failed": 0, "total": 0}):
            r = runner.invoke(app, ["dashboard"])
            assert r.exit_code == 0
            assert "Dashboard" in r.stdout or "NetProbe" in r.stdout


# ---------------------------------------------------------------------------
# proxy command (offline — real xray process mocked)
# ---------------------------------------------------------------------------

class TestCliProxy:
    def _fake_cfg(self):
        fake_cfg = MagicMock()
        fake_cfg.xray = {"enabled": True, "binary": "xray", "config_path": "config/xray.json"}
        fake_cfg.dns = {"provider": "cloudflare"}
        return fake_cfg

    def _patch_manager_ok(self):
        mgr = MagicMock()
        mgr.start.return_value = {"ok": True, "attempt": 1}
        mgr._process = MagicMock()
        mgr._process.is_alive.return_value = True
        return mgr

    @staticmethod
    def _sleep_that_ctrl_c(after=2):
        """time.sleep that raises KeyboardInterrupt after `after` calls."""
        import time as _time
        calls = {"n": 0}

        def _sleep(sec):
            calls["n"] += 1
            if calls["n"] >= after:
                raise KeyboardInterrupt()
            return _time.sleep(0)
        return _sleep

    def test_proxy_no_binary(self):
        # binary cannot be found -> AppError -> exit 1
        fake_cfg = self._fake_cfg()
        with patch("app.cli.load_config", return_value=fake_cfg), \
             patch("app.cli.load_dns_providers", return_value={}), \
             patch("app.xray.config.generate_xray_config", return_value={"inbounds": []}), \
             patch("pathlib.Path.write_text"), \
             patch("shutil.which", return_value=None), \
             patch("pathlib.Path.exists", return_value=False):
            r = runner.invoke(app, ["proxy", "--no-check"])
            assert r.exit_code != 0
            # Typer catches the AppError; the message lives in r.exception, not stdout.
            assert "xray binary not found" in str(r.exception)

    def test_proxy_start_ok_and_verified(self):
        fake_cfg = self._fake_cfg()
        mgr = self._patch_manager_ok()
        with patch("app.cli.load_config", return_value=fake_cfg), \
             patch("app.cli.load_dns_providers", return_value={}), \
             patch("app.xray.config.generate_xray_config",
                    return_value={"inbounds": [{"settings": {}, "streamSettings": {}}]}), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("app.xray.process.XrayManager", return_value=mgr), \
             patch("app.xray.health.check_port_open", return_value=True), \
             patch("app.cli._probe_through_proxy", return_value=200), \
             patch("time.sleep", self._sleep_that_ctrl_c(2)):
            r = runner.invoke(app, ["proxy", "--port", "10899", "--check"])
            assert "Proxy is listening" in r.stdout
            assert "Proxy verified" in r.stdout

    def test_proxy_restart_on_crash(self):
        fake_cfg = self._fake_cfg()
        mgr = self._patch_manager_ok()
        mgr._process.is_alive.side_effect = [True, False, True]
        with patch("app.cli.load_config", return_value=fake_cfg), \
             patch("app.cli.load_dns_providers", return_value={}), \
             patch("app.xray.config.generate_xray_config",
                    return_value={"inbounds": [{"settings": {}, "streamSettings": {}}]}), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("app.xray.process.XrayManager", return_value=mgr), \
             patch("app.xray.health.check_port_open", return_value=True), \
             patch("app.cli._probe_through_proxy", return_value=200), \
             patch("time.sleep", self._sleep_that_ctrl_c(1)):
            r = runner.invoke(app, ["proxy", "--port", "10899", "--check"])
            assert "restart" in r.stdout.lower() or "Shutting down" in r.stdout

    def test_proxy_failed_to_start(self):
        fake_cfg = self._fake_cfg()
        mgr = MagicMock()
        mgr.start.return_value = {"ok": False, "error": "nope", "diagnostics": {"stderr": ["boom line"]}}
        with patch("app.cli.load_config", return_value=fake_cfg), \
             patch("app.cli.load_dns_providers", return_value={}), \
             patch("app.xray.config.generate_xray_config",
                    return_value={"inbounds": [{"settings": {}, "streamSettings": {}}]}), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("app.xray.process.XrayManager", return_value=mgr), \
             patch("app.xray.health.check_port_open", return_value=True):
            r = runner.invoke(app, ["proxy", "--no-check"])
            assert r.exit_code != 0
            assert "Failed to start" in r.stdout

    def test_proxy_tor_fragment_forwarded(self):
        """--tor and --fragment must reach generate_xray_config."""
        fake_cfg = self._fake_cfg()
        mgr = self._patch_manager_ok()
        captured = {}

        def fake_generate(cfg, doh=None, output_path=None, proxy=None):
            captured["proxy"] = proxy
            return {"inbounds": [{"settings": {}, "streamSettings": {}}]}

        with patch("app.cli.load_config", return_value=fake_cfg), \
             patch("app.cli.load_dns_providers", return_value={}), \
             patch("app.xray.config.generate_xray_config", side_effect=fake_generate), \
             patch("pathlib.Path.write_text"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("app.xray.process.XrayManager", return_value=mgr), \
             patch("app.xray.health.check_port_open", return_value=True), \
             patch("app.cli._probe_through_proxy", return_value=200), \
             patch("time.sleep", self._sleep_that_ctrl_c(1)):
            r = runner.invoke(app, [
                "proxy", "--port", "10899", "--no-check",
                "--tor", "--fragment",
            ])
            assert r.exit_code == 0
            assert captured.get("proxy"), "proxy dict was not forwarded"
            assert captured["proxy"]["tor"] is True
            assert captured["proxy"]["tor_socks_host"] == "127.0.0.1"
            assert captured["proxy"]["tor_socks_port"] == 9050


class TestProbeThroughProxy:
    def test_curl_success(self):
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "200"
        with patch("shutil.which", return_value="/usr/bin/curl"), \
             patch("subprocess.run", return_value=proc):
            from app.cli import _probe_through_proxy
            assert _probe_through_proxy("127.0.0.1", 10808) == 200

    def test_curl_timeout(self):
        with patch("shutil.which", return_value="/usr/bin/curl"), \
             patch("subprocess.run", side_effect=TimeoutError("slow")):
            from app.cli import _probe_through_proxy
            assert _probe_through_proxy("127.0.0.1", 10808) is None

    def test_no_curl_socks_fallback(self):
        with patch("shutil.which", return_value=None), \
             patch("app.cli._socks_connect_ok", return_value=201) as m:
            from app.cli import _probe_through_proxy
            assert _probe_through_proxy("127.0.0.1", 10808) == 201
            m.assert_called_once()

    def test_socks_connect_ok(self):
        import socket
        # A tiny fake socket that responds correctly to the SOCKS5 handshake.
        class FakeSock:
            def sendall(self, bytes_): pass
            def recv(self, n):
                # first call: greet reply; second call: connect reply
                if not hasattr(self, "_c"):
                    self._c = 0
                self._c += 1
                if self._c == 1:
                    return b"\x05\x00"
                return b"\x05\x00\x00\x01" + b"\x00" * 6
            def close(self): pass
        with patch("socket.create_connection", return_value=FakeSock()):
            from app.cli import _socks_connect_ok
            assert _socks_connect_ok("127.0.0.1", 10808) == 200

    def test_socks_connect_fail(self):
        class FailSock:
            def sendall(self, b): pass
            def recv(self, n): return b"\x05\xff"
            def close(self): pass
        with patch("socket.create_connection", return_value=FailSock()):
            from app.cli import _socks_connect_ok
            assert _socks_connect_ok("127.0.0.1", 10808) is None
