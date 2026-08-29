"""Tests for scan_engine.py and failover.py (offline, mocked network ops)."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest

from app.scan_engine import scan_hostname, update_database
from app.failover import check_health_one_ip, failover, failover_with_fresh_dns
from app.models import EndpointRecord, DNSResult, CDNMatch, TLSResult
from app.cdn_detect import detect_cdn


def _fake_dns(hostname):
    return DNSResult(hostname=hostname, a=["93.184.216.34"], aaaa=["2606:2800::1"],
                    cname=["x.cloudflare.com"], ttl=300, source="dnspython", latency_ms=10.0)


def _fake_tls():
    return TLSResult(hostname="example.com", ip="93.184.216.34", sni="example.com",
                     san_list=["example.com"], success=True, tls_valid=True, latency_ms=12.0)


class FakeProbe:
    def model_dump(self):
        return {"host": "example.com",
                "icmp": {"reachable": True, "latency_ms": 5.0},
                "tcp443": {"reachable": True, "latency_ms": 10.0},
                "tls": {"reachable": True, "latency_ms": 12.0}}


class FakeRoute:
    def __init__(self, action="cdn"):
        self.action = type("A", (), {"value": action})()
        self.provider = "Cloudflare" if action == "cdn" else None
        self.confidence = 0.9 if action == "cdn" else 0.0
        self.reason = "CDN detected" if action == "cdn" else ""
        self.destination_ip = "93.184.216.34" if action == "cdn" else ""
        self.hostname = "example.com"
    def model_dump(self):
        return {"action": self.action.value}


class TestScanHostname:
    def test_full_scan(self, tmp_path):
        with patch("app.scan_engine.resolve_dns_a_and_aaaa", new=AsyncMock(side_effect=_fake_dns)), \
             patch("app.tls_inspector.inspect_tls", return_value=_fake_tls()), \
             patch("app.scan_engine.probe_host", return_value=FakeProbe()), \
             patch("app.route_engine.RouteEngine.decide", return_value=FakeRoute()):
            result = asyncio.run(scan_hostname("example.com", data_dir=tmp_path))
            assert result["hostname"] == "example.com"
            assert result["dns"]["ipv4"] == ["93.184.216.34"]
            assert result["tls"]["success"] is True
            assert result["endpoint"]["tls_valid"] is True
            assert "health" in result
            assert "route" in result
            assert "scanned_at" in result

    def test_scan_no_tls(self, tmp_path):
        with patch("app.scan_engine.resolve_dns_a_and_aaaa", new=AsyncMock(side_effect=_fake_dns)), \
             patch("app.scan_engine.probe_host", return_value=FakeProbe()), \
             patch("app.route_engine.RouteEngine.decide", return_value=FakeRoute("unknown")):
            result = asyncio.run(scan_hostname("example.com", do_tls=False, data_dir=tmp_path))
            assert result["tls"]["success"] is False


class TestUpdateDatabase:
    def test_update_creates_files(self, tmp_path):
        res = update_database(tmp_path)
        assert res["ok"] is True
        assert (tmp_path / "cdn" / "cloudflare-v4.json").exists()
        # Second run should not fail.
        res2 = update_database(tmp_path)
        assert res2["ok"] is True


class TestFailover:
    def test_check_health_one_ip(self):
        with patch("app.failover.TcpProber") as mock_tcp, patch("app.failover.tls_inspect") as mock_tls:
            mock_tcp.return_value.probe.return_value = {"reachable": True, "latency_ms": 10.0}
            mock_tls.return_value = type("T", (), {"success": True})()
            r = check_health_one_ip("93.184.216.34")
            assert r["tcp_ok"] is True
            assert r["tls_ok"] is True

    def test_check_health_tcp_fails(self):
        with patch("app.failover.TcpProber") as mock_tcp:
            mock_tcp.return_value.probe.return_value = {"reachable": False, "latency_ms": None}
            r = check_health_one_ip("203.0.113.5")
            assert r["tcp_ok"] is False
            assert r["tls_ok"] is False

    def test_failover_orders_healthy(self):
        with patch("app.failover.check_health_one_ip") as m_chk:
            def side(ip):
                return {"ip": ip, "tcp_ok": ip != "192.0.2.1", "tcp_latency_ms": 1.0, "tls_ok": True}
            m_chk.side_effect = side
            ep = EndpointRecord(hostname="example.com", ipv4=["192.0.2.1", "93.184.216.34"],
                               ipv6=["2606:2800::1"])
            out = failover("example.com", ep)
            assert "192.0.2.1" not in out.ipv4
            assert out.status == "fresh"

    def test_failover_all_fail(self):
        with patch("app.failover.check_health_one_ip", return_value={"ip": "x", "tcp_ok": False}):
            ep = EndpointRecord(hostname="example.com", ipv4=["198.51.100.1"])
            out = failover("example.com", ep)
            assert out.status == "failed"
            assert out.ipv4 == []

    def test_failover_with_fresh_dns_recover(self):
        # First round: original IP fails. Fresh DNS round adds a new IP that succeeds.
        def _side(ip):
            return {"ip": ip, "tcp_ok": ip == "203.0.113.9", "tcp_latency_ms": 1.0, "tls_ok": True}
        with patch("app.failover.check_health_one_ip", side_effect=_side), \
             patch("app.network_tools.dns.resolve_dns_a_and_aaaa", new=AsyncMock(
                 return_value=DNSResult(hostname="example.com", a=["203.0.113.9"]))):
            ep = EndpointRecord(hostname="example.com", ipv4=["198.51.100.1"])
            out = asyncio.run(failover_with_fresh_dns("example.com", ep))
            assert "203.0.113.9" in out.ipv4
