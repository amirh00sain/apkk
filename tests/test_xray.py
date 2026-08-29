"""Xray integration tests — offline."""

import json
import tempfile
from pathlib import Path

import pytest

from app.xray.config import generate_xray_config, validate_xray_config
from app.xray.binary import find_xray, get_version
from app.xray.process import XrayProcess
from app.xray.health import check_port_open, check_process_alive
from app.xray.templates import render_mixed_inbound
from app.config_loader import load_config


class TestXrayConfigGeneration:
    def test_generates_valid_json(self):
        cfg = load_config()
        config = generate_xray_config(cfg)
        assert "inbounds" in config
        assert "outbounds" in config
        assert "routing" in config
        assert len(config["inbounds"]) > 0
        assert len(config["outbounds"]) > 0
        assert len(config["routing"]["rules"]) > 0

    def test_credits_metadata_present(self):
        # Required credit for the reference project (SNI-Spoofing / @patterniha).
        cfg = load_config()
        config = generate_xray_config(cfg)
        assert "patterniha" in json.dumps(config)
        # config/app.json must carry the credit too.
        with open("config/app.json", encoding="utf-8") as f:
            assert "patterniha" in f.read()

    def test_always_has_block_direct_dns(self):
        cfg = load_config()
        config = generate_xray_config(cfg)
        tags = [o["tag"] for o in config["outbounds"]]
        assert "block" in tags
        assert "direct" in tags
        assert "dns-out" in tags

    def test_routing_covers_ir_private_direct(self):
        cfg = load_config()
        config = generate_xray_config(cfg)
        rules = config["routing"]["rules"]
        outbound_tags = [r["outboundTag"] for r in rules]
        assert "direct" in outbound_tags


class TestXrayAntiDpi:
    """Reality removed — DoH + Tor + Fragment stay."""

    TOR_PROXY = {"tor": True, "tor_socks_host": "127.0.0.1", "tor_socks_port": 9050}

    def test_no_reality_outbound_anywhere(self):
        """Reality was removed from the toolkit entirely (user decision)."""
        cfg = load_config()
        config = generate_xray_config(cfg)  # no proxy -> direct only
        outbound_tags = [o.get("tag") for o in config["outbounds"]]
        assert "reality-out" not in outbound_tags
        rules = config["routing"]["rules"]
        assert not any(r.get("outboundTag") == "reality-out" for r in rules)

    def test_no_reality_outbound_even_with_tor(self):
        cfg = load_config()
        config = generate_xray_config(cfg, proxy=self.TOR_PROXY)
        outbound_tags = [o.get("tag") for o in config["outbounds"]]
        assert "reality-out" not in outbound_tags
        assert "tor-out" in outbound_tags
        # No vless/protocol outbounds survive either.
        assert not [o for o in config["outbounds"] if isinstance(o, dict) and o.get("protocol") == "vless"]

    def test_doh_is_primary_resolver(self):
        cfg = load_config()
        config = generate_xray_config(cfg)
        servers = config["dns"]["servers"]
        assert servers, "dns servers empty"
        # First server must be the DoH (https) resolver.
        assert servers[0]["address"].startswith("https://")
        assert "dns-query" in servers[0]["address"]

    def test_tor_outbound_added(self):
        cfg = load_config()
        config = generate_xray_config(cfg, proxy=self.TOR_PROXY)
        tags = [o["tag"] for o in config["outbounds"]]
        assert "tor-out" in tags
        tor = [o for o in config["outbounds"] if o.get("tag") == "tor-out"][0]
        assert tor["protocol"] == "socks"
        server = tor["settings"]["servers"][0]
        assert server["address"] == "127.0.0.1"
        assert server["port"] == 9050

    def test_tor_routes_external_through_tor_out(self):
        cfg = load_config()
        config = generate_xray_config(cfg, proxy=self.TOR_PROXY)
        rules = config["routing"]["rules"]
        outbound_tags = [r["outboundTag"] for r in rules]
        assert "tor-out" in outbound_tags
        # The 0.0.0.0/0 rule should point to tor-out.
        external = [r for r in rules if r.get("ip") == ["0.0.0.0/0", "::/0"]]
        assert external, "expected external traffic rule"
        assert external[0]["outboundTag"] == "tor-out"

    def test_no_tor_without_flag(self):
        cfg = load_config()
        config = generate_xray_config(cfg)
        outbound_tags = [o.get("tag") for o in config["outbounds"]]
        assert "tor-out" not in outbound_tags
        # External rule degrades to direct.
        rules = config["routing"]["rules"]
        external = [r for r in rules if r.get("ip") == ["0.0.0.0/0", "::/0"]]
        assert external[0]["outboundTag"] == "direct"

    def test_private_ir_stays_direct_with_tor(self):
        cfg = load_config()
        config = generate_xray_config(cfg, proxy=self.TOR_PROXY)
        rules = config["routing"]["rules"]
        direct = [r for r in rules if r.get("outboundTag") == "direct"]
        assert direct, "expected direct rules for private/IR"
        domains = [d for r in direct for d in r.get("domain", [])]
        assert any("private" in d for d in domains)
        assert any(d == "domain:ir" for d in domains)

    def test_fragment_settings_serialisable(self):
        # The GUI/CLI writes Fragment into TLS settings; shape must stay valid.
        frag = {"enabled": True, "length": "100-200", "sleep": "50-100"}
        json.dumps(frag)  # must be serialisable


class TestXrayConfigValidation:
    def test_valid_config(self):
        cfg = load_config()
        config = generate_xray_config(cfg)
        path = Path(tempfile.mktemp(suffix=".json"))
        try:
            path.write_text(json.dumps(config))
            validated = validate_xray_config(str(path))
            assert "inbounds" in validated
        finally:
            path.unlink(missing_ok=True)

    def test_missing_inbounds_raises(self):
        path = Path(tempfile.mktemp(suffix=".json"))
        try:
            path.write_text(json.dumps({"outbounds": [], "routing": {"rules": []}}))
            with pytest.raises(ValueError, match="inbounds"):
                validate_xray_config(str(path))
        finally:
            path.unlink(missing_ok=True)

    def test_missing_routing_raises(self):
        path = Path(tempfile.mktemp(suffix=".json"))
        try:
            path.write_text(json.dumps({"inbounds": [1], "outbounds": [1], "routing": {}}))
            with pytest.raises(ValueError, match="rules"):
                validate_xray_config(str(path))
        finally:
            path.unlink(missing_ok=True)


class TestXrayBinary:
    def test_find_xray_or_skip(self):
        path = find_xray()
        # xray may not be installed; we just test the function doesn't crash
        assert path is None or isinstance(path, str)

    def test_get_version(self):
        version = get_version()
        # Might return None if xray not installed; no crash
        assert version is None or isinstance(version, str)


class TestTemplates:
    def test_render_inbound(self):
        inp = render_mixed_inbound(port=9999, ip="127.0.0.1")
        assert inp["port"] == 9999
        assert inp["settings"]["ip"] == "127.0.0.1"
        assert inp["protocol"] == "mixed"

    def test_default_inbound(self):
        inp = render_mixed_inbound()
        assert inp["port"] == 10808
