"""Configuration & CLI tests."""

import json
import tempfile
from pathlib import Path

import pytest

from app.config_loader import (
    AppConfig,
    load_config,
    load_blocklist,
    load_dns_providers,
    load_profiles,
    validate_config_app,
    validate_hostname_safe,
)
from app.errors import ErrorCollector
from app.profiles import get_profile, is_gaming_profile, DEFAULT_PROFILES
from app.models import EndpointRecord, RecordStatus, RouteAction


class TestAppConfig:
    def test_defaults_when_no_file(self, tmp_path):
        cfg = load_config(tmp_path)
        assert cfg.mode == "lab"
        assert cfg.tun["enabled"] is False
        assert cfg.dns["provider"] == "cloudflare"

    def test_merge_overrides(self, tmp_path):
        (tmp_path / "app.json").write_text(json.dumps({"mode": "research", "tun": {"mtu": 1400}}))
        cfg = load_config(tmp_path)
        assert cfg.mode == "research"
        assert cfg.tun["mtu"] == 1400
        assert cfg.tun["enabled"] is False  # inherited from defaults

    def test_validate_config_app_bad_mode(self, tmp_path):
        (tmp_path / "app.json").write_text(json.dumps({"mode": "badmode"}))
        cfg = load_config(tmp_path)
        ec = validate_config_app(cfg)
        assert ec.has_errors

    def test_validate_config_app_good(self, tmp_path):
        (tmp_path / "app.json").write_text(json.dumps({"mode": "lab", "tun": {"mtu": 1500}}))
        cfg = load_config(tmp_path)
        ec = validate_config_app(cfg)
        assert not ec.has_errors


class TestBlocklist:
    def test_load_blocklist(self):
        cidrs = load_blocklist("config")
        assert "10.10.34.0/24" in cidrs
        assert "2001:4188:2:600::/64" in cidrs

    def test_invalid_cidr_raises(self, tmp_path):
        (tmp_path / "blocklist.json").write_text(json.dumps({"cidrs": ["badcidr"]}))
        with pytest.raises(Exception):
            load_blocklist(tmp_path)


class TestProfiles:
    def test_gaming_profile(self):
        p = get_profile("gaming_measurement")
        assert p["packet_manipulation"] is False
        assert p["laboratory_setting"] is False
        assert p["quic_policy"] == "prefer"
        assert is_gaming_profile("gaming_measurement") is True

    def test_baseline_profile(self):
        p = get_profile("baseline")
        assert p["packet_manipulation"] is False

    def test_unknown_profile_falls_back_to_baseline(self):
        p = get_profile("nonexistent_profile")
        assert p["prefer_ipv6"] == DEFAULT_PROFILES["baseline"]["prefer_ipv6"]


class TestModels:
    def test_endpoint_record(self):
        r = EndpointRecord(hostname="example.com", provider="Cloudflare", ipv4=["1.2.3.4"])
        assert r.status == RecordStatus.OBSERVED
        assert "1.2.3.4" in r.ipv4

    def test_route_decision(self):
        from app.models import RouteDecision
        d = RouteDecision(hostname="x", destination_ip="1.2.3.4", action=RouteAction.DIRECT)
        assert d.action == RouteAction.DIRECT


class TestValidation:
    def test_validate_hostname_safe(self):
        assert validate_hostname_safe("example.com") == "example.com"
        with pytest.raises(Exception):
            validate_hostname_safe("bad name!")


class TestErrorCollector:
    def test_merge(self):
        ec1 = ErrorCollector()
        ec2 = ErrorCollector()
        ec1.add("test", "msg1")
        ec2.add("test", "msg2")
        ec1.merge(ec2)
        assert ec1.count == 2

    def test_summary_empty(self):
        ec = ErrorCollector()
        assert "No errors" in ec.summary()

    def test_summary_with_errors(self):
        ec = ErrorCollector()
        ec.add("cat1", "msg1")
        s = ec.summary()
        assert "msg1" in s
        assert "cat1" in s
