"""Tests for network_tools/route.py, security.py edge cases, logger, metrics, errors, models."""

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app.network_tools import route as route_mod
from app.security import (
    validate_hostname,
    validate_ip,
    validate_cidr,
    validate_port,
    validate_path,
    validate_json,
    safe_subprocess_args,
    is_private_ip,
    build_block_networks,
    is_blocked,
    ValidationError,
)
from app.logger import AppLogger, JsonFormatter, get_logger
from app.metrics import Metrics, default_metrics
from app.errors import AppError, ErrorCollector
from app.models import (
    DNSResult, TLSResult, ProbeResult, CDNProvider, CDNMatch, EndpointRecord,
    RouteDecision, HealthScore, LogEntry, RecordStatus, RouteAction, HealthLevel,
)


class TestRouteTools:
    def test_ip_route_get(self):
        out = json.dumps([{"dst": "8.8.8.8", "dev": "eth0", "gateway": "10.0.0.1"}])
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
            r = route_mod.ip_route_get("8.8.8.8")
            assert r["ok"] is True
            assert r["dst"] == "8.8.8.8"

    def test_ip_route_get_fail(self):
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr="no route")
            r = route_mod.ip_route_get("8.8.8.8")
            assert r["ok"] is False

    def test_ip_addr_show(self):
        out = json.dumps([{"ifname": "lo"}])
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
            r = route_mod.ip_addr_show()
            assert r[0]["ifname"] == "lo"

    def test_ip_addr_show_fail(self):
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr="err")
            with pytest.raises(RuntimeError):
                route_mod.ip_addr_show()

    def test_default_iface_ipv4(self):
        from unittest.mock import MagicMock
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("10.0.0.5", 0)
        with patch("socket.socket", return_value=fake_sock):
            got = route_mod.get_default_interface_ipv4()
            assert got == "10.0.0.5"
            fake_sock.connect.assert_called_once_with(("8.8.8.8", 53))

    def test_default_iface_ipv4_unreachable(self):
        with patch("socket.socket.connect", side_effect=OSError("unreachable")):
            assert route_mod.get_default_interface_ipv4() == ""

    def test_default_iface_ipv6_unreachable(self):
        with patch("socket.socket.connect", side_effect=OSError("unreachable")):
            assert route_mod.get_default_interface_ipv6() == ""


class TestSecurityHelpers:
    def test_validate_path(self):
        p = validate_path("config/app.json", must_exist=False)
        assert isinstance(p, Path)

    def test_validate_path_missing(self):
        with pytest.raises(ValidationError):
            validate_path("/nonexistent/xyz/file.txt", must_exist=True)

    def test_validate_json_ok(self):
        assert validate_json({"a": 1}) == {"a": 1}

    def test_validate_json_fail(self):
        class Bad:
            pass
        with pytest.raises(ValidationError):
            validate_json(Bad())

    def test_safe_subprocess_args_ok(self):
        assert safe_subprocess_args(["ping", "example.com"]) == ["ping", "example.com"]

    def test_safe_subprocess_args_nonstring(self):
        with pytest.raises(ValidationError):
            safe_subprocess_args(["x", 5])

    def test_safe_subprocess_args_shell_meta(self):
        with pytest.raises(ValidationError):
            safe_subprocess_args(["sh", "a;b"])

    def test_is_blocked_user_cidr(self):
        nets = build_block_networks(["203.0.113.0/24"])
        assert is_blocked("203.0.113.5", nets) is True
        assert is_blocked("8.8.8.8", nets) is False

    def test_validate_ip_invalid(self):
        with pytest.raises(ValidationError):
            validate_ip("not-an-ip")


class TestLogger:
    def test_formatter_with_structured(self):
        class Rec:
            structured = {"custom": "field"}
        out = JsonFormatter().format(Rec())
        assert "custom" in out

    def test_formatter_model(self):
        from logging import LogRecord
        rec = LogRecord("n", 20, "p", 1, "msg", None, None)
        out = JsonFormatter().format(rec)
        assert "event" in out

    def test_logger_levels(self):
        logger = AppLogger(capture=True)
        logger.debug("d")
        logger.info("i")
        logger.warning("w")
        logger.error("e")
        assert len(logger.entries) == 4
        assert logger.entries[-1]["level"] == "ERROR"

    def test_get_logger_singleton(self):
        assert get_logger() is get_logger()

    def test_logger_no_capture_debug(self):
        logger = AppLogger(capture=False)
        logger.info("x", hostname="a.com")
        assert len(logger.entries) == 0


class TestMetricsExtra:
    def test_record_latency_generic(self):
        m = Metrics()
        m.record_latency("custom", 5.0)
        assert m.snapshot()["latency_averages_ms"]["custom"] == 5.0

    def test_increment(self):
        m = Metrics()
        m.increment("custom_counter", 3.0)
        assert m.snapshot()["counters"]["custom_counter"] == 3.0

    def test_cdn_confidence_zero_count(self):
        m = Metrics()
        assert m.snapshot()["cdn_confidence_avg"] is None

    def test_xray_restart(self):
        m = Metrics()
        m.record_xray_restart()
        assert m.snapshot()["counters"]["xray_restarts"] == 1.0

    def test_load_or_create(self):
        m = Metrics.load_or_create()
        assert isinstance(m, Metrics)

    def test_default_metrics(self):
        assert isinstance(default_metrics, Metrics)


class TestErrors:
    def test_app_error_str(self):
        e = AppError("config", "bad", "cause", "fix it")
        s = str(e)
        assert "config" in s and "bad" in s and "cause" in s and "fix it" in s

    def test_collector_merge_and_summary(self):
        ec1 = ErrorCollector()
        ec1.add("a", "msg1")
        ec2 = ErrorCollector()
        ec2.add("b", "msg2")
        ec1.merge(ec2)
        assert ec1.count == 2
        assert "2 error(s)" in ec1.summary()

    def test_collector_empty_summary(self):
        assert ErrorCollector().summary() == "No errors."


class TestModels:
    def test_dnsresult_validator(self):
        r = DNSResult(hostname="  Example.COM  ")
        assert r.hostname == "example.com"

    def test_tlsresult_defaults(self):
        r = TLSResult(hostname="x", ip="1.2.3.4")
        assert r.port == 443
        assert r.san_list == []
        assert r.tls_valid is False

    def test_proberresult_defaults(self):
        p = ProbeResult(host="x")
        assert p.icmp == {}
        assert p.tcp443 == {}

    def test_cdnprovider(self):
        p = CDNProvider(name="Test", ipv4_ranges=["10.0.0.0/8"])
        assert p.name == "Test"

    def test_cdnmatch(self):
        m = CDNMatch(provider="Test", confidence=0.5)
        assert m.provider == "Test"

    def test_endpointrecord_defaults(self):
        from datetime import datetime, timezone
        e = EndpointRecord(hostname="x")
        assert e.status == RecordStatus.OBSERVED
        assert e.ipv4 == []

    def test_routedecision(self):
        d = RouteDecision(hostname="x", destination_ip="1.2.3.4", action=RouteAction.DIRECT)
        assert d.action == RouteAction.DIRECT

    def test_healthscore_defaults(self):
        s = HealthScore(hostname="x")
        assert s.level == HealthLevel.FAILED
        assert s.score == 0.0

    def test_logentry_defaults(self):
        e = LogEntry(event="test")
        assert e.success is False
