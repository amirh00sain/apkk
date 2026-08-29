"""Health and IP-selection tests — offline (mocked probes)."""

from datetime import datetime, timezone
from unittest.mock import patch

from app.health import compute_health, summarise, HealthLevel
from app.ip_select import rank_candidates, _is_reserved
from app.models import EndpointRecord, DNSResult, TLSResult


def _endpoint(ips_v4=(), ips_v6=(), tls_valid=True):
    return EndpointRecord(
        hostname="example.com",
        ipv4=list(ips_v4),
        ipv6=list(ips_v6),
        tls_valid=tls_valid,
        latency_ms=20.0,
    )


def test_compute_health_healthy():
    ep = _endpoint(ips_v4=["93.184.216.34"])
    with patch("app.health.TcpProber") as mock_tcp, patch("app.health.tls_inspect") as mock_tls:
        inst = mock_tcp.return_value
        inst.probe.return_value = {"reachable": True, "latency_ms": 15.0}
        mock_tls.return_value = type("T", (), {"success": True})()
        h = compute_health("example.com", ep)
        assert h.level == HealthLevel.HEALTHY
        assert h.score >= 0.75
        assert h.tcp_ok and h.dns_ok and h.tls_ok


def test_compute_health_failed_no_ips():
    ep = _endpoint()
    h = compute_health("example.com", ep)
    assert h.level == HealthLevel.FAILED
    assert h.score == 0.0


def test_compute_health_degraded():
    ep = _endpoint(ips_v4=["93.184.216.34"])
    with patch("app.health.TcpProber") as mock_tcp, patch("app.health.tls_inspect") as mock_tls:
        inst = mock_tcp.return_value
        inst.probe.return_value = {"reachable": True, "latency_ms": 15.0}
        mock_tls.return_value = type("T", (), {"success": False})()
        h = compute_health("example.com", ep)
        # dns + tcp but no tls, latency ok => 0.5 + 0.25 (latency) => healthy
        # To get degraded: simulate high latency so latency bonus is dropped.
        inst.probe.return_value = {"reachable": True, "latency_ms": 350.0}
        h2 = compute_health("example.com", ep)
        assert h2.level == HealthLevel.DEGRADED


def test_summarise():
    healthy = _endpoint(ips_v4=["93.184.216.34"])
    with patch("app.health.TcpProber") as mock_tcp, patch("app.health.tls_inspect") as mock_tls:
        inst = mock_tcp.return_value
        inst.probe.return_value = {"reachable": True, "latency_ms": 15.0}
        mock_tls.return_value = type("T", (), {"success": True})()
        summary = summarise([healthy])
        assert summary["healthy"] == 1
        assert summary["total"] == 1


def test_is_reserved():
    assert _is_reserved("127.0.0.1")
    assert _is_reserved("169.254.1.1")
    assert not _is_reserved("93.184.216.34")


def test_rank_candidates():
    dns = DNSResult(hostname="example.com", a=["93.184.216.34"], aaaa=["2606:2800::1"],
                    cname=["x.cloudflare.com"])
    tls = TLSResult(hostname="example.com", ip="93.184.216.34", tls_valid=True,
                    san_list=["example.com"], success=True)
    with patch("app.ip_select.TcpProber") as mock_tcp:
        inst = mock_tcp.return_value
        inst.probe.return_value = {"reachable": True, "latency_ms": 12.0}
        rec = rank_candidates("example.com", dns, tls_result=tls)
        assert "93.184.216.34" in rec.ipv4
        assert "2606:2800::1" in rec.ipv6
        assert rec.tls_valid is True
        assert rec.status == "tls_verified"


def test_rank_filters_reserved():
    dns = DNSResult(hostname="example.com", a=["127.0.0.1", "93.184.216.34"])
    with patch("app.ip_select.TcpProber") as mock_tcp:
        inst = mock_tcp.return_value
        inst.probe.return_value = {"reachable": True, "latency_ms": 12.0}
        rec = rank_candidates("example.com", dns)
        assert "127.0.0.1" not in rec.ipv4
        assert "93.184.216.34" in rec.ipv4
