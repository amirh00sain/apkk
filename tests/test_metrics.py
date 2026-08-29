"""Metrics, retry, logger, packet analyzer tests."""

import tempfile
from pathlib import Path

from app.metrics import Metrics
from app.retry import retry, retry_async
from app.logger import AppLogger
from app.packet_analyzer import PacketAnalyzer
from app.destination_db import DestinationDB
from app.failover import check_health_one_ip
from app.models import EndpointRecord


class TestMetrics:
    def test_record_latency(self):
        m = Metrics()
        m.record_dns_latency(10.0)
        m.record_dns_latency(20.0)
        snap = m.snapshot()
        avg = snap["latency_averages_ms"]["dns_latency"]
        assert avg == 15.0

    def test_counter_increment(self):
        m = Metrics()
        m.record_ipv4_success()
        m.record_ipv4_success()
        m.record_ipv6_success()
        snap = m.snapshot()
        assert snap["counters"]["ipv4_success"] == 2.0
        assert snap["counters"]["ipv6_success"] == 1.0

    def test_route_change_tracking(self):
        m = Metrics()
        m.record_route_change("direct")
        m.record_route_change("direct")  # duplicate — should not increment
        m.record_route_change("cdn")
        assert m.snapshot()["counters"]["route_changes"] == 2.0

    def test_export_json(self):
        m = Metrics()
        m.record_dns_latency(5.0)
        path = Path(tempfile.mktemp(suffix=".json"))
        try:
            m.export_json(path)
            import json
            data = json.loads(path.read_text())
            assert "latency_averages_ms" in data
        finally:
            path.unlink(missing_ok=True)

    def test_cdn_confidence(self):
        m = Metrics()
        m.record_cdn_confidence(0.9)
        m.record_cdn_confidence(0.7)
        assert m.snapshot()["cdn_confidence_avg"] == 0.8

    def test_jitter_and_packet_loss(self):
        m = Metrics()
        m.record_jitter(2.5)
        m.record_packet_loss(0.05)
        snap = m.snapshot()
        assert snap["latency_averages_ms"]["jitter"] == 2.5
        assert snap["latency_averages_ms"]["packet_loss"] == 0.05


class TestRetry:
    def test_retry_success_first(self):
        assert retry(lambda: 42, max_retries=3) == 42

    def test_retry_succeeds_on_third(self):
        counter = {"n": 0}
        def flaky():
            counter["n"] += 1
            if counter["n"] < 3:
                raise ValueError("fail")
            return "ok"
        assert retry(flaky, max_retries=5, backoffs=[0, 0]) == "ok"
        assert counter["n"] == 3

    def test_retry_exhausts(self):
        import pytest
        with pytest.raises(ValueError):
            retry(lambda: (_ for _ in ()).throw(ValueError("always")),
                  max_retries=2, backoffs=[0, 0])

    def test_retry_async(self):
        import asyncio
        async def _coro():
            return 99
        async def go():
            return await retry_async(_coro, max_retries=1, backoffs=[0])
        assert asyncio.run(go()) == 99


class TestLogger:
    def test_capture(self):
        logger = AppLogger(capture=True)
        logger.info("test_event", hostname="a.com")
        assert len(logger.entries) == 1
        assert logger.entries[0]["event"] == "test_event"

    def test_no_capture(self):
        logger = AppLogger(capture=False)
        logger.info("test_event")
        assert len(logger.entries) == 0


class TestPacketAnalyzer:
    def test_tcp_flags(self):
        # Minimal IPv4 TCP packet: IP(20) + TCP(20) = 40 bytes
        ip = bytes([
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x01, 0x02, 0x03, 0x04,  # src
            0x05, 0x06, 0x07, 0x08,  # dst
        ])
        tcp = bytes([
            0x00, 0x50, 0x00, 0x51,  # src_port, dst_port
            0x00, 0x00, 0x00, 0x01,  # seq
            0x00, 0x00, 0x00, 0x02,  # ack
            0x50, 0x12, 0x00, 0x00,  # data offset(5) + flags: SYN=0x02|ACK=0x10 = 0x12
            0x00, 0x00, 0x00, 0x00,  # checksum + urgent
        ])
        pkt = Analyzer.analyze_tcp(ip + tcp)
        assert pkt["src_port"] == 80
        assert pkt["dst_port"] == 81
        assert pkt["flags"]["syn"] is True
        assert pkt["flags"]["ack_flag"] is True
        assert pkt["src_ip"] == "1.2.3.4"

    def test_analyze_tls_record(self):
        # TLS record header + dummy content
        record = bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + b"\x01\x00\x00\x01\x00"
        result = Analyzer.analyze_tls_record(record)
        assert result["content_type"] == 0x16
        assert result["version"] == "3.01"

    def test_fragmentation_report(self):
        r = Analyzer.fragmentation_report([1500, 1500], [800, 700])
        assert r["before"]["count"] == 2
        assert r["after"]["count"] == 2
        assert "Measurement only" in r["note"]

    def test_mtu_report(self):
        r = Analyzer.mtu_report([1500, 2000], mtu=1500)
        assert r["oversized_count"] == 1
        assert r["fragmentation_likely"] is True


Analyzer = PacketAnalyzer()


class TestDestinationDB:
    def test_upsert_and_get(self):
        path = Path(tempfile.mktemp(suffix=".json"))
        db = DestinationDB(path)
        ep = EndpointRecord(hostname="a.com", ipv4=["1.2.3.4"])
        db.upsert(ep)
        assert db.get("a.com").ipv4 == ["1.2.3.4"]
        assert len(db.all()) == 1

    def test_persistence(self):
        path = Path(tempfile.mktemp(suffix=".json"))
        db1 = DestinationDB(path)
        db1.upsert(EndpointRecord(hostname="b.com"))
        # Reopen
        db2 = DestinationDB(path)
        assert db2.get("b.com") is not None

    def test_query_by_provider(self):
        path = Path(tempfile.mktemp(suffix=".json"))
        db = DestinationDB(path)
        db.upsert(EndpointRecord(hostname="a.com", provider="Cloudflare"))
        db.upsert(EndpointRecord(hostname="b.com"))
        assert len(db.query_by_provider("Cloudflare")) == 1


class TestFailover:
    def test_check_health_ip(self):
        with patch("app.failover.TcpProber") as mock_tcp, \
             patch("app.failover.tls_inspect") as mock_tls:
            inst = mock_tcp.return_value
            inst.probe.return_value = {"reachable": True, "latency_ms": 10.0}
            mock_tls.return_value = type("T", (), {"success": True})()
            result = check_health_one_ip("93.184.216.34")
            assert result["tcp_ok"] is True
            assert result["tls_ok"] is True


from unittest.mock import patch
