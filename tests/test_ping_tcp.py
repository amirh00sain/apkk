"""Tests for network_tools/ping.py and network_tools/tcp.py (offline with mocks + real local sockets)."""

import asyncio
import socket
import subprocess
import threading
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from app.network_tools.ping import IcmpProber, TcpProber, tls_probe, probe_host, probe_host_async
from app.models import ProbeTarget


@contextmanager
def _local_server():
    """Spin up a real TCP server on an ephemeral localhost port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        srv.close()


class TestIcmpProber:
    def test_reachable(self):
        out = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n" \
              "rtt min/avg/max/mdev = 11.0/12.3/13.0/0.5 ms\n"
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
            r = IcmpProber().probe(ProbeTarget(host="1.1.1.1"))
            assert r["reachable"] is True
            assert r["latency_ms"] == 12.3

    def test_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            r = IcmpProber().probe(ProbeTarget(host="1.1.1.1"))
            assert r["supported"] is False
            assert r["reachable"] is False

    def test_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 5)):
            r = IcmpProber().probe(ProbeTarget(host="1.1.1.1"))
            assert r["reachable"] is False
            assert r["supported"] is True

    def test_unreachable_returncode(self):
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr="")
            r = IcmpProber().probe(ProbeTarget(host="1.1.1.1"))
            assert r["reachable"] is False
            assert r["supported"] is True


class TestTcpProberReal:
    def test_reachable(self):
        with _local_server() as port:
            r = TcpProber().probe(ProbeTarget(host="127.0.0.1", port=port))
            assert r["reachable"] is True
            assert r["latency_ms"] is not None
            assert r["ip"] == "127.0.0.1"

    def test_unresolvable(self):
        r = TcpProber().probe(ProbeTarget(host="invalid.invalid.invalid", port=443))
        assert r["reachable"] is False

    def test_no_addresses(self):
        with patch("socket.getaddrinfo", return_value=[]):
            r = TcpProber().probe(ProbeTarget(host="example.com", port=443))
            assert r["reachable"] is False


class TestTcpConnect:
    def test_tcp_connect(self):
        from app.network_tools.tcp import tcp_connect, measure_jitter
        with _local_server() as port:
            r = tcp_connect("127.0.0.1", port)
            assert r["reachable"] is True
            assert r["family"] == "ipv4"
        # measure_jitter uses tcp_connect internally; mock it.
        with patch("app.network_tools.tcp.tcp_connect") as mc:
            mc.return_value = {"reachable": True, "latency_ms": 10.0}
            j = measure_jitter("127.0.0.1", 80, samples=3)
            assert j["jitter_ms"] == 0.0
            assert j["packet_loss"] == 0.0

    def test_measure_jitter_all_fail(self):
        from app.network_tools.tcp import measure_jitter
        with patch("app.network_tools.tcp.tcp_connect") as mc:
            mc.return_value = {"reachable": False, "latency_ms": None, "error": "x"}
            j = measure_jitter("127.0.0.1", 80, samples=2)
            assert j["packet_loss"] == 1.0
            assert j["jitter_ms"] is None


class TestTlsProbe:
    def test_tls_probe(self):
        fake = type("R", (), {"success": True, "latency_ms": 5.0, "tls_version": "TLSv1.3", "error": None})()
        with patch("app.tls_inspector.inspect_tls", return_value=fake):
            r = tls_probe(ProbeTarget(host="example.com", port=443))
            assert r["reachable"] is True
            assert r["tls_version"] == "TLSv1.3"


class TestProbeHost:
    def test_probe_host(self):
        fake_icmp = {"supported": True, "reachable": True, "latency_ms": 5.0}
        fake_tcp = {"reachable": True, "latency_ms": 10.0}
        fake_tls = {"reachable": True, "latency_ms": 12.0}
        with patch("app.network_tools.ping.IcmpProber.probe", return_value=fake_icmp), \
             patch("app.network_tools.ping.TcpProber.probe", return_value=fake_tcp), \
             patch("app.network_tools.ping.tls_probe", return_value=fake_tls):
            res = probe_host("example.com")
            assert res.icmp["reachable"] is True
            assert res.tcp443["reachable"] is True
            assert res.tls["reachable"] is True

    def test_probe_host_async(self):
        fake_tcp = {"reachable": True, "latency_ms": 10.0}
        with patch("app.network_tools.ping.TcpProber.probe", return_value=fake_tcp), \
             patch("app.network_tools.ping.IcmpProber.probe", return_value={"reachable": False}), \
             patch("app.network_tools.ping.tls_probe", return_value={"reachable": False}):
            res = asyncio.run(probe_host_async("example.com"))
            assert res.host == "example.com"
            assert res.tcp443["reachable"] is True
