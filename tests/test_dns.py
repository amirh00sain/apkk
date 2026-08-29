"""DNS module tests — offline (no network)."""

import asyncio
import json
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from app.network_tools.dns import DigResolver, DnspythonResolver, resolve_dns, DNSResult, resolve_dns_a_and_aaaa
from app.models import DNSResult as DNSResultModel


class TestDNSResult:
    def test_model_defaults(self):
        r = DNSResult(hostname="example.com")
        assert r.hostname == "example.com"
        assert r.a == []
        assert r.aaaa == []
        assert r.cname == []
        assert r.source == "unknown"
        assert r.ttl is None

    def test_hostname_lowercase(self):
        r = DNSResult(hostname="  EXAMPLE.COM  ")
        assert r.hostname == "example.com"


class TestDigResolver:
    def test_parse_json(self, dns_records):
        # Fake dig output mimicking real JSON format
        fake_json = {
            "answer": [
                {"type": "A", "data": "93.184.216.34", "TTL": 3600},
                {"type": "AAAA", "data": "2606:2800:220:1::248:1893:25c8:1946", "TTL": 3600},
            ]
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(fake_json))
            r = DigResolver().resolve("example.com")
            assert "93.184.216.34" in r.a
            assert r.ttl == 3600
            assert r.source == "dig"

    def test_dig_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            r = DigResolver().resolve("example.com")
            assert r.a == []
            assert r.source == "dig"


import json


class TestDnspythonResolver:
    def test_resolve_nxdomain(self):
        resolver = DnspythonResolver()
        resolver._resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NXDOMAIN())
        r = resolver.resolve("nonexistent.invalid")
        assert r.a == []
        assert r.source == "dnspython"

    def test_resolve_success(self):
        # Build a minimal object that iterates like a real dns answer.
        class FakeRdata:
            def __init__(self, val, rdtype_name):
                self._val = val
                self._rdtype = dns.rdatatype.from_text(rdtype_name)
            def __str__(self):
                return self._val
            @property
            def rdtype(self):
                # dnspython RdataType enum; the resolver maps it via to_text().
                return self._rdtype

        fake_answer = [FakeRdata("1.2.3.4", "A")]

        class FakeAnswer:
            def __init__(self, data):
                self._data = data
            def __iter__(self):
                return iter(self._data)
            @property
            def rrset(self):
                return MagicMock(ttl=600)

        resolver = DnspythonResolver()
        resolver._resolver.resolve = lambda *a, **k: FakeAnswer(fake_answer)
        r = resolver.resolve("example.com")
        assert "1.2.3.4" in r.a
        assert r.ttl == 600
        assert r.source == "dnspython"


import dns.rdatatype
import dns.resolver


class TestHighLevelResolve:
    def test_resolve_dns_with_backend_dig(self, monkeypatch):
        monkeypatch.setattr("app.network_tools.dns._resolver_backend", None)
        monkeypatch.setattr(DigResolver, "resolve",
                            lambda self, h, rt="A": DNSResult(hostname=h, a=["1.2.3.4"], source="dig"))
        r = resolve_dns("example.com", backend="dig")
        assert r.source == "dig"
        assert "1.2.3.4" in r.a

    def test_resolve_dns_with_backend_dnspython(self, monkeypatch):
        monkeypatch.setattr("app.network_tools.dns._resolver_backend", None)
        monkeypatch.setattr(DnspythonResolver, "resolve",
                            lambda self, h, rt="A": DNSResult(hostname=h, a=["5.6.7.8"], source="dnspython"))
        r = resolve_dns("example.com", backend="dnspython")
        assert r.source == "dnspython"


class TestDigMore:
    def test_dig_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("dig", 10)):
            r = DigResolver().resolve("example.com")
            assert r.a == []
            assert r.error == "dig timed out after 10 s"

    def test_dig_nonzero_return(self):
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout="{}", stderr="")
            r = DigResolver().resolve("example.com")
            assert r.a == []

    def test_dig_bad_json(self):
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="not json", stderr="")
            r = DigResolver().resolve("example.com")
            assert r.a == []
            assert r.latency_ms is not None

    def test_dig_cname_and_txt(self):
        fake_json = {
            "answer": [
                {"type": "CNAME", "data": "x.cdn.example.net", "TTL": 300},
                {"type": "TXT", "data": "\"v=spf1\"", "TTL": 300},
            ]
        }
        with patch("subprocess.run") as run:
            run.return_value = MagicMock(returncode=0, stdout=json.dumps(fake_json))
            r = DigResolver().resolve("example.com")
            assert "x.cdn.example.net" in r.cname
            assert "v=spf1" in r.txt
            assert r.ttl == 300

    def test_dig_aresolve(self):
        with patch("subprocess.run") as run:
            run.return_value = MagicMock(returncode=0, stdout="{}")
            r = asyncio.run(DigResolver().aresolve("example.com"))
            assert r.source == "dig"


class TestDnspythonMore:
    def test_resolve_no_answer(self):
        resolver = DnspythonResolver()
        resolver._resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NoAnswer())
        r = resolver.resolve("example.com")
        assert r.a == []
        assert r.latency_ms is not None

    def test_resolve_timeout(self):
        resolver = DnspythonResolver()
        resolver._resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(dns.resolver.Timeout())
        r = resolver.resolve("example.com")
        assert r.a == []
        assert r.latency_ms is not None

    def test_resolve_cname_txt(self):
        class FakeRdata:
            def __init__(self, val, rdtype_name):
                self._val = val
                self._rdtype = dns.rdatatype.from_text(rdtype_name)
            def __str__(self):
                return self._val
            @property
            def rdtype(self):
                return self._rdtype

        fake_answer = [FakeRdata("x.cdn.net", "CNAME"), FakeRdata("v=spf1", "TXT")]

        class FakeAnswer:
            def __init__(self, data):
                self._data = data
            def __iter__(self):
                return iter(self._data)
            @property
            def rrset(self):
                return MagicMock(ttl=300)

        resolver = DnspythonResolver()
        resolver._resolver.resolve = lambda *a, **k: FakeAnswer(fake_answer)
        r = resolver.resolve("example.com")
        assert "x.cdn.net" in r.cname
        assert "v=spf1" in r.txt
        assert r.ttl == 300

    def test_resolve_generic_exception(self):
        resolver = DnspythonResolver()
        resolver._resolver.resolve = lambda *a, **k: (_ for _ in ()).throw(ValueError("boom"))
        r = resolver.resolve("example.com")
        assert r.a == []
        assert r.latency_ms is not None

    def test_aresolve(self):
        resolver = DnspythonResolver()
        resolver.resolve = lambda h, rt="A": DNSResult(hostname=h, a=["9.9.9.9"], source="dnspython")
        r = asyncio.run(resolver.aresolve("example.com"))
        assert "9.9.9.9" in r.a


class TestResolveAAndAAAA:
    def test_merge(self, monkeypatch):
        a_res = DNSResult(hostname="example.com", a=["1.1.1.1"], cname=["x.net"],
                          latency_ms=10.0, ttl=300, source="dnspython")
        aaaa_res = DNSResult(hostname="example.com", aaaa=["2606::1"], cname=["x.net"],
                             latency_ms=30.0, ttl=300, source="dnspython")

        class FakeBackend:
            name = "dnspython"
            async def aresolve(self, hostname, record_type):
                if record_type == "A":
                    return a_res
                return aaaa_res

        monkeypatch.setattr("app.network_tools.dns._resolver_backend", FakeBackend())
        merged = asyncio.run(resolve_dns_a_and_aaaa("example.com"))
        assert merged.a == ["1.1.1.1"]
        assert merged.aaaa == ["2606::1"]
        assert merged.cname == ["x.net"]
        assert merged.ttl == 300
        assert merged.latency_ms == 20.0

    def test_merge_no_latency(self, monkeypatch):
        a_res = DNSResult(hostname="example.com", a=["1.1.1.1"], source="dnspython")
        aaaa_res = DNSResult(hostname="example.com", aaaa=[], source="dnspython")

        class FakeBackend:
            name = "dnspython"
            async def aresolve(self, hostname, record_type):
                if record_type == "A":
                    return a_res
                return aaaa_res

        monkeypatch.setattr("app.network_tools.dns._resolver_backend", FakeBackend())
        merged = asyncio.run(resolve_dns_a_and_aaaa("example.com"))
        assert merged.latency_ms == 0.0
