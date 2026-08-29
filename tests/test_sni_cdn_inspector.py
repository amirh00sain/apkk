"""Tests for sni_parser.py edge cases, cdn_detect.py extra, tls_inspector.py extras, destination_db.py."""

import struct
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.sni_parser import parse_client_hello, sni_consistency
from app.cdn_detect import detect_cdn, load_all_providers, _load_ranges
from app.tls_inspector import SNIMismatch, check_sni_consistency, inspect_tls, inspect_tls_detailed
from app.models import TLSResult, EndpointRecord
from app.destination_db import DestinationDB
from app.errors import AppError
from app.config_loader import load_blocklist, load_dns_providers, load_profiles


class TestSniParserEdge:
    def test_not_handshake(self):
        r = parse_client_hello(b"\x17\x03\x03\x00\x01\x00")
        assert r["error"] is not None
        assert r["sni"] is None

    def test_not_client_hello(self):
        # handshake type != 0x01
        hs = b"\x02" + struct.pack("!I", 1)[1:] + b"\x00"
        record = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
        r = parse_client_hello(record)
        assert "ClientHello" in r["error"]

    def test_handshake_too_short(self):
        r = parse_client_hello(b"\x16\x03\x03\x00\x04\x01\x00\x00\x00")
        assert r["error"] is not None

    def test_alpn_parse(self):
        # Build ClientHello with ALPN ext (0x10)
        alpn_data = b"\x02h2"
        alpn_block = struct.pack("!H", len(alpn_data)) + alpn_data
        hs_ext = struct.pack("!HH", 0x0010, len(alpn_block)) + alpn_block
        hs_body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        hs_body += struct.pack("!H", len(hs_ext)) + hs_ext
        hs_msg = b"\x01" + struct.pack("!I", len(hs_body))[1:] + hs_body
        record = b"\x16\x03\x03" + struct.pack("!H", len(hs_msg)) + hs_msg
        r = parse_client_hello(record)
        assert "h2" in r["alpn"]

    def test_invalid_utf8_sni(self):
        sni_host = b"\xff\xfe"
        sni_list_len = 3 + len(sni_host)
        sni_block = (struct.pack("!H", sni_list_len) + struct.pack("!B", 0)
                     + struct.pack("!H", len(sni_host)) + sni_host)
        hs_ext = struct.pack("!HH", 0x0000, len(sni_block)) + sni_block
        hs_body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        hs_body += struct.pack("!H", len(hs_ext)) + hs_ext
        hs_msg = b"\x01" + struct.pack("!I", len(hs_body))[1:] + hs_body
        record = b"\x16\x03\x03" + struct.pack("!H", len(hs_msg)) + hs_msg
        r = parse_client_hello(record)
        assert r["valid_utf8"] is False

    def test_extensions_truncated(self):
        # Extension total length claims 50 bytes but only a partial extension is present.
        hs_body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
        hs_body += struct.pack("!H", 50) + b"\x00\x0a\x00\x05"
        hs_msg = b"\x01" + struct.pack("!I", len(hs_body))[1:] + hs_body
        record = b"\x16\x03\x03" + struct.pack("!H", len(hs_msg)) + hs_msg
        r = parse_client_hello(record)
        assert "truncated" in (r["error"] or "").lower()


class TestSniConsistencyExtra:
    def test_case_insensitive(self):
        assert sni_consistency("EXAMPLE.COM", ["Example.com"]) == "MATCH"

    def test_wildcard_sub(self):
        assert sni_consistency("a.b.example.com", ["*.example.com"]) == "MATCH"


class TestCdnExtra:
    def test_san_keyword(self):
        # SAN "cloudflare" keyword without CNAME should match with 0.15 conf.
        m = detect_cdn("example.com", san_list=["something.cloudflare.net"])
        assert m.provider == "Cloudflare"
        assert m.confidence < 0.5

    def test_ipv6_range(self):
        # 2606:4700:: is within Cloudflare v6 range file
        m = detect_cdn("example.com", ipv6=["2606:4700:4700::1111"])
        assert m.provider == "Cloudflare"

    def test_load_ranges_missing(self):
        assert _load_ranges(__import__("pathlib").Path("nope.json")) == []

    def test_no_providers_match(self):
        m = detect_cdn("example.com", ipv4=["203.0.113.5"], providers={})
        assert m.provider is None

    def test_load_all_providers_keys(self):
        providers = load_all_providers()
        assert "akamai" in providers
        assert "google_cloud" in providers


class TestTlsInspectorExtra:
    def test_sni_mismatch_class(self):
        sm = SNIMismatch("evil.com", ["example.com"])
        assert sm.status == "MISMATCH"
        sm2 = SNIMismatch("example.com", ["example.com"])
        assert sm2.status == "MATCH"
        sm3 = SNIMismatch("", ["example.com"])
        assert sm3.status == "UNKNOWN"

    def test_check_sni_with_subject_cn(self):
        r = TLSResult(hostname="example.com", ip="1.2.3.4", sni="www.example.com",
                      subject="CN=www.example.com")
        c = check_sni_consistency(r)
        assert c["status"] == "MATCH"
        assert "www.example.com" in c["certificate_names"]

    def test_inspect_tls_retry_exhausted(self):
        with patch("app.tls_inspector._raw_inspect_tls", side_effect=OSError("nope")):
            res = inspect_tls("example.com", retries=1)
            assert res.success is False
            assert res.error is not None

    def test_inspect_tls_detailed(self):
        fake = TLSResult(hostname="example.com", ip="1.2.3.4", sni="example.com",
                         san_list=["example.com"], success=True, tls_valid=True,
                         subject="CN=example.com",
                         valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
                         valid_to=datetime(2025, 1, 1, tzinfo=timezone.utc),
                         latency_ms=10.0, tls_version="TLSv1.3")
        with patch("app.tls_inspector.inspect_tls", return_value=fake):
            d = inspect_tls_detailed("example.com")
            assert d["success"] is True
            assert d["sni_consistency"]["status"] == "MATCH"
            assert d["valid_from"] == "2024-01-01T00:00:00+00:00"


class TestDestinationDbExtra:
    def test_empty_db(self, tmp_path):
        db = DestinationDB(tmp_path / "x.json")
        assert db.all() == []
        assert db.get("missing") is None
        assert db.query_by_provider("X") == []

    def test_upsert_overwrites(self, tmp_path):
        db = DestinationDB(tmp_path / "x.json")
        db.upsert(EndpointRecord(hostname="a.com", ipv4=["1.1.1.1"]))
        db.upsert(EndpointRecord(hostname="a.com", ipv4=["2.2.2.2"]))
        assert db.get("a.com").ipv4 == ["2.2.2.2"]


class TestConfigLoadersExtra:
    def test_load_dns_providers(self):
        providers = load_dns_providers("config")
        assert isinstance(providers, dict)

    def test_load_blocklist(self):
        cidrs = load_blocklist("config")
        assert "10.10.34.0/24" in cidrs

    def test_load_profiles(self):
        profiles = load_profiles("config")
        assert "gaming_measurement" in profiles
