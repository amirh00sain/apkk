"""TLS module tests — offline with mocks."""

import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

from app.models import TLSResult
from app.sni_parser import parse_client_hello, sni_consistency
from app.tls_inspector import inspect_tls, check_sni_consistency, SNIMismatch


class TestParseClientHello:
    def test_non_tls_returns_error(self):
        result = parse_client_hello(b"not tls at all")
        assert result["error"] is not None
        assert result["sni"] is None

    def test_too_short(self):
        result = parse_client_hello(b"\x16")
        assert result["error"] is not None

    def test_simple_sni(self):
        # Minimal ClientHello with SNI = "a.com"
        import struct
        # TLS record header
        sni_host = b"a.com"
        # SNI extension data (RFC 6066):
        #   server_name_list_length(2) [ name_type(1) name_length(2) host_name(n) ]
        sni_list_len = 3 + len(sni_host)
        sni_block = (
            struct.pack("!H", sni_list_len)
            + struct.pack("!B", 0)                      # name_type = host_name
            + struct.pack("!H", len(sni_host))           # name_length
            + sni_host
        )
        # Build handshake
        hs_body = (
            b"\x03\x03"           # client_version (TLS 1.2)
            + b"\x00" * 32        # random
            + b"\x00"             # session ID length=0
            + b"\x00\x02\x13\x01" # cipher suites
            + b"\x01\x00"         # compression methods
        )
        hs_ext = struct.pack("!HH", 0x0000, len(sni_block)) + sni_block
        hs_body += struct.pack("!H", len(hs_ext)) + hs_ext

        # Handshake header
        hs_msg = b"\x01" + struct.pack("!I", len(hs_body))[1:] + hs_body
        # TLS record
        record = b"\x16\x03\x01" + struct.pack("!H", len(hs_msg)) + hs_msg
        result = parse_client_hello(record)
        assert result["sni"] == "a.com"
        assert result["valid_utf8"] is True
        assert result["length"] == len(sni_host)


class TestSNIConsistency:
    def test_match(self):
        assert sni_consistency("example.com", ["example.com"]) == "MATCH"

    def test_wildcard_match(self):
        assert sni_consistency("sub.example.com", ["*.example.com"]) == "MATCH"

    def test_mismatch(self):
        assert sni_consistency("evil.com", ["example.com"]) == "MISMATCH"

    def test_unknown_empty_sni(self):
        assert sni_consistency("", ["example.com"]) == "UNKNOWN"


class TestSNIResult:
    def test_model(self):
        r = TLSResult(hostname="example.com", ip="1.2.3.4", success=True)
        assert r.tls_valid is False
        assert r.san_list == []


class TestCheckSniConsistency:
    def test_returns_status(self):
        r = TLSResult(hostname="example.com", ip="1.2.3.4", sni="example.com",
                       san_list=["example.com", "www.example.com"], issuer="CN=Test",
                       valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
                       valid_to=datetime(2025, 1, 1, tzinfo=timezone.utc))
        consistency = check_sni_consistency(r)
        assert consistency["status"] == "MATCH"
        assert "example.com" in consistency["certificate_names"]
