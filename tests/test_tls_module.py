"""Tests for network_tools/tls.py — offline (mocked socket + real x509 cert parsing)."""

import ssl
import socket
import struct
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from app.network_tools.tls import inspect_tls, _build_context, _fill_cert_metadata, _resolve_first
from app.models import TLSResult


def _make_cert(cn="example.com", san=("example.com", "www.example.com"), days=100):
    """Build a real self-signed x509 certificate for metadata parsing tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=days))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


class TestBuildContext:
    def test_context_settings(self):
        ctx = _build_context()
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE


class TestResolveFirst:
    def test_resolve_ok(self):
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            assert _resolve_first("example.com") == "1.2.3.4"

    def test_resolve_fail(self):
        with patch("socket.gethostbyname", side_effect=OSError("nope")):
            assert _resolve_first("example.invalid") == "0.0.0.0"


class TestFillCertMetadata:
    def test_full_metadata(self):
        cert = _make_cert()
        der = cert.public_bytes(_enc())
        result = TLSResult(hostname="example.com", ip="1.2.3.4")
        _fill_cert_metadata(result, der)
        assert result.subject and "example.com" in result.subject
        assert result.issuer and "Test CA" in result.issuer
        assert "example.com" in result.san_list
        assert result.tls_valid is True

    def test_expired_cert(self):
        cert = _make_cert(days=-1)  # already expired
        der = cert.public_bytes(_enc())
        result = TLSResult(hostname="example.com", ip="1.2.3.4")
        _fill_cert_metadata(result, der)
        assert result.tls_valid is False

    def test_no_san(self):
        cert = _make_cert(san=())
        der = cert.public_bytes(_enc())
        result = TLSResult(hostname="example.com", ip="1.2.3.4")
        _fill_cert_metadata(result, der)
        assert result.san_list == []

    def test_garbage_cert(self):
        result = TLSResult(hostname="example.com", ip="1.2.3.4")
        _fill_cert_metadata(result, b"not a cert")
        assert "cert_parse" in (result.error or "")


def _enc():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


class TestInspectTlsSocket:
    def _fake_ssock(self, der):
        ssock = MagicMock()
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssock.selected_alpn_protocol.return_value = "h2"
        ssock.version.return_value = "TLSv1.3"
        ssock.getpeercert.return_value = der
        return ssock

    def test_success_full(self):
        cert = _make_cert()
        der = cert.public_bytes(_enc())
        ssock = self._fake_ssock(der)

        fake_sock = MagicMock()
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=fake_sock), \
             patch.object(ssl.SSLContext, "wrap_socket", return_value=ssock):
            r = inspect_tls("example.com", timeout=1.0)
            assert r.success is True
            assert r.ip == "1.2.3.4"
            assert r.cipher == "TLS_AES_256_GCM_SHA384-TLSv1.3"
            assert r.alpn == ["h2"]
            assert r.tls_version == "TLSv1.3"
            assert "example.com" in r.san_list
            assert r.tls_valid is True

    def test_ssl_error(self):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=MagicMock()), \
             patch.object(ssl.SSLContext, "wrap_socket", side_effect=ssl.SSLError("handshake boom")):
            r = inspect_tls("example.com", timeout=1.0)
            assert r.success is False
            assert "ssl_error" in (r.error or "")

    def test_os_error(self):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=MagicMock()), \
             patch.object(ssl.SSLContext, "wrap_socket", side_effect=OSError("conn refused")):
            r = inspect_tls("example.com", timeout=1.0)
            assert r.success is False
            assert "os_error" in (r.error or "")

    def test_connect_os_error(self):
        fake_sock = MagicMock()
        fake_sock.connect.side_effect = OSError("refused")
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=fake_sock):
            r = inspect_tls("example.com", timeout=1.0)
            assert r.success is False
            assert "os_error" in (r.error or "")

    def test_no_cert(self):
        # Server returns no cert (binary_form -> None).
        ssock = MagicMock()
        ssock.cipher.return_value = ("AES", "TLSv1.2", 128)
        ssock.selected_alpn_protocol.return_value = None
        ssock.version.return_value = "TLSv1.2"
        ssock.getpeercert.return_value = None
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=MagicMock()), \
             patch.object(ssl.SSLContext, "wrap_socket", return_value=ssock):
            r = inspect_tls("example.com", timeout=1.0)
            assert r.success is True
            assert r.certificate_der is None

    def test_alpn_exception(self):
        ssock = MagicMock()
        ssock.cipher.return_value = ("AES", "TLSv1.2", 128)
        ssock.selected_alpn_protocol.side_effect = Exception("no alpn")
        ssock.version.return_value = "TLSv1.2"
        ssock.getpeercert.return_value = None
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=MagicMock()), \
             patch.object(ssl.SSLContext, "wrap_socket", return_value=ssock):
            r = inspect_tls("example.com", timeout=1.0)
            assert r.success is True
            assert r.alpn == []

    def test_sni_overridden(self):
        # sni param must be honoured and validated.
        ssock = MagicMock()
        ssock.cipher.return_value = None
        ssock.selected_alpn_protocol.return_value = None
        ssock.version.return_value = "TLSv1.2"
        ssock.getpeercert.return_value = None
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))]), \
             patch("socket.socket", return_value=MagicMock()), \
             patch.object(ssl.SSLContext, "wrap_socket", return_value=ssock) as m_wrap:
            r = inspect_tls("example.com", sni="Example.COM", timeout=1.0)
            assert r.sni == "example.com"  # normalised
            assert m_wrap.call_args.kwargs.get("server_hostname") == "example.com"
