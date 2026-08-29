"""TLS inspection via Python's ssl module.

This module performs a real TLS handshake to a host using the SNI it requests,
extracts certificate metadata (SAN, issuer, validity, ALPN, cipher, version).
It NEVER fabricates SNI and NEVER generates unrelated identities — it is purely
for validation and telemetry.
"""

from __future__ import annotations

import ssl
import time
from datetime import datetime, timezone
from typing import Any

from app.models import TLSResult
from app.security import validate_hostname, validate_port


def _build_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # we record, not enforce, to allow telemetry on mismatches
    ctx.verify_mode = ssl.CERT_NONE
    # Advertise ALPN to encourage the server to reveal h2 support.
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except ssl.SSLError:
        pass
    return ctx


def inspect_tls(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = 8.0,
    sni: str | None = None,
) -> TLSResult:
    """Perform a TLS handshake and capture certificate/connection telemetry."""
    # The SNI we send equals the requested hostname (no fabrication).
    sni = validate_hostname(sni or hostname)
    port = validate_port(port)
    result = TLSResult(hostname=hostname, ip="", port=port, sni=sni)
    import socket

    ctx = _build_context()
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET if ":" not in _resolve_first(hostname) else socket.AF_INET6)
    # Use a simple IPv4 connect; for IPv6 we resolve accordingly.
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        fam, _, _, _, sockaddr = infos[0]
        sock.close()
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        result.ip = sockaddr[0]
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        result.latency_ms = round((time.monotonic() - start) * 1000, 1)
        result.success = True

        cipher = ssock.cipher()
        if cipher:
            result.cipher = f"{cipher[0]}-{cipher[1]}"
        try:
            result.alpn = [ssock.selected_alpn_protocol()] if ssock.selected_alpn_protocol() else []
        except Exception:
            result.alpn = []
        result.tls_version = ssock.version()

        cert_bin = ssock.getpeercert(binary_form=True)
        if cert_bin:
            result.certificate_der = cert_bin
            _fill_cert_metadata(result, cert_bin)
        ssock.close()
    except ssl.SSLError as exc:
        result.error = f"ssl_error: {exc}"
        result.latency_ms = round((time.monotonic() - start) * 1000, 1)
    except OSError as exc:
        result.error = f"os_error: {exc}"
        result.latency_ms = round((time.monotonic() - start) * 1000, 1)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result


def _resolve_first(hostname: str) -> str:
    import socket
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return "0.0.0.0"


def _fill_cert_metadata(result: TLSResult, cert_bin: bytes) -> None:
    """Extract SAN / issuer / validity from DER cert using cryptography."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(cert_bin)
        result.subject = cert.subject.rfc4514_string()
        result.issuer = cert.issuer.rfc4514_string()
        result.valid_from = cert.not_valid_before_utc.replace(tzinfo=timezone.utc)
        result.valid_to = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)

        # SAN
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = ext.value.get_values_for_type(x509.DNSName)
            result.san_list = [n.lower() for n in names]
        except x509.ExtensionNotFound:
            pass

        # Expiry check
        now = datetime.now(timezone.utc)
        if result.valid_from and result.valid_to:
            result.tls_valid = result.valid_from <= now <= result.valid_to
    except Exception as exc:  # pragma: no cover - cryptography edge cases
        result.error = (result.error or "") + f"; cert_parse: {exc}"
