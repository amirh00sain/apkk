"""TLS Inspector — high-level façade over network_tools/tls.py.

Performs real TLS handshakes, extracts certificate metadata (SAN, issuer,
validity, ALPN, cipher, version), and reports SNI/CN/SAN consistency.

NEVER fabricates SNI or unrelated identities.  Every mismatch is flagged as
`MISMATCH` and never silently silenced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.logger import get_logger
from app.models import TLSResult
from app.network_tools.tls import inspect_tls as _raw_inspect_tls
from app.retry import retry
from app.security import validate_hostname, validate_port

logger = get_logger()


class SNIMismatch:
    """Raised when SNI does not match certificate SAN/CN."""

    def __init__(self, sni: str, certificate_names: list[str]):
        self.sni = sni
        self.certificate_names = certificate_names

    @property
    def status(self) -> str:
        if not self.sni:
            return "UNKNOWN"
        if self.sni in self.certificate_names:
            return "MATCH"
        # Check wildcard match.
        for name in self.certificate_names:
            if name.startswith("*.") and self.sni.endswith(name[1:]):
                return "MATCH"
        return "MISMATCH"


def inspect_tls(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = 8.0,
    retries: int = 3,
) -> TLSResult:
    """Full TLS inspection with automatic retry."""
    hostname = validate_hostname(hostname)
    port = validate_port(port)

    def _try() -> TLSResult:
        return _raw_inspect_tls(hostname, port=port, timeout=timeout)

    try:
        result = retry(
            _try,
            max_retries=retries,
            backoffs=[0.5, 1.0, 2.0],
            exceptions=(OSError, ConnectionError),
        )
    except (OSError, ConnectionError) as exc:
        logger.warning(
            "tls_probe_failed",
            hostname=hostname,
            details={"error": str(exc)},
        )
        return TLSResult(
            hostname=hostname,
            ip="",
            port=port,
            success=False,
            tls_valid=False,
            error=str(exc),
        )

    logger.info(
        "tls_probe",
        hostname=hostname,
        ip=result.ip or None,
        latency_ms=result.latency_ms,
        success=result.success,
    )
    return result


def check_sni_consistency(result: TLSResult) -> dict[str, Any]:
    """Check whether SNI, SAN, and CN are consistent.

    Returns a dict with status (MATCH | MISMATCH | UNKNOWN) and details.
    This never modifies the result — it only reports.
    """
    sni = result.sni or result.hostname
    cert_names = list(result.san_list)
    # Attempt to parse CN from subject if available.
    if result.subject:
        for part in result.subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                cn = part[3:].strip().lower()
                if cn and cn not in cert_names:
                    cert_names.append(cn)

    checker = SNIMismatch(sni, cert_names)
    return {
        "sni": sni,
        "certificate_names": cert_names,
        "status": checker.status,
        "issuer": result.issuer,
        "tls_version": result.tls_version,
        "cipher": result.cipher,
    }


def inspect_tls_detailed(hostname: str, port: int = 443) -> dict[str, Any]:
    """High-level: run TLS check + SNI consistency in one call."""
    result = inspect_tls(hostname, port=port)
    consistency = check_sni_consistency(result)
    return {
        "hostname": hostname,
        "ip": result.ip,
        "success": result.success,
        "error": result.error,
        "latency_ms": result.latency_ms,
        "tls_version": result.tls_version,
        "cipher": result.cipher,
        "sni": result.sni,
        "san_list": result.san_list,
        "issuer": result.issuer,
        "subject": result.subject,
        "valid_from": result.valid_from.isoformat() if result.valid_from else None,
        "valid_to": result.valid_to.isoformat() if result.valid_to else None,
        "tls_valid": result.tls_valid,
        "alpn": result.alpn,
        "sni_consistency": consistency,
    }
