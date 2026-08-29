"""Dynamic IP selection for a hostname.

Pipeline:
    DNS → remove private/reserved → provider match → TCP reachability
    → TLS verification → latency → rank candidates.

IPs are never hardcoded — always resolved and validated at runtime.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from app.logger import get_logger
from app.models import EndpointRecord, DNSResult, TLSResult
from app.network_tools.ping import TcpProber
from app.network_tools.tls import inspect_tls as tls_inspect
from app.security import validate_hostname, is_blocked
from app.retry import retry

logger = get_logger()


def _is_reserved(ip_str: str) -> bool:
    """Return True if IP is loopback/link-local/reserved/unicast-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_unspecified


def rank_candidates(
    hostname: str,
    dns_result: DNSResult,
    *,
    tls_result: TLSResult | None = None,
    block_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
    prefer_ipv6: bool = True,
) -> EndpointRecord:
    """Build an EndpointRecord with ranked candidate IPs.

    Ordering logic (from spec):
        DNS → remove private/reserved → provider match → TCP reachability
        → TLS verification → latency → rank.
    """
    hostname = validate_hostname(hostname)
    now = datetime.now(timezone.utc)

    # 1. Deduplicate and filter private/reserved.
    all_ipv4 = [ip for ip in dict.fromkeys(dns_result.a) if not is_blocked(ip, block_networks) and not _is_reserved(ip)]
    all_ipv6 = [ip for ip in dict.fromkeys(dns_result.aaaa) if not is_blocked(ip, block_networks) and not _is_reserved(ip)]

    # 2. Provider match from TLS certificate names.
    cert_names: list[str] = []
    tls_valid = False
    if tls_result:
        cert_names = list(tls_result.san_list)
        tls_valid = tls_result.tls_valid

    # 3. TCP reachability check on each candidate.
    prober = TcpProber()
    ranked: list[tuple[str, float | None, str]] = []  # (ip, latency_ms, family)

    for ip in (all_ipv6 if prefer_ipv6 else all_ipv4) + (all_ipv4 if prefer_ipv6 else all_ipv6):
        probe = prober.probe({"host": ip, "port": 443}, timeout=3.0, prefer_v6=prefer_ipv6)
        latency = probe.get("latency_ms")
        if probe.get("reachable"):
            ranked.append((ip, latency, "ipv6" if ":" in ip else "ipv4"))

    # 4. Sort by latency (None last).
    ranked.sort(key=lambda x: (x[1] is None, x[1] or 9999.0))

    best_latency = ranked[0][1] if ranked else None

    return EndpointRecord(
        hostname=hostname,
        ipv4=all_ipv4,
        ipv6=all_ipv6,
        cname_chain=list(dns_result.cname),
        tls_valid=tls_valid,
        certificate_names=cert_names,
        latency_ms=best_latency,
        first_seen=now,
        last_seen=now,
        last_verified=now if tls_valid else None,
        source=[dns_result.source],
        status="tls_verified" if tls_valid else ("resolved" if ranked else "observed"),
    )
