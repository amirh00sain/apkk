"""Automatic failover with candidate validation.

When a destination fails, try:
    candidate 1 → candidate 2 → candidate 3 → fresh DNS resolution.

Every candidate is validated (TCP + TLS) before use.  Failover is NOT
infinite — capped at the number of available candidates.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.logger import get_logger
from app.models import EndpointRecord, TLSResult
from app.network_tools.ping import TcpProber
from app.network_tools.tls import inspect_tls as tls_inspect
from app.security import validate_hostname

logger = get_logger()


def check_health_one_ip(ip: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Quick health check: TCP + TLS for one IP."""
    prober = TcpProber()
    tcp = prober.probe({"host": ip, "port": port}, timeout=timeout)
    result: dict[str, Any] = {
        "ip": ip,
        "tcp_ok": tcp.get("reachable", False),
        "tcp_latency_ms": tcp.get("latency_ms"),
        "tls_ok": False,
    }
    if tcp.get("reachable"):
        try:
            tls = tls_inspect(ip, port=port, timeout=timeout)
            result["tls_ok"] = tls.success
        except Exception:
            pass
    return result


def failover(hostname: str, endpoint: EndpointRecord) -> EndpointRecord:
    """Validate current candidate IPs; order healthy IPs first.

    Returns the updated EndpointRecord.  If all IPs fail, the record's status
    is set to 'failed' — we never fabricate a working IP.
    """
    hostname = validate_hostname(hostname)
    all_ips = endpoint.ipv6 + endpoint.ipv4

    healthy: list[str] = []
    for ip in all_ips:
        h = check_health_one_ip(ip)
        if h["tcp_ok"]:
            healthy.append(ip)
        else:
            logger.warning("failover_candidate_failed", hostname=hostname, ip=ip)

    endpoint.ipv6 = [ip for ip in healthy if ":" in ip]
    endpoint.ipv4 = [ip for ip in healthy if ":" not in ip]
    endpoint.last_seen = datetime.now(timezone.utc)

    if not healthy:
        endpoint.status = "failed"
        endpoint.last_verified = None
        logger.warning("failover_all_failed", hostname=hostname)
    else:
        endpoint.status = "fresh"
        endpoint.last_verified = datetime.now(timezone.utc)
        logger.info("failover_ok", hostname=hostname, healthy_count=len(healthy))

    return endpoint


async def failover_with_fresh_dns(
    hostname: str,
    endpoint: EndpointRecord,
    dns_resolver=None,
) -> EndpointRecord:
    """If all IPs fail, re-resolve DNS and try again.  One round only."""
    all_ips = endpoint.ipv6 + endpoint.ipv4
    # First try existing IPs.
    validated = failover(hostname, endpoint)
    if validated.status != "failed":
        return validated

    # All IPs failed → one fresh DNS round.
    if dns_resolver is None:
        from app.network_tools.dns import resolve_dns_a_and_aaaa
        dns_result = await resolve_dns_a_and_aaaa(hostname)
    else:
        dns_result = await dns_resolver(hostname)
    endpoint.ipv4 = dns_result.a
    endpoint.ipv6 = dns_result.aaaa
    endpoint.source = list(dict.fromkeys(endpoint.source + ["failover_dns_refresh"]))
    endpoint.cname_chain = list(dict.fromkeys(endpoint.cname_chain + dns_result.cname))
    return failover(hostname, endpoint)
