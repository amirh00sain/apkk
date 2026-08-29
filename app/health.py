"""Endpoint health checking.

Defines healthy / degraded / failed levels based on:
  DNS success, TCP reachability, TLS validity, latency, failure rate.

Health score is 0.0–1.0.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models import EndpointRecord, HealthLevel, HealthScore
from app.network_tools.ping import TcpProber
from app.network_tools.tls import inspect_tls as tls_inspect


def compute_health(
    hostname: str,
    endpoint: EndpointRecord,
    *,
    failure_rate: float = 0.0,
) -> HealthScore:
    """Compute a health score for an endpoint.

    Score components (max 1.0):
      DNS resolved (has IPs)    0.25
      TCP reachable             0.25
      TLS valid                 0.25
      low latency (<200ms)      0.25
    Minus failure_rate penalty (up to 1.0).
    """
    dns_ok = bool(endpoint.ipv4 or endpoint.ipv6)
    all_ips = endpoint.ipv6 + endpoint.ipv4

    tcp_ok = False
    tls_ok = False
    latency: float | None = None

    if all_ips:
        # Probe the best available IP (first v6 or v4).
        best_ip = all_ips[0]
        probe = TcpProber().probe({"host": best_ip, "port": 443}, timeout=5.0)
        tcp_ok = bool(probe.get("reachable"))
        if tcp_ok:
            latency = probe.get("latency_ms", latency)
            try:
                tls = tls_inspect(best_ip, port=443, timeout=8.0)
                tls_ok = tls.success
            except Exception:
                tls_ok = False

    score = 0.0
    if dns_ok:
        score += 0.25
    if tcp_ok:
        score += 0.25
    if tls_ok:
        score += 0.25
    if latency is not None and latency < 200.0:
        score += 0.25
    # Penalise failure rate.
    score = max(0.0, score - failure_rate)

    if score >= 0.75:
        level = HealthLevel.HEALTHY
    elif score >= 0.4:
        level = HealthLevel.DEGRADED
    else:
        level = HealthLevel.FAILED

    return HealthScore(
        hostname=hostname,
        level=level,
        dns_ok=dns_ok,
        tcp_ok=tcp_ok,
        tls_ok=tls_ok,
        latency_ms=latency,
        failure_rate=failure_rate,
        score=round(score, 2),
    )


def summarise(records: list[EndpointRecord]) -> dict[str, Any]:
    """Summarise health across a list of endpoints."""
    healthy = degraded = failed = 0
    for rec in records:
        h = compute_health(rec.hostname, rec)
        if h.level == HealthLevel.HEALTHY:
            healthy += 1
        elif h.level == HealthLevel.DEGRADED:
            degraded += 1
        else:
            failed += 1
    return {
        "healthy": healthy,
        "degraded": degraded,
        "failed": failed,
        "total": len(records),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
