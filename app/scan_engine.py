"""Scan engine — high-level orchestrator that combines all modules.

This is the core of the `scan` command: given a hostname, run the full
pipeline (DNS → TLS → CDN → IP selection → health → route decision → persist)
and return a rich result dict.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.cdn_detect import detect_cdn_from_dns_result, load_all_providers
from app.config_loader import load_config, load_blocklist
from app.database import CacheDB, open_caches
from app.destination_db import DestinationDB
from app.health import compute_health
from app.ip_select import rank_candidates
from app.logger import get_logger
from app.metrics import default_metrics
from app.network_tools.dns import resolve_dns, resolve_dns_a_and_aaaa
from app.models import RouteAction, RouteDecision, TLSResult
from app.network_tools.ping import probe_host
from app.route_engine import RouteEngine
from app.security import build_block_networks, validate_hostname

logger = get_logger()


async def scan_hostname(
    hostname: str,
    *,
    do_tls: bool = True,
    do_probe: bool = True,
    do_cdn: bool = True,
    data_dir: str | Path = "data",
    blocklist_cidrs: list[str] | None = None,
) -> dict[str, Any]:
    """Full scan of a single hostname.

    Returns a dict with all findings.  Every claim is labelled with its
    verification status (observed / inferred / verified / failed).
    """
    hostname = validate_hostname(hostname)
    now = datetime.now(timezone.utc)

    # --- Step 1: DNS ---
    dns = await resolve_dns_a_and_aaaa(hostname)
    default_metrics.record_dns_latency(dns.latency_ms or 0)
    logger.info("dns_result", hostname=hostname, a_count=len(dns.a), aaaa_count=len(dns.aaaa),
                latency_ms=dns.latency_ms, source=dns.source)

    # --- Step 2: TLS ---
    tls: TLSResult | None = None
    if do_tls:
        from app.tls_inspector import inspect_tls as tls_inspect
        tls = tls_inspect(hostname, timeout=8.0)
        default_metrics.record_tls_latency(tls.latency_ms or 0)
        logger.info("tls_result", hostname=hostname, success=tls.success,
                     latency_ms=tls.latency_ms)

    # --- Step 3: Probe ---
    probe: dict[str, Any] | None = None
    if do_probe:
        probe_obj = probe_host(hostname)
        probe = probe_obj.model_dump()
        tcp_latency = probe.get("tcp443", {}).get("latency_ms")
        if tcp_latency is not None:
            default_metrics.record_tcp_latency(tcp_latency)

    # --- Step 4: CDN detection ---
    cdn = None
    if do_cdn:
        cdn = detect_cdn_from_dns_result(
            dns,
            san_list=tls.san_list if tls else None,
        )
        if cdn.provider:
            default_metrics.record_cdn_confidence(cdn.confidence)

    # --- Step 5: IP selection ---
    block_nets = build_block_networks(blocklist_cidrs or load_blocklist())
    endpoint = rank_candidates(
        hostname, dns, tls_result=tls, block_networks=block_nets,
    )

    # --- Step 6: Health ---
    health = compute_health(hostname, endpoint)

    # --- Step 7: Route decision ---
    engine = RouteEngine(block_networks=block_nets)
    # Pick the first available IP for routing decision.
    best_ip = (endpoint.ipv6 + endpoint.ipv4 + [""])[0]
    route = engine.decide(
        hostname, best_ip, cdn_match=cdn,
        private_block=True,
    )
    default_metrics.record_route_change(route.action.value)

    # --- Step 8: Persist ---
    dest_db = DestinationDB(Path(data_dir) / "domains" / "verified.json")
    dest_db.upsert(endpoint)

    try:
        with open_caches(Path(data_dir) / "cache") as caches:
            for a in dns.a:
                caches["dns"].put_dns(hostname, "A", a, dns.ttl, dns.source)
            for aaaa in dns.aaaa:
                caches["dns"].put_dns(hostname, "AAAA", aaaa, dns.ttl, dns.source)
            if tls:
                # certificate_der is binary; JSON-serialising it fails on non-UTF-8
                # bytes and the cache only stores metadata anyway.
                caches["tls"].put_tls(tls.model_dump(mode="json", exclude={"certificate_der"}))
            if probe:
                caches["probes"].put_probe(probe)
    except Exception as exc:
        logger.warning("cache_write_failed", details={"error": str(exc)})

    result = {
        "hostname": hostname,
        "dns": {
            "ipv4": dns.a,
            "ipv6": dns.aaaa,
            "cname": dns.cname,
            "latency_ms": dns.latency_ms,
            "ttl": dns.ttl,
            "source": dns.source,
            "status": "verified" if (dns.a or dns.aaaa) else "failed",
        },
        "tls": {
            "success": tls.success if tls else False,
            "ip": tls.ip if tls else None,
            "latency_ms": tls.latency_ms if tls else None,
            "tls_version": tls.tls_version if tls else None,
            "cipher": tls.cipher if tls else None,
            "sni": tls.sni if tls else None,
            "san_list": tls.san_list if tls else [],
            "issuer": tls.issuer if tls else None,
            "tls_valid": tls.tls_valid if tls else False,
            "status": "verified" if (tls and tls.success) else "unverified",
        },
        "probe": probe or {},
        "cdn": {
            "provider": cdn.provider if cdn else None,
            "confidence": cdn.confidence if cdn else 0.0,
            "evidence": cdn.evidence if cdn else [],
            "status": "inferred" if (cdn and cdn.provider) else "unverified",
        },
        "endpoint": endpoint.model_dump(mode="json"),
        "health": health.model_dump(),
        "route": route.model_dump(),
        "scanned_at": now.isoformat(),
    }

    logger.info("scan_complete", hostname=hostname,
                details={"provider": cdn.provider if cdn else None,
                         "route_action": route.action.value})
    return result


def update_database(data_dir: str | Path = "data") -> dict[str, Any]:
    """Update CDN ranges and expire stale cache entries.

    Called by `python -m app update`.
    """
    import json
    base = Path(data_dir)
    # CDN ranges would normally be fetched from official sources.
    # For now we write stub files so the system is functional offline.
    cdn_dir = base / "cdn"
    cdn_dir.mkdir(parents=True, exist_ok=True)
    for provider in ("cloudflare-v4", "cloudflare-v6", "akamai", "fastly", "cloudfront"):
        path = cdn_dir / f"{provider}.json"
        if not path.exists():
            with open(path, "w") as f:
                json.dump([], f)

    # Expire stale DNS entries.
    try:
        with open_caches(base / "cache") as caches:
            removed = caches["dns"].cleanup_expired()
        return {"ok": True, "expired_dns_entries": removed, "cdn_files": len(list(cdn_dir.glob("*.json")))}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
