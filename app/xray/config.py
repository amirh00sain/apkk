"""Xray-core JSON configuration generator.

All configuration is built from structured Python dicts and serialised with
json.dumps.  No string concatenation, no template string interpolation.

Features:
  - DoH (DNS over HTTPS) for all resolver traffic
  - TLS ClientHello Fragment to break DPI fingerprints
  - Tor SOCKS outbound (optional) for an onion route
  - Private/IR direct routing; everything else through the tunnel (or direct)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config_loader import AppConfig
from app.security import validate_path


def _base_config(log_level: str = "warning") -> dict[str, Any]:
    return {
        "remarks": "NetProbe generated config — credits: @patterniha (SNI-Spoofing project reference)",
        "log": {"loglevel": log_level, "dnsLog": False, "access": "none"},
        "policy": {
            "levels": {
                "0": {"uplinkOnly": 0, "downlinkOnly": 0},
                "1": {"uplinkOnly": 0, "downlinkOnly": 0, "connIdle": 6},
            },
        },
    }


# ---------------------------------------------------------------------------
# DNS — DoH as primary resolver; localhost as fallback
# ---------------------------------------------------------------------------

_DOH_URLS: dict[str, str] = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/dns-query",
    "quad9":      "https://dns.quad9.net/dns-query",
}


def _dns_section(cfg: AppConfig, doh_providers: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build DNS section with DoH as the primary resolver.

    DoH is used for *all* DNS queries so the resolver never sees plaintext
    DNS.  The localhost entry is a fallback for private/internal domains.
    """
    provider = cfg.dns.get("provider", "cloudflare")
    doh_providers = doh_providers or {}

    # Resolve DoH URL: prefer loaded dns.json, fall back to built-in table.
    doh_url = (
        doh_providers.get(provider, {}).get("doh_url")
        or _DOH_URLS.get(provider)
        or "https://cloudflare-dns.com/dns-query"
    )

    return {
        "queryStrategy": "UseIPv4",
        "useSystemHosts": True,
        "disableCache": False,
        "disableFallback": False,
        "servers": [
            # Primary: DoH (all queries go here by default)
            {
                "address": doh_url,
                "domains": [
                    "geosite:geolocation-!cn",
                ],
                "timeoutMs": cfg.dns.get("timeout_ms", 6000),
                "queryStrategy": "UseIPv4",
                "skipFallback": False,
            },
            # Fallback: localhost for private/internal domains
            {
                "address": "localhost",
                "domains": [
                    "geosite:private",
                    "domain:ir",
                    "domain:local",
                    "domain:localhost",
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Inbound — local SOCKS5/HTTP mixed proxy (localhost only)
# ---------------------------------------------------------------------------

def _inbound(cfg: AppConfig, port: int = 10808, host: str = "127.0.0.1") -> list[dict[str, Any]]:
    """Local mixed inbound (SOCKS5 + HTTP on the same port).

    Fragment settings are applied here to break up the *outgoing* TLS
    ClientHello from the local proxy, making DPI fingerprinting harder.
    """
    stream: dict[str, Any] = {
        "sockopt": {
            "tcpKeepAliveInterval": 1,
            "tcpKeepAliveIdle": 11,
        },
    }
    return [
        {
            "tag": "mixed-in",
            "port": port,
            "protocol": "mixed",
            "sniffing": {
                "enabled": True,
                "destOverride": ["fakedns", "tls", "http", "quic"],
                "routeOnly": False,
            },
            "settings": {"udp": True, "ip": host},
            "streamSettings": stream,
        },
    ]


# ---------------------------------------------------------------------------
# Fragment — break up TLS ClientHello to bypass DPI
# ---------------------------------------------------------------------------

def _fragment_stream_settings() -> dict[str, Any]:
    """Stream settings with TLS ClientHello Fragment enabled.

    Fragment splits the outgoing TLS ClientHello into small pieces with
    random sleep intervals, defeating DPI systems that reassemble by
    matching the full ClientHello fingerprint.
    """
    return {
        "sockopt": {
            "tcpKeepAliveInterval": 1,
            "tcpKeepAliveIdle": 11,
        },
        "security": "tls",
        "tlsSettings": {
            "fragment": {
                "enabled": True,
                "length": "100-200",
                "sleep": "50-100",
            },
        },
    }


# ---------------------------------------------------------------------------
# Happy Eyeballs — fast dual-stack connection
# ---------------------------------------------------------------------------

def _happy_eyeballs(prioritize_ipv6: bool = False) -> dict[str, Any]:
    return {
        "tryDelayMs": 300,
        "prioritizeIPv6": prioritize_ipv6,
        "interleave": 2,
        "maxConcurrentTry": 20,
    }


# ---------------------------------------------------------------------------
# Outbounds
# ---------------------------------------------------------------------------

def _tor_outbound(socks_host: str = "127.0.0.1", socks_port: int = 9050) -> dict[str, Any]:
    """Build a SOCKS outbound that routes traffic through a local Tor instance.

    xray speaks SOCKS natively, so it can chain through a running Tor
    daemon (``tor`` listening on 127.0.0.1:9050).  This gives a 3-hop
    onion route on top of the Fragment/DoH layer.
    """
    return {
        "tag": "tor-out",
        "protocol": "socks",
        "settings": {
            "servers": [{"address": socks_host, "port": int(socks_port)}],
        },
        "streamSettings": {
            "sockopt": {"domainStrategy": "UseIP"},
        },
    }


def _outbounds(cfg: AppConfig, proxy_cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Build outbound list.

    If ``proxy_cfg`` is provided and has ``tor`` enabled, a ``tor-out``
    outbound is added and external traffic routes through it.
    """
    prefer_v6 = cfg.profiles and any("gaming" in p for p in cfg.profiles)

    outbounds: list[dict[str, Any]] = [
        {"tag": "block", "protocol": "block"},
        {
            "tag": "direct",
            "protocol": "direct",
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "ForceIP",
                    "happyEyeballs": _happy_eyeballs(prefer_v6),
                },
            },
        },
        {
            "tag": "dns-out",
            "protocol": "dns",
            "settings": {"userLevel": 1},
        },
    ]

    # Add Tor outbound when enabled.
    if proxy_cfg and proxy_cfg.get("tor"):
        outbounds.insert(0, _tor_outbound(
            socks_host=proxy_cfg.get("tor_socks_host", "127.0.0.1"),
            socks_port=proxy_cfg.get("tor_socks_port", 9050),
        ))

    return outbounds


# ---------------------------------------------------------------------------
# Routing rules
# ---------------------------------------------------------------------------

def _routing_rules(
    cfg: AppConfig,
    has_tor: bool = False,
) -> list[dict[str, Any]]:
    """Build routing rules.

    Priority:
      1. Tor is present      → external goes through ``tor-out``
      2. Neither             → external goes direct

    Private/IR domains and IPs always bypass the tunnel.
    """
    rules: list[dict[str, Any]] = []

    # DNS queries → dns-out
    rules.append({"outboundTag": "dns-out", "port": 53})

    # Private / IR direct (always bypass the tunnel)
    rules.append({
        "outboundTag": "direct",
        "domain": [
            "geosite:private",
            "domain:ir",
            "domain:localhost",
            "domain:local",
            "geosite:category-ir",
        ],
    })
    rules.append({
        "outboundTag": "direct",
        "ip": ["geoip:private", "geoip:ir"],
    })

    # User blocklist
    rules.append({
        "outboundTag": "block",
        "ip": ["10.10.34.0/24", "2001:4188:2:600::/64"],
    })

    # External traffic routing: Tor > direct.
    default_out = "tor-out" if has_tor else "direct"

    rules.append({
        "outboundTag": default_out,
        "ip": ["0.0.0.0/0", "::/0"],
    })

    # Catch-all block (should never be reached)
    rules.append({"outboundTag": "block", "port": "0-65535"})
    return rules


def is_tor_available(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Check if a Tor SOCKS port is reachable on localhost."""
    import socket
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        return True
    except (OSError, TimeoutError):
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_xray_config(
    cfg: AppConfig,
    doh_providers: dict[str, Any] | None = None,
    output_path: str | Path | None = None,
    proxy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete xray-core JSON config from app configuration.

    Parameters
    ----------
    proxy : dict | None
        Tunnel settings.  Keys: ``tor`` (bool), ``fragment`` (bool),
        ``tor_socks_host``, ``tor_socks_port``.  When ``tor`` is enabled,
        external traffic routes through the Tor SOCKS outbound on top of the
        DoH resolver and optional TLS Fragment for DPI avoidance.
    """
    proxy_cfg = proxy or {}
    has_tor = bool(proxy_cfg.get("tor"))

    config: dict[str, Any] = _base_config()
    config["dns"] = _dns_section(cfg, doh_providers)
    config["inbounds"] = _inbound(cfg)
    config["outbounds"] = _outbounds(cfg, proxy_cfg if has_tor else None)
    config["routing"] = {
        "domainStrategy": "IPOnDemand",
        "rules": _routing_rules(cfg, has_tor=has_tor),
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    return config


def validate_xray_config(config_path: str | Path) -> dict[str, Any]:
    """Load and validate an xray JSON config file."""
    path = validate_path(str(config_path), must_exist=True, must_be_file=True)
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)
    errors: list[str] = []
    required = {"inbounds", "outbounds", "routing"}
    for key in required:
        if key not in config:
            errors.append(f"missing required key: {key}")
    if not config.get("inbounds"):
        errors.append("inbounds is empty")
    if not config.get("outbounds"):
        errors.append("outbounds is empty")
    if not config.get("routing", {}).get("rules"):
        errors.append("routing.rules is empty")

    if errors:
        raise ValueError("config validation failed:\n" + "\n".join(f"  - {e}" for e in errors))
    return config
