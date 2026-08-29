"""Xray-core configuration templates (structured data, not strings)."""

from __future__ import annotations

from typing import Any


LOG_TEMPLATES: dict[str, dict[str, Any]] = {
    "warning": {"loglevel": "warning", "dnsLog": False, "access": "none"},
    "info": {"loglevel": "info", "dnsLog": False, "access": "none"},
    "debug": {"loglevel": "debug", "dnsLog": True, "access": "none"},
}


DNS_TEMPLATES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "address": "https://cloudflare-dns.com/dns-query",
        "timeoutMs": 6000,
        "finalQuery": True,
    },
    "google": {
        "address": "https://dns.google/dns-query",
        "timeoutMs": 6000,
        "finalQuery": True,
    },
    "quad9": {
        "address": "https://dns.quad9.net/dns-query",
        "timeoutMs": 6000,
        "finalQuery": True,
    },
}


INBOUND_MIXED_TEMPLATE: dict[str, Any] = {
    "tag": "mixed-in",
    "port": 10808,
    "protocol": "mixed",
    "sniffing": {
        "enabled": True,
        "destOverride": ["fakedns", "tls", "http", "quic"],
        "routeOnly": False,
    },
    "settings": {"udp": True, "ip": "127.0.0.1"},
    "streamSettings": {
        "sockopt": {"tcpKeepAliveInterval": 1, "tcpKeepAliveIdle": 11},
    },
}


BLOCK_OUTBOUND_TEMPLATE: dict[str, Any] = {"tag": "block", "protocol": "block"}
DIRECT_OUTBOUND_TEMPLATE: dict[str, Any] = {"tag": "direct", "protocol": "direct"}
DNS_OUTBOUND_TEMPLATE: dict[str, Any] = {
    "tag": "dns-out",
    "protocol": "dns",
    "settings": {"userLevel": 1},
}


def render_mixed_inbound(port: int = 10808, ip: str = "127.0.0.1") -> dict[str, Any]:
    """Render a mixed inbound dict (congfigurable port/ip)."""
    tpl = dict(INBOUND_MIXED_TEMPLATE)
    tpl["port"] = port
    tpl["settings"]["ip"] = ip
    return tpl
