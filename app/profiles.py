"""Research and traffic profiles.

Profiles govern *measurement and classification* behaviour only.  They never
enable packet injection or transformation unless explicitly marked with
`packet_manipulation: true` AND `laboratory_setting: true`.  By default all
profiles are measurement-only.  This is a deliberate safety constraint.
"""

from __future__ import annotations

from typing import Any


DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "baseline": {
        "description": "Default measurement profile.",
        "prefer_ipv6": True,
        "ipv4_fallback": True,
        "udp_support": True,
        "quic_policy": "observe",
        "mtu_aware": True,
        "connection_reuse": True,
        "packet_manipulation": False,
        "laboratory_setting": False,
        "fragmentation_analysis": False,
        "dns_analysis": False,
        "tls_analysis": True,
    },
    "low_latency": {
        "description": "Minimise probe overhead, prioritise fastest candidate.",
        "prefer_ipv6": True,
        "ipv4_fallback": True,
        "udp_support": True,
        "quic_policy": "observe",
        "mtu_aware": True,
        "connection_reuse": True,
        "packet_manipulation": False,
        "laboratory_setting": False,
        "fragmentation_analysis": False,
        "dns_analysis": False,
        "tls_analysis": False,
    },
    "fragmentation_analysis": {
        "description": "Measurement-only capture of packet sizes and ClientHello layout.",
        "prefer_ipv6": True,
        "ipv4_fallback": True,
        "udp_support": True,
        "quic_policy": "observe",
        "mtu_aware": True,
        "connection_reuse": True,
        "packet_manipulation": False,
        "laboratory_setting": True,
        "fragmentation_analysis": True,
        "dns_analysis": False,
        "tls_analysis": True,
    },
    "dns_analysis": {
        "description": "Deep DNS inspection (A/AAAA/CNAME/TXT/NS).",
        "prefer_ipv6": True,
        "ipv4_fallback": True,
        "udp_support": True,
        "quic_policy": "observe",
        "mtu_aware": True,
        "connection_reuse": True,
        "packet_manipulation": False,
        "laboratory_setting": True,
        "fragmentation_analysis": False,
        "dns_analysis": True,
        "tls_analysis": True,
    },
    "tls_analysis": {
        "description": "TLS certificate and SNI telemetry.",
        "prefer_ipv6": True,
        "ipv4_fallback": True,
        "udp_support": True,
        "quic_policy": "observe",
        "mtu_aware": True,
        "connection_reuse": True,
        "packet_manipulation": False,
        "laboratory_setting": True,
        "fragmentation_analysis": False,
        "dns_analysis": False,
        "tls_analysis": True,
    },
    "gaming_measurement": {
        "description": "Gaming measurement: low latency, minimal buffering, UDP/QUIC aware, "
                       "NO transformation by default (to avoid worsening jitter).",
        "prefer_ipv6": True,
        "ipv4_fallback": True,
        "udp_support": True,
        "quic_policy": "prefer",
        "mtu_aware": True,
        "connection_reuse": True,
        "packet_manipulation": False,
        "laboratory_setting": False,
        "fragmentation_analysis": False,
        "dns_analysis": False,
        "tls_analysis": False,
    },
}


# Gaming profile is derived here so it stays isolated from web profiles.
GAMING_PROFILE_NAME = "gaming_measurement"


def get_profile(name: str, profiles: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a profile by name, falling back to baseline fields."""
    profiles = profiles or DEFAULT_PROFILES
    base = dict(DEFAULT_PROFILES["baseline"])
    base.update(profiles.get(name, {}))
    base["name"] = name
    return base


def is_gaming_profile(name: str) -> bool:
    return name == GAMING_PROFILE_NAME or name.startswith("gaming")
