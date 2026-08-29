"""Input validation and security helpers.  No shell=True.  No raw command strings."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any


_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
_PORT_MIN = 1
_PORT_MAX = 65535


class ValidationError(Exception):
    """Raised when an input fails validation."""

    def __init__(self, category: str, message: str, cause: str = "", recovery: str = ""):
        self.category = category
        self.message = message
        self.cause = cause
        self.recovery = recovery
        super().__init__(f"[{category}] {message}")


# --------------- hostname ---------------

def validate_hostname(hostname: str) -> str:
    """Validate and normalise a hostname.  Returns lowercase stripped string."""
    hostname = hostname.strip().lower()
    if not hostname:
        raise ValidationError("hostname", "empty hostname")
    if len(hostname) > 253:
        raise ValidationError("hostname", f"hostname too long ({len(hostname)} > 253)")
    if not _HOSTNAME_RE.match(hostname):
        raise ValidationError(
            "hostname",
            f"invalid hostname format: {hostname!r}",
            recovery="provide a valid FQDN such as example.com",
        )
    return hostname


# --------------- IP ---------------

def validate_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse and validate an IP address string."""
    ip_str = ip_str.strip()
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValidationError("ip", f"invalid IP address: {ip_str!r}")


# --------------- CIDR ---------------

def validate_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse and validate a CIDR network string."""
    cidr = cidr.strip()
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ValidationError("cidr", f"invalid CIDR: {cidr!r}")


# --------------- Port ---------------

def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number."""
    if not isinstance(port, int) or port < _PORT_MIN or port > _PORT_MAX:
        raise ValidationError("port", f"port out of range: {port}")
    return port


# --------------- Path ---------------

def validate_path(path: str, *, must_exist: bool = False, must_be_file: bool = False) -> Path:
    """Validate a filesystem path.  Rejects traversal outside cwd by default."""
    p = Path(path).expanduser().resolve()
    if must_exist and not p.exists():
        raise ValidationError("path", f"path does not exist: {p}")
    if must_be_file and not p.is_file():
        raise ValidationError("path", f"not a regular file: {p}")
    return p


# --------------- JSON blob ---------------

def validate_json(data: Any) -> Any:
    """Basic sanity check — ensure the data is serialisable."""
    import json
    try:
        json.loads(json.dumps(data))
    except (TypeError, ValueError) as exc:
        raise ValidationError("json", "data is not JSON-serialisable", cause=str(exc))
    return data


# --------------- subprocess safety ---------------

def safe_subprocess_args(args: list[str]) -> list[str]:
    """Ensure subprocess args are safe strings — no shell metacharacters."""
    safe: list[str] = []
    for a in args:
        if not isinstance(a, str):
            raise ValidationError(
                "subprocess",
                f"non-string arg in subprocess list: {a!r}",
                recovery="pass only string arguments",
            )
        if any(ch in a for ch in (";", "|", "&", "$", "`", "\n", "\r")):
            raise ValidationError(
                "subprocess",
                f"shell metacharacter in arg: {a!r}",
                recovery="do not use shell syntax in arguments",
            )
        safe.append(a)
    return safe


# --------------- is_private helper ---------------

PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if ip_str belongs to any private/reserved range."""
    addr = validate_ip(ip_str)
    return any(addr in net for net in PRIVATE_NETWORKS)


def build_block_networks(extra_cidrs: list[str] | None = None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Build the full blocklist from built-in private ranges + user CIDRs."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(PRIVATE_NETWORKS)
    if extra_cidrs:
        for c in extra_cidrs:
            nets.append(validate_cidr(c))
    return nets


def is_blocked(ip_str: str, block_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None) -> bool:
    """Check if an IP falls within the combined blocklist."""
    nets = block_networks if block_networks is not None else PRIVATE_NETWORKS
    addr = validate_ip(ip_str)
    return any(addr in net for net in nets)
