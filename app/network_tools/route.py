"""Routing / interface helpers (system `ip` command wrappers).

Uses subprocess.run with a fixed arg list and shell=False.  No raw command strings.
"""

from __future__ import annotations

import subprocess
from typing import Any

from app.security import safe_subprocess_args


def ip_addr_show(dev: str | None = None) -> list[dict[str, Any]]:
    """Return interface addresses via `ip -j addr show`."""
    args = ["ip", "-j", "addr", "show"]
    if dev:
        args.append(dev)
    args = safe_subprocess_args(args)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if proc.returncode != 0:
        raise RuntimeError(f"ip addr show failed: {proc.stderr}")
    import json
    return json.loads(proc.stdout)


def ip_route_get(host: str) -> dict[str, Any]:
    """Resolve the routing decision for a host via `ip route get`.

    Accepts either a hostname or a literal IP (both valid `ip route get` targets).
    """
    from app.security import validate_hostname, validate_ip
    try:
        validate_ip(host)
    except Exception:
        host = validate_hostname(host)
    args = safe_subprocess_args(["ip", "-j", "route", "get", host])
    proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
    import json
    if proc.returncode != 0:
        return {"ok": False, "output": proc.stderr}
    data = json.loads(proc.stdout)
    if isinstance(data, list) and data:
        return {"ok": True, **data[0]}
    return {"ok": True, "raw": data}


def get_default_interface_ipv4(addr: str = "8.8.8.8") -> str:
    """Best-effort detection of the egress IPv4 address (no packets sent)."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def get_default_interface_ipv6(addr: str = "2001:4860:4860::8888") -> str:
    """Best-effort detection of the egress IPv6 address."""
    import socket
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()
