"""Ping / reachability probes: ICMP, TCP connect, TLS connect.

IMPORTANT: a failed ICMP probe does NOT mean the host is down — ICMP is often
blocked by firewalls even when TCP/443 is perfectly reachable.  We never equate
ping failure with "site is broken".
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from typing import Any, Protocol

from app.models import ProbeResult, ProbeTarget
from app.security import safe_subprocess_args, validate_hostname, validate_port


class ProbeBackend(Protocol):
    def probe(self, target: ProbeTarget) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# ICMP ping (system `ping`)
# ---------------------------------------------------------------------------

class IcmpProber:
    """Use the system `ping` command to measure ICMP reachability."""

    name = "icmp"

    def probe(self, target: ProbeTarget, count: int = 4, timeout_s: float = 3.0) -> dict[str, Any]:
        from app.security import validate_ip
        # ping works with hostnames or IPs; validate lightly.
        host = target.host
        args = safe_subprocess_args([
            "ping", "-c", str(count), "-w", str(int(timeout_s)), host,
        ])
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_s + 2)
        except FileNotFoundError:
            return {"supported": False, "reachable": False, "latency_ms": None,
                    "error": "ping binary not found"}
        except subprocess.TimeoutExpired:
            return {"supported": True, "reachable": False, "latency_ms": None,
                    "error": "ping timed out"}

        supported = proc.returncode in (0, 1, 2)
        reachable = proc.returncode == 0
        latency: float | None = None
        # Parse min/avg/max/mdev from ping output.
        for line in proc.stdout.splitlines():
            if "round-trip" in line or "rtt" in line:
                parts = line.split("=")[-1].strip().split("/")
                if len(parts) >= 2:
                    try:
                        latency = float(parts[1])  # avg
                    except ValueError:
                        latency = None
        return {"supported": supported, "reachable": reachable, "latency_ms": latency}


# ---------------------------------------------------------------------------
# TCP connect probe
# ---------------------------------------------------------------------------

class TcpProber:
    """Probe TCP connectivity by attempting a socket connect.

    `target` may be a ProbeTarget, a dict {"host", "port"}, or an object
    with `.host` / `.port` attributes (both shapes are used across the codebase).
    """

    name = "tcp"

    def probe(self, target: ProbeTarget | dict | Any, timeout: float = 5.0, prefer_v6: bool = True) -> dict[str, Any]:
        import socket

        # Normalise target to a ProbeTarget (accept dict or object shape).
        if isinstance(target, dict):
            target = ProbeTarget(**{k: v for k, v in target.items() if k in ("host", "port")})
        host = target.host
        port = validate_port(target.port)
        # Try the preferred family first, then fall back to the other on failure.
        # This matters when the host has e.g. only IPv6 addresses but this machine
        # has no IPv6 route (common on NAT/CN networks) — we must still reach it
        # over IPv4 rather than reporting a bogus "unreachable".
        families = [socket.AF_INET6, socket.AF_INET] if prefer_v6 else [socket.AF_INET, socket.AF_INET6]
        last_err: str | None = None
        for family in families:
            family_name = "ipv6" if family == socket.AF_INET6 else "ipv4"
            try:
                infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
            except (socket.gaierror, OSError) as exc:
                last_err = f"getaddrinfo {family_name} failed: {exc}"
                continue
            if not infos:
                last_err = f"no {family_name} addresses"
                continue
            for info in infos:
                fam, _, _, _, sockaddr = info
                start = time.monotonic()
                sock = socket.socket(fam, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                try:
                    sock.connect(sockaddr)
                    latency = round((time.monotonic() - start) * 1000, 1)
                    sock.close()
                    return {"reachable": True, "latency_ms": latency, "ip": sockaddr[0],
                            "family": "ipv6" if fam == socket.AF_INET6 else "ipv4"}
                except OSError as exc:
                    last_err = str(exc)
                    sock.close()
        return {"reachable": False, "latency_ms": None, "error": last_err or "connect failed"}


# ---------------------------------------------------------------------------
# TLS connect probe (thin wrapper around tls_inspector)
# ---------------------------------------------------------------------------

def tls_probe(target: ProbeTarget, timeout: float = 8.0) -> dict[str, Any]:
    """Probe TLS handshake (used for reachability telemetry)."""
    from app.tls_inspector import inspect_tls
    res = inspect_tls(target.host, port=target.port, timeout=timeout)
    return {
        "reachable": res.success,
        "latency_ms": res.latency_ms,
        "tls_version": res.tls_version,
        "error": res.error,
    }


# ---------------------------------------------------------------------------
# Combined multi-probe
# ---------------------------------------------------------------------------

def probe_host(host: str, port: int = 443) -> ProbeResult:
    """Run all probe types against a host and combine."""
    host = validate_hostname(host)
    target = ProbeTarget(host=host, port=port)
    icmp = IcmpProber().probe(target)
    tcp = TcpProber().probe(target)
    tls = tls_probe(target)
    return ProbeResult(host=host, icmp=icmp, tcp443=tcp, tls=tls)


async def probe_host_async(host: str, port: int = 443) -> ProbeResult:
    """Async variant running probes concurrently."""
    host = validate_hostname(host)
    target = ProbeTarget(host=host, port=port)
    loop = asyncio.get_running_loop()
    icmp, tcp, tls = await asyncio.gather(
        loop.run_in_executor(None, IcmpProber().probe, target),
        loop.run_in_executor(None, TcpProber().probe, target),
        loop.run_in_executor(None, tls_probe, target),
    )
    return ProbeResult(host=host, icmp=icmp, tcp443=tcp, tls=tls)
