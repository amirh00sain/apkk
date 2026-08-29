"""TCP connectivity helpers.

Used for reachability checks and as a building block in the probe engine.
All operations use the standard library socket — no raw sockets, no shell.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from app.security import validate_hostname, validate_port, validate_ip


def tcp_connect(hostname: str, port: int, *, timeout: float = 5.0, prefer_ipv6: bool = True) -> dict[str, Any]:
    """Attempt a TCP connect and report latency.  No data is sent.

    Accepts either a hostname or a literal IP address.
    Returns a dict with keys: reachable, latency_ms, ip, family, error.
    """
    port = validate_port(port)
    # Accept IPs directly; only run hostname validation for non-numeric hosts.
    try:
        validate_ip(hostname)
    except Exception:
        hostname = validate_hostname(hostname)
    family = socket.AF_INET6 if prefer_ipv6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(hostname, port, family, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        family = socket.AF_INET if prefer_ipv6 else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(hostname, port, family, socket.SOCK_STREAM)
        except (socket.gaierror, OSError) as exc:
            return {"reachable": False, "latency_ms": None, "error": f"getaddrinfo: {exc}"}
    if not infos:
        return {"reachable": False, "latency_ms": None, "error": "no addresses"}

    last_err: str | None = None
    for info in infos:
        fam, _, _, _, sockaddr = info
        start = time.monotonic()
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            latency = round((time.monotonic() - start) * 1000, 1)
            sock.close()
            return {
                "reachable": True,
                "latency_ms": latency,
                "ip": sockaddr[0],
                "family": "ipv6" if fam == socket.AF_INET6 else "ipv4",
            }
        except OSError as exc:
            last_err = str(exc)
            try:
                sock.close()
            except OSError:
                pass
    return {"reachable": False, "latency_ms": None, "error": last_err or "connect failed"}


def measure_jitter(hostname: str, port: int, samples: int = 10, timeout: float = 5.0) -> dict[str, Any]:
    """Measure latency jitter across N samples.

    Returns min/avg/max/stddev of round-trip connect latency.
    """
    latencies: list[float] = []
    for _ in range(samples):
        r = tcp_connect(hostname, port, timeout=timeout)
        if r.get("reachable"):
            latencies.append(float(r["latency_ms"]))
        else:
            latencies.append(float("nan"))
    valid = [x for x in latencies if not (isinstance(x, float) and x != x)]
    if not valid:
        return {"samples": samples, "jitter_ms": None, "packet_loss": 1.0}
    import statistics
    avg = statistics.fmean(valid)
    mx = max(valid)
    mn = min(valid)
    std = statistics.pstdev(valid) if len(valid) > 1 else 0.0
    return {
        "samples": samples,
        "min_ms": round(mn, 2),
        "avg_ms": round(avg, 2),
        "max_ms": round(mx, 2),
        "jitter_ms": round(std, 2),
        "packet_loss": round((samples - len(valid)) / samples, 3),
    }
