"""Xray-core health checking.

Verifies that the xray process is alive and its inbound proxy port accepts
connections.  Reports structured health status.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from app.logger import get_logger

logger = get_logger()


def check_process_alive(proc: Any) -> bool:
    """Return True if the process is running."""
    return proc is not None and proc.poll() is None


def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def health_check(config: dict[str, Any], proc: Any, timeout: float = 3.0) -> dict[str, Any]:
    """Full health check: process alive + at least one inbound port reachable."""
    alive = check_process_alive(proc)
    ports_ok = []
    if alive:
        for inbound in config.get("inbounds", []):
            port = inbound.get("port")
            if isinstance(port, int):
                ok = check_port_open("127.0.0.1", port, timeout=timeout)
                ports_ok.append({"port": port, "tag": inbound.get("tag"), "open": ok})
    healthy = alive and any(p["open"] for p in ports_ok)
    return {
        "process_alive": alive,
        "healthy": healthy,
        "ports": ports_ok,
    }
