"""Metrics collection.

Tracks (per spec):
  dns_latency, tcp_connect_latency, tls_latency, packet_loss, jitter,
  ipv4_success, ipv6_success, cdn_confidence, route_changes, xray_restarts.

Metrics are exported to JSON and aggregated for the dashboard.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Metrics:
    """Thread-safe metrics store with rolling samples for latency metrics."""

    def __init__(self, max_samples: int = 1000):
        self._lock = threading.Lock()
        self._max_samples = max_samples
        self._samples: dict[str, deque[float]] = {}
        self._counters: dict[str, float] = {
            "ipv4_success": 0.0,
            "ipv6_success": 0.0,
            "cdn_confidence_sum": 0.0,
            "cdn_confidence_count": 0.0,
            "route_changes": 0.0,
            "xray_restarts": 0.0,
        }
        self._last_route_action: str | None = None

    # ---- latency-style samples ----
    def record_latency(self, name: str, value_ms: float) -> None:
        with self._lock:
            dq = self._samples.setdefault(name, deque(maxlen=self._max_samples))
            dq.append(value_ms)

    def record_packet_loss(self, loss: float) -> None:
        self.record_latency("packet_loss", loss)

    def record_jitter(self, jitter_ms: float) -> None:
        self.record_latency("jitter", jitter_ms)

    # ---- counters ----
    def increment(self, name: str, amount: float = 1.0) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + amount

    def record_dns_latency(self, ms: float) -> None:
        self.record_latency("dns_latency", ms)

    def record_tcp_latency(self, ms: float) -> None:
        self.record_latency("tcp_connect_latency", ms)

    def record_tls_latency(self, ms: float) -> None:
        self.record_latency("tls_latency", ms)

    def record_ipv4_success(self) -> None:
        self.increment("ipv4_success")

    def record_ipv6_success(self) -> None:
        self.increment("ipv6_success")

    def record_cdn_confidence(self, confidence: float) -> None:
        with self._lock:
            self._counters["cdn_confidence_sum"] += confidence
            self._counters["cdn_confidence_count"] += 1.0

    def record_route_change(self, action: str) -> None:
        with self._lock:
            if self._last_route_action != action:
                self._counters["route_changes"] += 1.0
                self._last_route_action = action

    def record_xray_restart(self) -> None:
        self.increment("xray_restarts")

    # ---- aggregation ----
    def _avg(self, name: str) -> float | None:
        with self._lock:
            dq = self._samples.get(name)
            if not dq:
                return None
            return sum(dq) / len(dq)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            samples_avg = {k: (sum(v) / len(v) if v else None) for k, v in self._samples.items()}
            counters = dict(self._counters)
            cdn_avg = None
            if counters.get("cdn_confidence_count"):
                cdn_avg = counters["cdn_confidence_sum"] / counters["cdn_confidence_count"]
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "latency_averages_ms": samples_avg,
                "counters": counters,
                "cdn_confidence_avg": cdn_avg,
            }

    def export_json(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            import json
            json.dump(self.snapshot(), f, indent=2, default=str)

    @classmethod
    def load_or_create(cls, path: str | Path | None = None) -> "Metrics":
        return cls()


# Module-level default metrics instance.
default_metrics = Metrics()
