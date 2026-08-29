"""Structured JSON logging.

All log records are emitted as JSON with a consistent schema so they can be
machine-parsed.  Human-friendly rendering is handled separately (see cli dashboard).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from app.models import LogEntry


class JsonFormatter(logging.Formatter):
    """Format LogRecords as structured JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        # If caller passed a fully-structured payload, emit it verbatim.
        structured = getattr(record, "structured", None)
        if structured:
            return json.dumps(structured, default=str)
        entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc),
            event=record.getMessage() if not getattr(record, "event", None) else record.event,  # type: ignore[arg-type]
            hostname=getattr(record, "hostname", None),
            ip=getattr(record, "ip", None),
            latency_ms=getattr(record, "latency_ms", None),
            success=getattr(record, "success", False),
            details=getattr(record, "details", {}) or {},
        )
        return entry.model_dump_json()


class AppLogger:
    """Thin wrapper around logging that captures structured entries in memory."""

    def __init__(self, name: str = "netprobe", level: int = logging.INFO, capture: bool = True):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(JsonFormatter())
            self._logger.addHandler(handler)
        self._logger.propagate = False
        self.capture = capture
        self.entries: list[dict[str, Any]] = []

    def _emit(self, event: str, level: int, *, hostname=None, ip=None, latency_ms=None,
              success=False, **details: Any) -> None:
        extra = {
            "event": event,
            "hostname": hostname,
            "ip": ip,
            "latency_ms": latency_ms,
            "success": success,
            "details": details,
        }
        record = self._logger.makeRecord(
            self._logger.name, level, "(app)", 0, event, None, None, extra=extra
        )
        self._logger.handle(record)
        if self.capture:
            self.entries.append({
                "event": event,
                "hostname": hostname,
                "ip": ip,
                "latency_ms": latency_ms,
                "success": success,
                "details": details,
                "level": logging.getLevelName(level),
            })

    def debug(self, event: str, **kw: Any) -> None:
        self._emit(event, logging.DEBUG, **kw)

    def info(self, event: str, **kw: Any) -> None:
        self._emit(event, logging.INFO, **kw)

    def warning(self, event: str, **kw: Any) -> None:
        self._emit(event, logging.WARNING, **kw)

    def error(self, event: str, **kw: Any) -> None:
        self._emit(event, logging.ERROR, **kw)

    def get_entries(self) -> list[dict[str, Any]]:
        return list(self.entries)


# Module-level default logger
default_logger = AppLogger()


def get_logger() -> AppLogger:
    return default_logger
