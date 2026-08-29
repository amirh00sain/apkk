"""Destination database — store and query observed/verified endpoints.

This database NEVER claims to have discovered "all websites".  Every record
carries an explicit status (observed / resolved / provider_detected /
tls_verified / fresh / stale / failed) so claims can be audited.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models import EndpointRecord, RecordStatus


class DestinationDB:
    """JSON-backed endpoint store with in-memory index."""

    def __init__(self, path: str | Path = "data/domains/verified.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._records: dict[str, EndpointRecord] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        with self._lock:
            for item in raw:
                rec = EndpointRecord(**item)
                self._records[rec.hostname] = rec

    def save(self) -> None:
        with self._lock:
            data = [r.model_dump(mode="json") for r in self._records.values()]
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def upsert(self, record: EndpointRecord) -> None:
        with self._lock:
            self._records[record.hostname] = record
        self.save()

    def get(self, hostname: str) -> EndpointRecord | None:
        with self._lock:
            return self._records.get(hostname.lower())

    def all(self) -> list[EndpointRecord]:
        with self._lock:
            return list(self._records.values())

    def query_by_provider(self, provider: str) -> list[EndpointRecord]:
        return [r for r in self.all() if r.provider == provider]

    def mark_status(self, hostname: str, status: RecordStatus) -> None:
        rec = self.get(hostname)
        if rec:
            rec.status = status
            rec.last_seen = datetime.now(timezone.utc)
            self.save()

    def add_source(self, hostname: str, source: str) -> None:
        rec = self.get(hostname)
        if rec and source not in rec.source:
            rec.source.append(source)
            self.save()
