"""SQLite-backed storage for DNS, TLS, and probe caches.

Three databases:
  - data/cache/dns.sqlite    (hostname, record_type, value, ttl, expires_at, source)
  - data/cache/tls.sqlite    (certificate / SNI records)
  - data/cache/probes.sqlite (probe / reachability history)

Fresh → use; stale → use temporarily + refresh; expired → resolve again.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.security import validate_hostname


_SCHEMA: dict[str, str] = {
    "dns": """
        CREATE TABLE IF NOT EXISTS dns_cache (
            hostname TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INTEGER,
            expires_at REAL NOT NULL,
            source TEXT,
            PRIMARY KEY (hostname, record_type, value)
        );
    """,
    "tls": """
        CREATE TABLE IF NOT EXISTS tls_cache (
            hostname TEXT NOT NULL,
            ip TEXT,
            sni TEXT,
            issuer TEXT,
            valid_from TEXT,
            valid_to TEXT,
            tls_version TEXT,
            cipher TEXT,
            san TEXT,
            latency_ms REAL,
            success INTEGER,
            probed_at REAL,
            PRIMARY KEY (hostname, ip)
        );
    """,
    "probes": """
        CREATE TABLE IF NOT EXISTS probe_cache (
            host TEXT NOT NULL,
            icmp_reachable INTEGER,
            icmp_latency REAL,
            tcp_reachable INTEGER,
            tcp_latency REAL,
            tls_reachable INTEGER,
            tls_latency REAL,
            probed_at REAL,
            PRIMARY KEY (host)
        );
    """,
}


class CacheDB:
    """SQLite cache wrapper with a single connection and a lock."""

    def __init__(self, db_type: str, path: str | Path):
        self.db_type = db_type
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA[self.db_type])
            self._conn.commit()

    def now_ts(self) -> float:
        return datetime.now(timezone.utc).timestamp()

    def is_fresh(self, expires_at: float) -> bool:
        return self.now_ts() < expires_at

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __del__(self) -> None:  # best-effort safety net; prefer explicit close()
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "CacheDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- DNS cache ---
    def put_dns(self, hostname: str, record_type: str, value: str, ttl: int | None, source: str) -> None:
        hostname = validate_hostname(hostname)
        expires_at = self.now_ts() + (ttl if ttl else 300)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO dns_cache "
                "(hostname, record_type, value, ttl, expires_at, source) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (hostname, record_type, value, ttl, expires_at, source),
            )
            self._conn.commit()

    def get_dns(self, hostname: str, record_type: str) -> list[dict[str, Any]]:
        hostname = validate_hostname(hostname)
        with self._lock:
            cur = self._conn.execute(
                "SELECT value, ttl, expires_at, source FROM dns_cache "
                "WHERE hostname=? AND record_type=?",
                (hostname, record_type),
            )
            rows = cur.fetchall()
        now = self.now_ts()
        result = []
        for value, ttl, expires_at, source in rows:
            result.append({
                "value": value,
                "ttl": ttl,
                "expires_at": expires_at,
                "source": source,
                "fresh": now < expires_at,
            })
        return result

    def dns_status(self, hostname: str, record_type: str) -> str:
        """Return 'fresh' | 'stale' | 'expired' | 'absent'."""
        rows = self.get_dns(hostname, record_type)
        if not rows:
            return "absent"
        if all(r["fresh"] for r in rows):
            return "fresh"
        if any(r["fresh"] for r in rows):
            return "stale"
        return "expired"

    # --- TLS cache ---
    def put_tls(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tls_cache "
                "(hostname, ip, sni, issuer, valid_from, valid_to, tls_version, cipher, san, latency_ms, success, probed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.get("hostname"),
                    record.get("ip"),
                    record.get("sni"),
                    record.get("issuer"),
                    str(record.get("valid_from")) if record.get("valid_from") else None,
                    str(record.get("valid_to")) if record.get("valid_to") else None,
                    record.get("tls_version"),
                    record.get("cipher"),
                    ",".join(record.get("san_list", [])),
                    record.get("latency_ms"),
                    1 if record.get("success") else 0,
                    self.now_ts(),
                ),
            )
            self._conn.commit()

    def get_tls(self, hostname: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT hostname, ip, sni, issuer, valid_from, valid_to, tls_version, cipher, san, latency_ms, success "
                "FROM tls_cache WHERE hostname=?",
                (validate_hostname(hostname),),
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    # --- Probe cache ---
    def put_probe(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO probe_cache "
                "(host, icmp_reachable, icmp_latency, tcp_reachable, tcp_latency, tls_reachable, tls_latency, probed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    validate_hostname(record["host"]),
                    1 if record.get("icmp", {}).get("reachable") else 0,
                    record.get("icmp", {}).get("latency_ms"),
                    1 if record.get("tcp443", {}).get("reachable") else 0,
                    record.get("tcp443", {}).get("latency_ms"),
                    1 if record.get("tls", {}).get("reachable") else 0,
                    record.get("tls", {}).get("latency_ms"),
                    self.now_ts(),
                ),
            )
            self._conn.commit()

    def get_probe(self, host: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM probe_cache WHERE host=?", (validate_hostname(host),)
            )
            cols = [d[0] for d in cur.description]
            row = cur.fetchone()
            return dict(zip(cols, row)) if row else None

    # --- maintenance ---
    def cleanup_expired(self) -> int:
        """Delete expired DNS rows.  Returns number removed."""
        now = self.now_ts()
        with self._lock:
            cur = self._conn.execute("DELETE FROM dns_cache WHERE expires_at < ?", (now,))
            self._conn.commit()
            return cur.rowcount


class CacheSet(dict):
    """Mapping of cache name -> CacheDB usable as a context manager.

    ``with open_caches(...) as caches:`` closes every database on exit, so
    SQLite handles are never leaked (no ResourceWarnings).
    """

    def __enter__(self) -> "CacheSet":
        return self

    def __exit__(self, *exc: Any) -> None:
        for db in self.values():
            try:
                db.close()
            except Exception:
                pass


def open_caches(data_dir: str | Path = "data/cache") -> CacheSet:
    """Open all three cache databases and return a mapping.

    Use as a context manager so connections are guaranteed to be closed::
        with open_caches() as caches: ...
    """
    base = Path(data_dir)
    return CacheSet({
        "dns": CacheDB("dns", base / "dns.sqlite"),
        "tls": CacheDB("tls", base / "tls.sqlite"),
        "probes": CacheDB("probes", base / "probes.sqlite"),
    })
