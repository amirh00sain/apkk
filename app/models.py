"""Pydantic data models for the entire project."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RecordStatus(str, Enum):
    OBSERVED = "observed"
    RESOLVED = "resolved"
    PROVIDER_DETECTED = "provider_detected"
    TLS_VERIFIED = "tls_verified"
    FRESH = "fresh"
    STALE = "stale"
    FAILED = "failed"


class RouteAction(str, Enum):
    PRIVATE = "private"
    LOCAL = "local"
    DIRECT = "direct"
    CDN = "cdn"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class HealthLevel(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# DNS Result
# ---------------------------------------------------------------------------

class DNSResult(BaseModel):
    hostname: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    ttl: int | None = None
    source: str = "unknown"
    error: str | None = None
    queried_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("hostname")
    @classmethod
    def _strip_hostname(cls, v: str) -> str:
        return v.strip().lower()


# ---------------------------------------------------------------------------
# TLS Result
# ---------------------------------------------------------------------------

class TLSResult(BaseModel):
    hostname: str
    ip: str
    port: int = 443
    tls_version: str | None = None
    cipher: str | None = None
    sni: str | None = None
    san_list: list[str] = Field(default_factory=list)
    issuer: str | None = None
    subject: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    alpn: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    certificate_der: bytes | None = None
    tls_valid: bool = False
    success: bool = False
    error: str | None = None
    probed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Probe Result
# ---------------------------------------------------------------------------

class ProbeTarget(BaseModel):
    host: str
    port: int = 443


class ProbeResult(BaseModel):
    host: str
    icmp: dict[str, Any] = Field(default_factory=dict)
    tcp443: dict[str, Any] = Field(default_factory=dict)
    tls: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# CDN Provider
# ---------------------------------------------------------------------------

class CDNProvider(BaseModel):
    name: str
    ipv4_ranges: list[str] = Field(default_factory=list)
    ipv6_ranges: list[str] = Field(default_factory=list)
    known_cnames: list[str] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)
    last_updated: datetime | None = None


class CDNMatch(BaseModel):
    provider: str | None = None
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    cnames_matched: list[str] = Field(default_factory=list)
    ips_matched: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoint Record
# ---------------------------------------------------------------------------

class EndpointRecord(BaseModel):
    hostname: str
    provider: str | None = None
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    tls_valid: bool = False
    certificate_names: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: datetime | None = None
    source: list[str] = Field(default_factory=list)
    status: RecordStatus = RecordStatus.OBSERVED


# ---------------------------------------------------------------------------
# Route Decision
# ---------------------------------------------------------------------------

class RouteDecision(BaseModel):
    hostname: str
    destination_ip: str
    action: RouteAction
    provider: str | None = None
    reason: str = ""
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# Health Score
# ---------------------------------------------------------------------------

class HealthScore(BaseModel):
    hostname: str
    level: HealthLevel = HealthLevel.FAILED
    dns_ok: bool = False
    tcp_ok: bool = False
    tls_ok: bool = False
    latency_ms: float | None = None
    failure_rate: float = 1.0
    score: float = 0.0  # 0.0 - 1.0


# ---------------------------------------------------------------------------
# Structured Log Entry
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event: str
    hostname: str | None = None
    ip: str | None = None
    latency_ms: float | None = None
    success: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
