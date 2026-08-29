"""DNS resolution with dual backends (dig CLI + dnspython).

Provides `DigResolver`, `DnspythonResolver`, and a convenience `resolve_dns()`.
Results are returned as `app.models.DNSResult`.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from typing import Protocol

import dns.rdatatype
import dns.resolver

from app.models import DNSResult
from app.security import safe_subprocess_args, validate_hostname


class DNSResolverBackend(Protocol):
    """Interface every DNS backend must satisfy."""

    def resolve(self, hostname: str, record_type: str = "A") -> DNSResult: ...

    async def aresolve(self, hostname: str, record_type: str = "A") -> DNSResult: ...


# ---------------------------------------------------------------------------
# Dig (system CLI) backend
# ---------------------------------------------------------------------------

class DigResolver:
    """Resolve via the ``dig`` command if available on the system."""

    name = "dig"

    def resolve(self, hostname: str, record_type: str = "A") -> DNSResult:
        hostname = validate_hostname(hostname)
        start = time.monotonic()
        args = safe_subprocess_args([
            "dig", "+nocmd", "+noall", "+answer", "+json",
            hostname, record_type,
        ])
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            # dig not installed — return an empty result (graceful degradation).
            result = DNSResult(hostname=hostname, latency_ms=None, source="dig", error="dig binary not found")
            return result
        except subprocess.TimeoutExpired:
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            result = DNSResult(hostname=hostname, latency_ms=elapsed_ms, source="dig", error="dig timed out after 10 s")
            return result

        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        result = DNSResult(hostname=hostname, latency_ms=elapsed_ms, source="dig")

        if proc.returncode != 0:
            # dig returns 1 on NXDOMAIN or SERVFAIL; treat as empty result.
            return result

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return result

        answer_section = data.get("answer", [])
        for rr in answer_section:
            rt = rr.get("type", "")
            val = rr.get("data", "")
            ttl = rr.get("TTL", 0)
            if rt == "A":
                result.a.append(val)
            elif rt == "AAAA":
                result.aaaa.append(val)
            elif rt == "CNAME":
                result.cname.append(val)
            elif rt == "TXT":
                # dig JSON keeps surrounding quotes for TXT records; strip them.
                result.txt.append(val.strip('"'))
            if ttl and (result.ttl is None or ttl < result.ttl):
                result.ttl = ttl
        return result

    async def aresolve(self, hostname: str, record_type: str = "A") -> DNSResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.resolve, hostname, record_type)


# ---------------------------------------------------------------------------
# dnspython backend
# ---------------------------------------------------------------------------

class DnspythonResolver:
    """Resolve via the ``dnspython`` library (pure Python, no CLI needed)."""

    name = "dnspython"

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 6.0):
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._timeout = timeout

    def resolve(self, hostname: str, record_type: str = "A") -> DNSResult:
        hostname = validate_hostname(hostname)
        start = time.monotonic()
        result = DNSResult(hostname=hostname, source="dnspython")
        try:
            answer = self._resolver.resolve(hostname, record_type, lifetime=self._timeout)
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            result.latency_ms = elapsed_ms

            for rdata in answer:
                val = str(rdata).strip('"')
                # dnspython 2.8+ uses an IntEnum for rdtype; str() yields the
                # numeric value ("1" for A) on Python 3.11+, so map it by name.
                rname = dns.rdatatype.to_text(rdata.rdtype)
                if rname == "A":
                    result.a.append(val)
                elif rname == "AAAA":
                    result.aaaa.append(val)
                elif rname == "CNAME":
                    result.cname.append(val)
                elif rname == "TXT":
                    result.txt.append(val)

            if answer.rrset and answer.rrset.ttl:
                result.ttl = answer.rrset.ttl
        except dns.resolver.NXDOMAIN:
            result.latency_ms = round((time.monotonic() - start) * 1000, 1)
        except dns.resolver.NoAnswer:
            result.latency_ms = round((time.monotonic() - start) * 1000, 1)
        except dns.resolver.Timeout:
            result.latency_ms = round((time.monotonic() - start) * 1000, 1)
        except Exception:
            result.latency_ms = round((time.monotonic() - start) * 1000, 1)
        return result

    async def aresolve(self, hostname: str, record_type: str = "A") -> DNSResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.resolve, hostname, record_type)


# ---------------------------------------------------------------------------
# Convenience resolver
# ---------------------------------------------------------------------------

_resolver_backend: DNSResolverBackend | None = None


def _get_default_backend() -> DNSResolverBackend:
    global _resolver_backend
    if _resolver_backend is not None:
        return _resolver_backend
    # Prefer dig if available, else fall back to dnspython.
    import shutil
    if shutil.which("dig"):
        _resolver_backend = DigResolver()
    else:
        _resolver_backend = DnspythonResolver()
    return _resolver_backend


def resolve_dns(
    hostname: str,
    record_type: str = "A",
    *,
    backend: str | None = None,
) -> DNSResult:
    """High-level resolve that picks a backend automatically unless overridden.

    backend: "dig" | "dnspython" | None (auto-detect)
    """
    global _resolver_backend
    if backend == "dig":
        _resolver_backend = DigResolver()
    elif backend == "dnspython":
        _resolver_backend = DnspythonResolver()
    return _get_default_backend().resolve(hostname, record_type)


async def resolve_dns_a_and_aaaa(hostname: str, *, backend: str | None = None) -> DNSResult:
    """Resolve both A and AAAA in parallel and merge into one DNSResult."""
    r = _get_default_backend()
    a_result, aaaa_result = await asyncio.gather(
        r.aresolve(hostname, "A"),
        r.aresolve(hostname, "AAAA"),
    )
    # Merge into a single result.
    merged = DNSResult(
        hostname=hostname,
        a=a_result.a,
        aaaa=aaaa_result.aaaa,
        cname=list(dict.fromkeys(a_result.cname + aaaa_result.cname)),
        txt=list(dict.fromkeys(a_result.txt + aaaa_result.txt)),
        latency_ms=round(
            sum(x for x in (a_result.latency_ms, aaaa_result.latency_ms) if x is not None) / max(1, sum(1 for x in (a_result.latency_ms, aaaa_result.latency_ms) if x is not None)),
            1,
        ),
        ttl=a_result.ttl or aaaa_result.ttl,
        source=r.name,
    )
    return merged
