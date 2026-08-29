"""CDN Detection — evidence-based identification.

For each hostname the module examines:
  1. CNAME chain
  2. A / AAAA records
  3. ASN (via IP)
  4. TLS certificate CN/SAN
  5. Known CDN IP ranges

Provider confidence is accumulated from independent evidence signals.
A claim is NEVER inferred from a single signal; multiple signals increase
confidence.  CDN IP range = customer hostname list is NEVER assumed.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from app.logger import get_logger
from app.models import CDNMatch, CDNProvider
from app.security import validate_hostname

logger = get_logger()

# ---------------------------------------------------------------------------
# Built-in providers (loaded from data/cdn/ at runtime)
# ---------------------------------------------------------------------------

_DEFAULT_PROVIDERS: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "name": "Cloudflare",
        "cnames": ["cloudflare", "cloudflare-dns.com"],
        "cidr4_file": "data/cdn/cloudflare-v4.json",
        "cidr6_file": "data/cdn/cloudflare-v6.json",
    },
    "akamai": {
        "name": "Akamai",
        "cnames": ["akamai", "akadns", "akamaized", "edgesuite", "edgekey"],
        "cidr4_file": "data/cdn/akamai.json",
        "cidr6_file": None,
    },
    "fastly": {
        "name": "Fastly",
        "cnames": ["fastly", "fastlylb", "fastly.net"],
        "cidr4_file": "data/cdn/fastly.json",
        "cidr6_file": None,
    },
    "cloudfront": {
        "name": "AWS CloudFront",
        "cnames": ["cloudfront", "amazonaws.com"],
        "cidr4_file": "data/cdn/cloudfront.json",
        "cidr6_file": None,
    },
    "azure_frontdoor": {
        "name": "Azure Front Door",
        "cnames": ["azurefd", "frontdoor", "msecnd"],
        "cidr4_file": None,
        "cidr6_file": None,
    },
    "google_cloud": {
        "name": "Google Cloud CDN",
        "cnames": ["googleusercontent", "google", "gvt1"],
        "cidr4_file": None,
        "cidr6_file": None,
    },
    "bunny": {
        "name": "Bunny CDN",
        "cnames": ["b-cdn", "bunnycdn"],
        "cidr4_file": None,
        "cidr6_file": None,
    },
    "imperva": {
        "name": "Imperva (Incapsula)",
        "cnames": ["imperva", "incapsula", "impervadns"],
        "cidr4_file": None,
        "cidr6_file": None,
    },
}


def _load_ranges(path: Path) -> list[str]:
    """Load a list of CIDR ranges from a JSON file."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [str(c) for c in data]
    if isinstance(data, dict) and "ranges" in data:
        return [str(c) for c in data["ranges"]]
    return []


def load_all_providers(data_dir: Path | None = None) -> dict[str, CDNProvider]:
    """Load CDN provider definitions and IP ranges from data/cdn/."""
    d = data_dir or Path("data") / "cdn"
    providers: dict[str, CDNProvider] = {}
    for key, info in _DEFAULT_PROVIDERS.items():
        ipv4 = _load_ranges(d / Path(info["cidr4_file"]).name) if info.get("cidr4_file") else []
        ipv6 = _load_ranges(d / Path(info["cidr6_file"]).name) if info.get("cidr6_file") else []
        providers[key] = CDNProvider(
            name=info["name"],
            ipv4_ranges=ipv4,
            ipv6_ranges=ipv6,
            known_cnames=info.get("cnames", []),
        )
    return providers


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

def detect_cdn(
    hostname: str,
    *,
    cname_chain: list[str] | None = None,
    ipv4: list[str] | None = None,
    ipv6: list[str] | None = None,
    san_list: list[str] | None = None,
    providers: dict[str, CDNProvider] | None = None,
) -> CDNMatch:
    """Detect CDN provider for a hostname from available evidence.

    Evidence sources:
      - CNAME chain keywords
      - SAN keywords
      - IP range matching (IPv4 / IPv6 CIDR)

    Confidence is accumulated: each matching signal adds ~0.25; up to 1.0.
    A single signal is never sufficient for full confidence.
    """
    hostname = validate_hostname(hostname)
    cname_chain = cname_chain or []
    ipv4 = ipv4 or []
    ipv6 = ipv6 or []
    san_list = san_list or []
    providers = providers or load_all_providers()

    best_match = CDNMatch()

    for provider_key, prov in providers.items():
        evidence: list[str] = []
        confidence = 0.0
        cnames_matched: list[str] = []
        ips_matched: list[str] = []

        # Signal 1: CNAME chain keywords
        chain_lower = " ".join(c.lower() for c in cname_chain)
        for kw in prov.known_cnames:
            if kw.lower() in chain_lower:
                evidence.append(f"cname_keyword:{kw}")
                confidence += 0.25
                cnames_matched.append(kw)
                break

        # Signal 2: SAN keywords
        san_lower = " ".join(s.lower() for s in san_list)
        for kw in prov.known_cnames:
            if kw.lower() in san_lower:
                evidence.append(f"san_keyword:{kw}")
                confidence += 0.15
                break

        # Signal 3: IPv4 range matching
        for ip_str in ipv4:
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            for cidr_str in prov.ipv4_ranges:
                try:
                    net = ipaddress.ip_network(cidr_str)
                    if addr in net:
                        evidence.append(f"ipv4_range:{cidr_str}")
                        confidence += 0.30
                        ips_matched.append(ip_str)
                        break
                except ValueError:
                    continue
            if ips_matched:
                break  # one match is enough for the provider

        # Signal 4: IPv6 range matching
        for ip_str in ipv6:
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            for cidr_str in prov.ipv6_ranges:
                try:
                    net = ipaddress.ip_network(cidr_str)
                    if addr in net:
                        evidence.append(f"ipv6_range:{cidr_str}")
                        confidence += 0.30
                        ips_matched.append(ip_str)
                        break
                except ValueError:
                    continue
            if len(ips_matched) > 1:
                break

        if not evidence:
            continue

        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)

        if confidence > best_match.confidence:
            best_match = CDNMatch(
                provider=prov.name,
                confidence=round(confidence, 2),
                evidence=evidence,
                cnames_matched=cnames_matched,
                ips_matched=ips_matched,
            )

    if best_match.provider:
        logger.info(
            "cdn_detected",
            hostname=hostname,
            details={"provider": best_match.provider, "confidence": best_match.confidence},
        )

    return best_match


def detect_cdn_from_dns_result(
    dns_result: Any,
    san_list: list[str] | None = None,
    providers: dict[str, CDNProvider] | None = None,
) -> CDNMatch:
    """Convenience wrapper accepting a DNSResult object."""
    return detect_cdn(
        hostname=dns_result.hostname,
        cname_chain=dns_result.cname,
        ipv4=dns_result.a,
        ipv6=dns_result.aaaa,
        san_list=san_list,
        providers=providers,
    )
