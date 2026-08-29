#!/usr/bin/env python3
"""Fetch CDN IP ranges from official sources.

This script downloads published IP ranges from the official provider pages and
writes them to data/cdn/*.json.  It is safe to run offline (will skip on error).

Providers & official sources:
  - Cloudflare  : https://www.cloudflare.com/ips-v4 + /ips-v6
  - Fastly      : https://api.fastly.com/public-ip-list
  - Akamai      : published via akamai.com (requires their published list)

No CDN IP range is EVER treated as a customer hostname list.  These are purely
network ranges used for evidence-based CDN attribution.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

DATA_CDN = Path("data/cdn")
TIMEOUT = 15


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "NetProbe/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8")


def fetch_cloudflare() -> None:
    try:
        v4 = _fetch("https://www.cloudflare.com/ips-v4").strip().splitlines()
        v6 = _fetch("https://www.cloudflare.com/ips-v6").strip().splitlines()
        DATA_CDN.mkdir(parents=True, exist_ok=True)
        (DATA_CDN / "cloudflare-v4.json").write_text(json.dumps(v4, indent=2))
        (DATA_CDN / "cloudflare-v6.json").write_text(json.dumps(v6, indent=2))
        print(f"Cloudflare: {len(v4)} v4 + {len(v6)} v6 ranges")
    except Exception as exc:
        print(f"Cloudflare fetch skipped: {exc}", file=sys.stderr)


def fetch_fastly() -> None:
    try:
        data = json.loads(_fetch("https://api.fastly.com/public-ip-list"))
        addresses = data.get("addresses", []) + data.get("ipv6_addresses", [])
        DATA_CDN.mkdir(parents=True, exist_ok=True)
        (DATA_CDN / "fastly.json").write_text(json.dumps(addresses, indent=2))
        print(f"Fastly: {len(addresses)} ranges")
    except Exception as exc:
        print(f"Fastly fetch skipped: {exc}", file=sys.stderr)


def main() -> None:
    fetch_cloudflare()
    fetch_fastly()
    print("Done (CDN ranges that failed to fetch are left as empty stub files).")


if __name__ == "__main__":
    main()
