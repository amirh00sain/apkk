#!/usr/bin/env python3
"""Download the correct xray-core binary for the current platform.

Usage:
    python scripts/fetch_xray.py          # downloads to bin/xray
    python scripts/fetch_xray.py -o /tmp  # downloads to /tmp/xray

The script selects the correct Xray release asset by OS and architecture
(linux/amd64, windows/amd64, android/arm64) from the latest release JSON.
"""

from __future__ import annotations

import argparse
import io
import json
import platform
import shutil
import stat
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

XRAY_VERSION = "26.3.27"

# Direct download URLs (no auth needed) keyed by (os, arch).
_ASSET_MAP: dict[tuple[str, str], str] = {
    ("linux",  "amd64"): f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-64.zip",
    ("linux",  "arm64"): f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-arm64-v8a.zip",
    ("darwin", "amd64"): f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-macos-arm64.zip",
    ("darwin", "arm64"): f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-macos-arm64.zip",
    ("windows","amd64"): f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-windows-64.zip",
    ("android","arm64"): f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-android-arm64-v8a.zip",
}


def _detect_platform() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "x64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = "amd64"
    return system, arch


def _download_asset(url: str) -> bytes:
    """Download a release asset.  GitHub release assets follow redirects."""
    req = Request(url, headers={"Accept": "application/octet-stream"})
    with urlopen(req, timeout=120) as resp:  # noqa: S310
        return resp.read()


def fetch(output_dir: str = "bin") -> str:
    """Download xray and return the path to the extracted binary."""
    system, arch = _detect_platform()
    download_url = _ASSET_MAP.get((system, arch))
    if not download_url:
        print(f"[fetch_xray] Unsupported platform: {system}/{arch}", file=sys.stderr)
        sys.exit(1)

    print(f"[fetch_xray] Fetching xray {XRAY_VERSION} for {system}/{arch} …")
    try:
        raw = _download_asset(download_url)
    except URLError as exc:
        print(f"[fetch_xray] Download failed ({download_url}): {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"[fetch_xray] Downloaded {len(raw):,} bytes — extracting …")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(str(out))

    binary_name = "xray.exe" if system == "windows" else "xray"
    binary_path = out / binary_name
    if not binary_path.exists():
        print(f"[fetch_xray] {binary_name} not found after extraction", file=sys.stderr)
        sys.exit(1)

    # Mark executable on Unix.
    if system != "windows":
        binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"[fetch_xray] Ready: {binary_path}")
    return str(binary_path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Download xray-core binary for this platform")
    ap.add_argument("-o", "--output", default="bin", help="Output directory (default: bin)")
    args = ap.parse_args()
    fetch(args.output)


if __name__ == "__main__":
    main()
