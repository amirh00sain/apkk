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
import os
import platform
import shutil
import stat
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

XRAY_VERSION = "2.6.24"
GITHUB_API = "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v" + XRAY_VERSION

_ASSET_MAP: dict[tuple[str, str], str] = {
    ("linux",  "amd64"): "Xray-linux-64.zip",
    ("linux",  "arm64"): "Xray-linux-arm64-v8a.zip",
    ("darwin", "amd64"): "Xray-macos-arm64.zip",
    ("darwin", "arm64"): "Xray-macos-arm64.zip",
    ("windows","amd64"): "Xray-windows-64.zip",
    ("android","arm64"): "Xray-linux-arm64-v8a.zip",
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


def _download_json(url: str) -> dict:
    req = Request(url, headers={"Accept": "application/vnd.github+json"})
    with urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read())


def _download_asset(url: str) -> bytes:
    req = Request(url, headers={
        "Accept": "application/octet-stream",
        "Authorization": "token " + os.environ.get("GITHUB_TOKEN", ""),
    })
    with urlopen(req, timeout=120) as resp:  # noqa: S310
        return resp.read()


def fetch(output_dir: str = "bin") -> str:
    """Download xray and return the path to the extracted binary."""
    system, arch = _detect_platform()
    asset_name = _ASSET_MAP.get((system, arch))
    if not asset_name:
        print(f"[fetch_xray] Unsupported platform: {system}/{arch}", file=sys.stderr)
        sys.exit(1)

    print(f"[fetch_xray] Fetching xray {XRAY_VERSION} for {system}/{arch} …")
    try:
        info = _download_json(GITHUB_API)
    except URLError as exc:
        print(f"[fetch_xray] Failed to reach GitHub API: {exc}", file=sys.stderr)
        sys.exit(1)

    download_url = None
    for asset in info.get("assets", []):
        if asset["name"] == asset_name:
            download_url = asset["browser_download_url"]
            break

    if not download_url:
        print(f"[fetch_xray] Asset {asset_name} not found in release v{XRAY_VERSION}", file=sys.stderr)
        sys.exit(1)

    raw = _download_asset(download_url)
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
