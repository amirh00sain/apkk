"""Xray-core binary detection and version check."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.security import safe_subprocess_args, validate_path


def find_xray(binary: str = "xray") -> str | None:
    """Return a path to the xray binary if found, else None.

    Resolves in this order:
    1. via ``shutil.which`` (a name on ``PATH``);
    2. as an explicit file path (absolute or relative to CWD) that exists and
       is executable.
    """
    found = shutil.which(binary)
    if found:
        return found
    # Fall back to treating the value as a literal (relative/absolute) path.
    candidate = Path(binary)
    if candidate.is_absolute() or binary.startswith((".", "/")):
        try:
            p = validate_path(str(candidate), must_exist=True, must_be_file=True)
            if os.access(p, os.X_OK):
                return str(p)
        except Exception:
            return None
    return None


def get_version(binary: str = "xray") -> str | None:
    """Return the version string of the xray binary."""
    path = find_xray(binary)
    if not path:
        return None
    args = safe_subprocess_args([path, "version"])
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return proc.stdout.strip().splitlines()[0] if proc.stdout else None
    except Exception:
        return None


def validate_binary(binary: str = "xray") -> dict[str, Any]:
    """Check that xray exists and report version."""
    path = find_xray(binary)
    if not path:
        return {"ok": False, "error": f"xray binary not found: {binary}", "binary": binary}
    version = get_version(binary)
    return {"ok": True, "path": path, "version": version}
