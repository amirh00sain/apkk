"""Application configuration loading, validation, and profiles."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.errors import AppError, ErrorCollector
from app.security import (
    ValidationError,
    validate_hostname,
    validate_json,
    validate_path,
)

DEFAULT_CONFIG_DIR = Path("config")
DEFAULT_DATA_DIR = Path("data")

APP_SCHEMA_DEFAULTS: dict[str, Any] = {
    "mode": "lab",
    "tun": {"enabled": False, "mtu": 1500, "name": "tun0"},
    "dns": {
        "provider": "cloudflare",
        "doh": True,
        "timeout_ms": 6000,
        "cache_enabled": True,
    },
    "private_block": True,
    "cdn_detection": True,
    "xray": {"enabled": False, "binary": "xray", "config_path": "config/xray.json"},
    "profiles": ["baseline"],
    "resource_limits": {
        "max_concurrent_probes": 50,
        "max_dns_cache": 10000,
        "connection_timeout": 5.0,
        "tls_timeout": 8.0,
        "process_timeout": 30.0,
    },
}


class AppConfig:
    """Validated application configuration."""

    def __init__(self, data: dict[str, Any], config_dir: Path, data_dir: Path):
        self.raw = data
        self.config_dir = config_dir
        self.data_dir = data_dir

    # --- nested getters ---
    @property
    def mode(self) -> str:
        return self.raw.get("mode", APP_SCHEMA_DEFAULTS["mode"])

    @property
    def tun(self) -> dict[str, Any]:
        return {**APP_SCHEMA_DEFAULTS["tun"], **self.raw.get("tun", {})}

    @property
    def dns(self) -> dict[str, Any]:
        return {**APP_SCHEMA_DEFAULTS["dns"], **self.raw.get("dns", {})}

    @property
    def xray(self) -> dict[str, Any]:
        return {**APP_SCHEMA_DEFAULTS["xray"], **self.raw.get("xray", {})}

    @property
    def resource_limits(self) -> dict[str, Any]:
        return {**APP_SCHEMA_DEFAULTS["resource_limits"], **self.raw.get("resource_limits", {})}

    @property
    def private_block(self) -> bool:
        return bool(self.raw.get("private_block", True))

    @property
    def cdn_detection(self) -> bool:
        return bool(self.raw.get("cdn_detection", True))

    @property
    def profiles(self) -> list[str]:
        return self.raw.get("profiles", ["baseline"])

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)


@lru_cache(maxsize=8)
def load_config(config_dir: str | Path = DEFAULT_CONFIG_DIR) -> AppConfig:
    """Load and merge app.json with schema defaults.  Cached per config_dir."""
    cfg_dir = Path(config_dir)
    path = cfg_dir / "app.json"
    if not path.exists():
        # Use defaults silently when no config present (e.g. tests).  This is a
        # safe default, not an inferred value about the network.
        return AppConfig(dict(APP_SCHEMA_DEFAULTS), cfg_dir, DEFAULT_DATA_DIR)
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    merged = {**APP_SCHEMA_DEFAULTS, **raw}
    return AppConfig(merged, cfg_dir, DEFAULT_DATA_DIR)


def validate_config_app(cfg: AppConfig) -> ErrorCollector:
    """Validate the app-level configuration (schema + filesystem)."""
    ec = ErrorCollector()
    try:
        validate_json(cfg.raw)
    except ValidationError as e:
        ec.add(e.category, e.message, e.cause, e.recovery)

    allowed_modes = {"lab", "research", "production"}
    if cfg.mode not in allowed_modes:
        ec.add(
            "config",
            f"unknown mode: {cfg.mode!r}",
            recovery=f"use one of {sorted(allowed_modes)}",
        )

    if cfg.tun.get("enabled") and not isinstance(cfg.tun.get("mtu", 1500), int):
        ec.add("config", "tun.mtu must be an integer", recovery="set tun.mtu to e.g. 1500")

    # dns provider whitelist — provider-specific endpoints live in config/dns.json
    known_dns = {"cloudflare", "google", "quad9", "custom"}
    if cfg.dns.get("provider") not in known_dns:
        ec.add(
            "config",
            f"unsupported dns.provider: {cfg.dns.get('provider')!r}",
            recovery=f"use one of {sorted(known_dns)}",
        )
    return ec


def load_dns_providers(config_dir: str | Path = DEFAULT_CONFIG_DIR) -> dict[str, Any]:
    """Load DoH provider endpoints from config/dns.json."""
    path = Path(config_dir) / "dns.json"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_blocklist(config_dir: str | Path = DEFAULT_CONFIG_DIR) -> list[str]:
    """Load user blocklist CIDRs from config/blocklist.json."""
    path = Path(config_dir) / "blocklist.json"
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    cidrs = data.get("cidrs", []) if isinstance(data, dict) else []
    # Validate each CIDR eagerly; raise on bad input (fail fast, not silent).
    for c in cidrs:
        try:
            from app.security import validate_cidr
            validate_cidr(c)
        except ValidationError as e:
            raise AppError("config", f"invalid blocklist CIDR: {c}", e.message) from e
    return cidrs


def load_profiles(config_dir: str | Path = DEFAULT_CONFIG_DIR) -> dict[str, Any]:
    """Load profile definitions from config/profiles.json."""
    path = Path(config_dir) / "profiles.json"
    if not path.exists():
        from app.profiles import DEFAULT_PROFILES
        return dict(DEFAULT_PROFILES)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_hostname_safe(hostname: str) -> str:
    """Public helper for CLI entry points."""
    return validate_hostname(hostname)
