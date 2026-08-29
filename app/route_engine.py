"""Route engine — classify destinations and decide a routing action.

Actions: PRIVATE, LOCAL, DIRECT, CDN, UNKNOWN, BLOCKED.

The engine combines:
  - private/reserved blocklist (always applies first)
  - user custom blocklist (config/blocklist.json)
  - CDN detection result
  - DNS reachability
"""

from __future__ import annotations

import ipaddress
from typing import Any

from app.cdn_detect import CDNMatch
from app.models import RouteAction, RouteDecision
from app.security import is_blocked, validate_ip, PRIVATE_NETWORKS


class RouteEngine:
    """Decide how traffic to a destination should be handled."""

    def __init__(
        self,
        block_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
        cdn_confidence_threshold: float = 0.5,
    ):
        # Custom user blocklist only — NOT the built-in private ranges (those
        # get their own dedicated classification below).
        self.block_networks = block_networks or []
        self.cdn_threshold = cdn_confidence_threshold

    def decide(
        self,
        hostname: str,
        destination_ip: str,
        *,
        cdn_match: CDNMatch | None = None,
        private_block: bool = True,
    ) -> RouteDecision:
        addr = validate_ip(destination_ip)

        # 1. User custom blocklist — checked FIRST (only explicit CIDRs).
        if private_block and self.block_networks and is_blocked(destination_ip, self.block_networks):
            return RouteDecision(
                hostname=hostname,
                destination_ip=destination_ip,
                action=RouteAction.BLOCKED,
                reason="IP within user blocklist",
            )

        # 2. Built-in private/reserved classification (always applied).
        if addr.is_loopback:
            return RouteDecision(
                hostname=hostname, destination_ip=destination_ip,
                action=RouteAction.LOCAL, reason="loopback address",
            )
        if addr.is_link_local:
            return RouteDecision(
                hostname=hostname, destination_ip=destination_ip,
                action=RouteAction.LOCAL, reason="link-local address",
            )
        if addr.is_private:
            return RouteDecision(
                hostname=hostname, destination_ip=destination_ip,
                action=RouteAction.PRIVATE, reason="private address",
            )

        # 2. CDN classification.
        if cdn_match and cdn_match.provider and cdn_match.confidence >= self.cdn_threshold:
            return RouteDecision(
                hostname=hostname,
                destination_ip=destination_ip,
                action=RouteAction.CDN,
                provider=cdn_match.provider,
                confidence=cdn_match.confidence,
                reason=f"CDN provider detected: {cdn_match.provider} "
                       f"(confidence {cdn_match.confidence})",
            )

        # 3. Unknown — do not overclaim.
        return RouteDecision(
            hostname=hostname,
            destination_ip=destination_ip,
            action=RouteAction.UNKNOWN,
            confidence=0.0,
            reason="no CDN evidence; classified as generic direct/wildcard (inferred)",
        )
