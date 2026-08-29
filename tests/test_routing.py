"""Routing engine tests — offline."""

import pytest

from app.cdn_detect import CDNMatch
from app.route_engine import RouteEngine
from app.models import RouteAction
from app.security import build_block_networks


class TestRouteEngine:
    def test_blocked_by_user_blocklist(self):
        nets = build_block_networks(["10.10.34.0/24"])
        eng = RouteEngine(block_networks=nets)
        decision = eng.decide("example.com", "10.10.34.5", private_block=True)
        assert decision.action == RouteAction.BLOCKED

    def test_local_loopback(self):
        eng = RouteEngine()
        d = eng.decide("localhost", "127.0.0.1")
        assert d.action == RouteAction.LOCAL

    def test_private(self):
        eng = RouteEngine()
        d = eng.decide("host", "192.168.1.1")
        assert d.action == RouteAction.PRIVATE

    def test_cdn_action(self):
        eng = RouteEngine()
        cdn = CDNMatch(provider="Cloudflare", confidence=0.95, evidence=["ipv4_range:x"])
        d = eng.decide("example.com", "104.16.0.1", cdn_match=cdn)
        assert d.action == RouteAction.CDN
        assert d.provider == "Cloudflare"

    def test_unknown_does_not_overclaim(self):
        eng = RouteEngine()
        # Use a clearly public, non-reserved IP (not documentation range).
        d = eng.decide("example.com", "93.184.216.34")
        assert d.action == RouteAction.UNKNOWN
        assert "inferred" in d.reason.lower() or "generic" in d.reason.lower()

    def test_cdn_below_threshold_is_unknown(self):
        eng = RouteEngine(cdn_confidence_threshold=0.9)
        cdn = CDNMatch(provider="Cloudflare", confidence=0.25, evidence=["cname:x"])
        d = eng.decide("example.com", "203.0.113.10", cdn_match=cdn)
        assert d.action != RouteAction.CDN
