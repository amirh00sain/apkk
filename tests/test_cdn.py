"""CDN detection tests — offline."""

import pytest

from app.cdn_detect import detect_cdn, CDNMatch, load_all_providers


class TestCDNDetection:
    def test_cloudflare_by_ip_range(self):
        match = detect_cdn(
            "example.com",
            ipv4=["104.16.0.1"],  # Cloudflare range
        )
        assert match.provider == "Cloudflare"
        assert match.confidence > 0
        assert any("ipv4_range" in e for e in match.evidence)

    def test_no_match(self):
        match = detect_cdn("example.com", ipv4=["203.0.113.5"])
        assert match.provider is None

    def test_akamai_by_cname(self):
        match = detect_cdn(
            "example.com",
            cname_chain=["e1234.akadns.net"],
        )
        assert match.provider == "Akamai"
        assert match.confidence > 0

    def test_fastly_by_cname(self):
        match = detect_cdn(
            "example.com",
            cname_chain=["foo.fastlylb.net"],
        )
        assert match.provider == "Fastly"

    def test_single_signal_not_full_confidence(self):
        match = detect_cdn("example.com", cname_chain=["x.cloudflare.com"])
        # CNAME signal alone should be < 1.0
        assert match.confidence < 1.0

    def test_cloudfront_by_cname(self):
        match = detect_cdn("example.com", cname_chain=["d123.cloudfront.net"])
        assert match.provider == "AWS CloudFront"

    def test_load_providers(self):
        providers = load_all_providers()
        assert "cloudflare" in providers
        assert providers["cloudflare"].ipv4_ranges  # cloudflare-v4.json
