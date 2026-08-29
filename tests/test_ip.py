"""IP / private-range validation tests."""

import ipaddress

import pytest

from app.security import (
    is_private_ip,
    is_blocked,
    validate_ip,
    validate_cidr,
    validate_hostname,
    validate_port,
    build_block_networks,
    ValidationError,
)


class TestValidation:
    def test_validate_hostname_ok(self):
        assert validate_hostname("Example.COM") == "example.com"
        assert validate_hostname("sub.example.com") == "sub.example.com"

    def test_validate_hostname_bad(self):
        with pytest.raises(ValidationError):
            validate_hostname("not a host!")
        with pytest.raises(ValidationError):
            validate_hostname("")

    def test_validate_ip(self):
        assert validate_ip("192.168.1.1")
        with pytest.raises(ValidationError):
            validate_ip("999.1.1.1")

    def test_validate_cidr(self):
        net = validate_cidr("10.0.0.0/8")
        assert net.prefixlen == 8
        # 10.0.0.0 without prefix is accepted by ip_network (becomes /32)
        net2 = validate_cidr("10.0.0.0")
        assert net2.prefixlen == 32
        with pytest.raises(ValidationError):
            validate_cidr("not-a-cidr!!!")

    def test_validate_port(self):
        assert validate_port(443) == 443
        with pytest.raises(ValidationError):
            validate_port(70000)


class TestPrivateIP:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1",
        "169.254.1.1", "100.64.0.1", "fc00::1", "fe80::1", "::1",
    ])
    def test_is_private(self, ip):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700::1"])
    def test_is_public(self, ip):
        assert is_private_ip(ip) is False


class TestBlocklist:
    def test_custom_blocklist(self):
        nets = build_block_networks(["10.10.34.0/24"])
        assert is_blocked("10.10.34.5", nets) is True
        assert is_blocked("8.8.8.8", nets) is False

    def test_ipv6_blocklist(self):
        nets = build_block_networks(["2001:4188:2:600::/64"])
        assert is_blocked("2001:4188:2:600::1", nets) is True
