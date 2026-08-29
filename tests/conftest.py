"""Shared fixtures for offline testing."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def dns_records():
    with open(FIXTURES / "dns_records.json") as f:
        return json.load(f)


@pytest.fixture
def tls_metadata():
    with open(FIXTURES / "tls_metadata.json") as f:
        return json.load(f)


@pytest.fixture
def cloudflare_ipv4s():
    with open(Path("data/cdn/cloudflare-v4.json")) as f:
        return json.load(f)
