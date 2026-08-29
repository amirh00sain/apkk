"""SQLite cache tests — offline (uses temp files)."""

import tempfile
from pathlib import Path

from app.database import CacheDB, open_caches


def _tmp_db(kind):
    path = Path(tempfile.mktemp(suffix=".sqlite"))
    return CacheDB(kind, path)


def test_dns_put_get_fresh():
    db = _tmp_db("dns")
    db.put_dns("example.com", "A", "1.2.3.4", 300, "dnspython")
    rows = db.get_dns("example.com", "A")
    assert len(rows) == 1
    assert rows[0]["value"] == "1.2.3.4"
    assert rows[0]["fresh"] is True


def test_dns_expired():
    db = _tmp_db("dns")
    db.put_dns("example.com", "A", "1.2.3.4", -1, "dnspython")  # ttl negative => already expired
    status = db.dns_status("example.com", "A")
    assert status == "expired"


def test_dns_stale():
    # One fresh, one expired -> stale
    db = _tmp_db("dns")
    db.put_dns("example.com", "A", "1.2.3.4", 300, "dnspython")
    db.put_dns("example.com", "A", "5.6.7.8", -1, "dnspython")
    assert db.dns_status("example.com", "A") == "stale"


def test_dns_absent():
    db = _tmp_db("dns")
    assert db.dns_status("nope.com", "A") == "absent"


def test_cleanup_expired():
    db = _tmp_db("dns")
    db.put_dns("a.com", "A", "1.1.1.1", 300, "x")
    db.put_dns("b.com", "A", "2.2.2.2", -1, "x")
    removed = db.cleanup_expired()
    assert removed >= 1


def test_tls_put_get():
    db = _tmp_db("tls")
    db.put_tls({"hostname": "example.com", "ip": "1.2.3.4", "sni": "example.com",
                "success": True, "latency_ms": 10.0, "san_list": ["example.com"]})
    rows = db.get_tls("example.com")
    assert len(rows) == 1
    assert rows[0]["ip"] == "1.2.3.4"


def test_probe_put_get():
    db = _tmp_db("probes")
    db.put_probe({"host": "example.com", "icmp": {"reachable": True, "latency_ms": 5.0},
                  "tcp443": {"reachable": True, "latency_ms": 10.0},
                  "tls": {"reachable": True, "latency_ms": 12.0}})
    row = db.get_probe("example.com")
    assert row is not None
    assert row["icmp_reachable"] == 1
    assert row["tcp_latency"] == 10.0


def test_open_caches():
    base = Path(tempfile.mkdtemp()) / "cache"
    caches = open_caches(base)
    assert set(caches.keys()) == {"dns", "tls", "probes"}
    caches["dns"].put_dns("x.com", "A", "9.9.9.9", 60, "x")
    assert caches["dns"].get_dns("x.com", "A")[0]["value"] == "9.9.9.9"
