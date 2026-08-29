# NetProbe — Network Traffic Analysis & CDN/TLS Inspection Toolkit

`NetProbe` is a modular, Python-based framework for **analyzing and measuring
network traffic** in a controlled environment (a network or lab you are
authorized to test). It performs DNS inspection, TLS certificate/SNI
telemetry, CDN provider attribution, reachability probing, traffic
classification, and Xray-core integration as a transport backend.

> **Scope & honesty.** This tool is for **analysis, measurement, validation,
> and telemetry** of traffic. It does **not** claim to "open all sites" or
> "bypass DPI." Where a value is only inferred (not directly observed), output
> is explicitly labelled `inferred`. The tool never fabricates SNI or maps a
> target to an unrelated identity; any SNI/certificate mismatch is reported as
> `MISMATCH` and used only in offline research fixtures.

---

## Features

- **Platform abstraction** — Windows (`WinDivert`), Linux (`TUN`), and
  Offline (`PCAP`) backends behind a single `PacketBackend` interface.
- **DNS engine** — `dig` and pure-Python `dnspython` backends; A/AAAA/CNAME/TXT.
  Configurable DoH (Cloudflare / Google / Quad9 / custom).
- **TLS inspection** — real handshake, certificate SAN/CN, issuer, validity,
  version, cipher, ALPN; SNI↔cert consistency check.
- **CDN detection** — evidence-based attribution (CNAME, SAN, IP-range match)
  for Cloudflare, Akamai, Fastly, CloudFront, Azure, Google, Bunny, Imperva.
- **Reachability probing** — ICMP / TCP-443 / TLS with pass/fail separation
  (ICMP block ≠ host down).
- **Routing engine** — classifies destinations as `DIRECT / CDN / PRIVATE /
  LOCAL / BLOCKED / UNKNOWN`.
- **Health & metrics** — per-endpoint health scoring, latency/jitter/packet-loss.
- **Xray-core integration** — JSON config generation, process lifecycle,
  health checks, crash diagnosis, auto-restart with backoff.
- **Structured JSON logging**, **Rich dashboard**, full **pytest** suite with
  **offline fixtures** (no real network required).
- **Cross-platform GUI (Flet)** — a single centered **Connect** button that
  establishes a **TUN-mode** tunnel using **DoH + TLS-Fragment + (optional
  Tor)**.  Builds as **Linux AppImage**, **Windows EXE**, and **Android APK**
  (real Kotlin `VpnService` for system-wide TUN on Android).
- **Security first** — all inputs validated; `subprocess` always uses
  `shell=False` with a fixed arg list; no raw command strings; no `shell=True`.

---

## Installation

### Linux system prerequisites

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y python3.12 iproute2 iputils-ping bind9-dnsutils openssl xray-core

# Optional: fetch official CDN ranges
python scripts/fetch_cdn_ranges.py
```

### Python dependencies

```bash
python -m pip install --user -e .
# or explicitly:
python -m pip install --user \
  pydantic httpx dnspython cryptography aiohttp aiosqlite rich typer orjson
```

For testing, add: `pytest pytest-cov pytest-asyncio`.

### TUN permissions (Linux)

Opening a TUN device requires `CAP_NET_ADMIN`. Either run as root, or grant
the capability to your Python interpreter (recommended, least-privilege):

```bash
sudo setcap cap_net_admin+ep "$(readlink -f "$(which python3)")"
```

The application never *requires* root — when privileges are absent it falls
back to **offline/PCAP analysis mode**, which is fully testable without root.

### Xray-core

Install from <https://github.com/XTLS/Xray-core/releases>. Verify with
`xray version`.

---

## Configuration

| File | Purpose |
|------|---------|
| `config/app.json`      | Mode, TUN, DNS, Xray, resource limits, private block, profiles |
| `config/dns.json`      | DoH provider endpoints |
| `config/blocklist.json`| Custom CIDRs blocked before any outbound decision |
| `config/profiles.json` | Measurement/research profiles |
| `profiles/web.json`    | Web traffic profile |
| `profiles/gaming.json` | Gaming profile (low-latency, UDP/QUIC, NO transformation) |
| `data/cdn/*.json`      | CDN IP ranges (official sources) |
| `data/domains/verified.json` | Observed/verified endpoint DB |
| `data/cache/*.sqlite`  | DNS / TLS / probe caches |

Example `config/app.json`:

```json
{
  "mode": "lab",
  "tun": { "enabled": false, "mtu": 1500 },
  "dns": { "provider": "cloudflare", "doh": true },
  "private_block": true,
  "cdn_detection": true
}
```

---

## Usage

```bash
python -m app update        # fetch CDN ranges, expire stale cache, write exports
python -m app scan example.com
python -m app resolve example.com [-t A|AAAA|CNAME|TXT]
python -m app tls example.com
python -m app cdn example.com
python -m app health
python -m app generate      # emit xray config
python -m app validate      # validate config + blocklist + xray binary
python -m app proxy [--port 10808]  # start a local SOCKS5/HTTP proxy via xray
python -m app run           # live mode (TUN + Xray if configured)
python -m app dashboard      # Rich status dashboard
```

### `proxy` — local SOCKS5/HTTP proxy (via xray-core)

Start a persistent local proxy bound to `127.0.0.1` (default port 10808). It
spawns xray, verifies the port is serving, smoke-tests a real HTTPS request
through the tunnel, then keeps running until you press `Ctrl+C`:

```bash
python -m app proxy                          # socks5://127.0.0.1:10808 (direct mode)
python -m app proxy --port 10809             # different port
```

Point your browser / curl at it:

```bash
curl -x socks5h://127.0.0.1:10808 https://example.com
```

The inbound is a `mixed` proxy, so both SOCKS5 and HTTP clients work on the
same port.

#### DoH + Tor + Fragment anti-DPI tunnel

The default `proxy` mode builds an anti-DPI stack:

1. **DoH** (DNS over HTTPS) — all DNS queries go over encrypted HTTPS to
   Cloudflare / Google / Quad9 (no plaintext DNS on the wire).
2. **TLS Fragment** — the outgoing ClientHello is split into small pieces with
   random sleep intervals, defeating DPI systems that fingerprint full TLS
   handshakes.
3. **Tor (optional)** — when `--tor` is passed, external traffic routes through
   a local Tor SOCKS proxy (`127.0.0.1:9050`), adding a 3-hop onion route on
   top of DoH + Fragment.

```bash
python -m app proxy --tor --fragment   # full stack: DoH + Tor + Fragment
python -m app proxy --fragment         # DoH + Fragment, external direct
python -m app proxy --no-fragment      # DoH only, external direct
```

- `--tor/--no-tor` — route external traffic through local Tor SOCKS
  (requires `tor` running on `127.0.0.1:9050`).
- `--fragment/--no-fragment` — toggle TLS ClientHello Fragment.

> This is measurement and analysis software (credit: @patterniha,
> SNI-Spoofing reference).  It does **not** fabricate SNI or claim to
> "bypass DPI" — it applies transparent encryption and fragmentation layers
> and lets you observe the resulting traffic characteristics.

### `scan` output

Shows DNS (A/AAAA/CNAME/TTL), TLS (version, cipher, SAN, issuer, validity),
CDN provider + confidence, reachability probe, route action, and health level.

### `cdn` output

```
Hostname: example.com
Provider: Cloudflare
Confidence: 0.98
IPv4: ...
IPv6: ...
CNAME: ...
TLS: VALID
Latency: 42 ms
```

---

## GUI (Flet) — Connect button with TUN + DoH/Tor/Fragment

A cross-platform desktop/mobile GUI wraps the same anti-DPI stack behind a
single center **Connect** button (see `gui/`):

```bash
pip install -e ".[dev,gui]"
python scripts/fetch_xray.py -o bin     # download xray for your OS
flet run gui/main.py                    # desktop
```

On **Connect** it:
1. Verifies the xray binary.
2. Generates `config/xray-gui.json` with **DoH + TLS-Fragment + (Tor if running)**.
3. Smoke-tests the config with `xray -test`.
4. Opens a **TUN** device (Linux / Android) — requires `CAP_NET_ADMIN` (Linux)
   or the VPN permission (Android).
5. Spawns xray and flips the UI to **Connected**.

Disconnect tears everything down cleanly.

### Build matrix (GitHub Actions)

| Output      | Command / wrapper                          | TUN |
|-------------|--------------------------------------------|-----|
| Linux AppImage | PyInstaller + linuxdeploy                | Real Linux TUN (`CAP_NET_ADMIN`) |
| Windows EXE    | PyInstaller `--onefile`                  | xray `mixed` on `127.0.0.1` (WinDivert out of scope) |
| Android APK    | Gradle `VpnService` (Kotlin) + WebView   | Real Android TUN via `VpnService` |

> `flet build` is not used in CI — it interactive-prompts for Flutter SDK.
> Instead the workflow uses **PyInstaller** which is headless-friendly.

```bash
# Tag a release to trigger all three builds:
git tag v0.1.0 && git push origin v0.1.0
```

Artifacts land on **GitHub Releases** and a copy is committed into
`dist/latest/` (via Git LFS) by `.github/workflows/ci-commit-dist.yml`.

> **Honest caveat:** Windows "TUN mode" is the xray `mixed` inbound on
> localhost (a full system TUN needs the WinDivert kernel driver, out of
> scope). Android uses a genuine `VpnService`. On Linux the TUN needs
> `CAP_NET_ADMIN` (see *TUN permissions* above).

---

## Gaming profile

`profiles/gaming.json` enables: low latency, minimal buffering, IPv4/IPv6
fallback, UDP support, QUIC preference, MTU awareness, connection reuse.
**Fragmentation and packet transformation are OFF by default** for games,
because they can worsen latency and jitter.

---

## Data model & status labels

Every record carries an explicit status so claims are auditable:

`observed | resolved | provider_detected | tls_verified | fresh | stale | failed`

When a fact is not directly observed, output uses **`inferred`** (never
presented as verified). The tool does **not** claim to have discovered "all
websites" — the database only contains hosts you actually queried.

---

## Testing

```bash
python -m compileall app
pytest -q
python -m app validate
python -m app scan example.com
python -m app cdn example.com
python -m app resolve example.com
# if xray binary is present:
python -m app generate
python -m app health
```

The test suite uses `tests/fixtures/` with faked DNS records and TLS metadata,
so it runs **fully offline** (no real network). Target: ≥80% coverage of
pure-Python code.

---

## Troubleshooting

- **`permission denied` opening TUN** — grant `CAP_NET_ADMIN` or run in
  offline/PCAP mode.
- **`dig` not found** — the tool auto-falls back to `dnspython`; install
  `bind9-dnsutils` for the dig backend.
- **`xray binary not found`** — install Xray-core or set `xray.enabled:false`.
- **All probes fail but host is up** — ICMP may be filtered; TCP/TLS probes
  still report reachability (ICMP failure ≠ host down).

---

## Security & limitations

- All inputs (hostname, IP, CIDR, port, path) are validated; library APIs only.
- No `shell=True`; all `subprocess` calls use `shell=False` with fixed arg lists.
- This is **measurement and analysis software**. It does not perform packet
  injection or identity spoofing. Any transformation belongs only in an
  explicit laboratory setting with appropriate authorization.
- CDN IP ranges are **never** treated as customer hostname lists.
- The tool makes **no claim** about defeating censorship or DPI; it observes
  and reports what it can see on networks you are authorized to test.

---

## License

MIT.
