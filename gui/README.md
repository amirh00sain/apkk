# NetProbe GUI — Flet desktop + Android (TUN)

A single-center **Connect/Disconnect** button that spins up the full
**DoH + TLS-Fragment + Tor + TUN** anti-DPI stack on a user click.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  gui/main.py  (Flet)                  gui/backend.py                │
│  ┌──────────────────┐      ┌──────────────────────────────────┐    │
│  │  Connect button   │─────▶│ ConnectionController.connect()   │    │
│  │  Status text      │      │  1. check_binary()               │    │
│  │  Detail text      │      │  2. _write_config() (DoH+Fragment│    │
│  └──────────────────┘      │  3. smoke_test (xray -test)      │    │
│                             │  4. open_tun() (Linux TUN)       │    │
│                             │  5. start_xray()                 │    │
│                             └──────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
         │                                         │
    ┌────▼─────┐    ┌─────────────┐    ┌──────────▼──────────┐
    │ xray bin │    │ config.json │    │ TUN (Linux/app only)│
    │  (DoH,   │    │ (generated) │    │ CAP_NET_ADMIN       │
    │  Frag,   │    │             │    │                     │
    │  Tor)    │    └─────────────┘    └─────────────────────┘
    └──────────┘
```

## Platform targets

| Output     | How                         | TUN mode                  |
|------------|-----------------------------|---------------------------|
| **Linux**  | PyInstaller + AppImage          | Real Linux TUN (CAP_NET_ADMIN) |
| **Windows**| PyInstaller (onefile)           | xray `mixed` on 127.0.0.1 (WinDivert out of scope) |
| **Android**| Gradle + VpnService (Kotlin)    | Real Android TUN via `VpnService` |

> **Note on Flet:** the GUI is written in Flet, but the CI builds use
> **PyInstaller** (not `flet build`, which interactive-prompts for a bundled
> Flutter SDK and fails headless in GitHub Actions).

## Local dev (desktop)

```bash
# Install deps
pip install -e ".[dev,gui]"

# Fetch xray for your platform
python scripts/fetch_xray.py -o bin

# Run the GUI
flet run gui/main.py
```

Click **Connect** — verify `xray -test` passes, then observe DoH + Fragment
traffic with Wireshark.  If Tor is running (`tor -f config/torrc`), the
`--tor` path is used automatically.

## Android (APK)

The Android wrapper lives in `android/` — it is a real Kotlin `VpnService`
project with a WebView for the UI:

```bash
cd android
./gradlew assembleDebug    # requires Android SDK / NDK
```

The APK bundles:
- `xray` binary for `arm64-v8a` (downloaded by CI or `scripts/fetch_xray.py`)
- `config.json` (generated, DoH + Fragment + Tor routing)
- `index.html` (minimal Connect UI served in a WebView)

> **Note:** Requires Android 7.0+ (API 24). VPN permission is requested at
> runtime via `VpnService.prepare()`. A debug keystore is used in CI; for
> production you must supply a release keystore via GitHub Secrets.

## Windows (EXE)

```bash
flet build windows --include-packages app,gui
# Output: build/windows/x64/runner/Release/
```

Windows TUN degrades to the xray `mixed` inbound on `127.0.0.1:10808`
(no WinDivert kernel driver). Users set a system SOCKS5 proxy manually.

## CI / GitHub Actions

The full build is triggered by a `v*` tag push or manual workflow dispatch.
The matrix in `.github/workflows/build.yml` handles all three platforms:

1. `pytest -q --cov` gate — must pass
2. `python scripts/fetch_xray.py` — download correct xray
3. `flet build {linux|windows|apk|web}` — compile UI
4. `gh release` upload — APK + EXE zip + AppImage
5. `dist/latest/` committed back via `ci-commit-dist.yml`

---

*Credits: @patterniha (SNI-Spoofing reference). Measurement/analysis tool.*
