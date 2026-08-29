#!/usr/bin/env bash
#
# run.sh — NetProbe / SNI-Spoofing toolkit bootstrap & smoke test.
#
# What it does (everything is guarded by an "is it already installed?" check):
#   1. Verify required system tools (bash, python3, uv, curl/wget) are present.
#   2. Create a Python virtualenv if missing.
#   3. Install project deps + dev extras (+ scapy for the PCAP backend).
#   4. Provide the xray-core binary:
#        - use /home/amir/Downloads/xray if present, else download Xray 26.x.
#   5. Download geoip.dat / geosite.dat (needed by the generated routing rules).
#   6. Run `python -m app validate`, generate the xray config, and `xray -test`.
#   7. Run the full pytest suite.
#   8. Optionally scan a list of sites (pass sites as args to run.sh).
#
# Usage:
#   ./run.sh                 # bootstrap + self-tests only
#   ./run.sh example.com     # also probe the given site(s)
#   ./run.sh --proxy         # bootstrap, then start the local SOCKS5/HTTP proxy
#   ./run.sh --proxy example.com
#   PROXY=1 ./run.sh         # same as --proxy
#   XRAY_BIN=/path/to/xray ./run.sh
#
# This tool is measurement/analysis ONLY. Packet injection is out of scope.

set -euo pipefail

# Resolve script directory so paths are stable regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN_DIR="$SCRIPT_DIR/bin"
XRAY_BIN="${XRAY_BIN:-$BIN_DIR/xray}"

# Allow overriding the download source of the xray binary / geo data.
XRAY_VERSION="${XRAY_VERSION:-26.3.27}"
GEOIP_URL="${GEOIP_URL:-https://github.com/v2fly/geoip/releases/latest/download/geoip.dat}"
GEO_SITE_URL="${GEO_SITE_URL:-https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat}"

log()  { printf '\033[1;34m[run]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[err]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. System prerequisites
# ---------------------------------------------------------------------------
log "Checking system prerequisites..."
need() { command -v "$1" >/dev/null 2>&1 || { err "required tool not found: $1"; return 1; }; }

missing=0
for t in bash python3 curl; do
  if need "$t"; then ok "$t: $(command -v "$t")"; else missing=1; fi
done

if command -v uv >/dev/null 2>&1; then
  ok "uv: $(command -v uv) ($(uv --version 2>/dev/null || echo unknown))"
else
  warn "uv not found — will install via the official installer"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # Make uv available in this shell.
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  if ! command -v uv >/dev/null 2>&1; then
    err "uv installation failed; install it manually: https://docs.astral.sh/uv/"
    exit 1
  fi
  ok "uv installed: $(command -v uv)"
fi

# A downloader helper that prefers curl, falls back to wget.
dl() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    err "neither curl nor wget available to download $url"; return 1
  fi
}

# ---------------------------------------------------------------------------
# 2. Virtual environment
# ---------------------------------------------------------------------------
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  ok "venv present: $SCRIPT_DIR/.venv"
else
  log "Creating virtualenv..."
  uv venv --python 3.14
  ok "venv created"
fi

# Always use the venv's python/pip going forward.
PY="$SCRIPT_DIR/.venv/bin/python"
PIP="$SCRIPT_DIR/.venv/bin/pip"

# ---------------------------------------------------------------------------
# 3. Dependencies
# ---------------------------------------------------------------------------
if [ -x "$SCRIPT_DIR/.venv/bin/pytest" ]; then
  ok "python deps already installed"
else
  log "Installing Python dependencies (project + dev + scapy)..."
  uv pip install -e ".[dev]"
  uv pip install scapy
  ok "dependencies installed"
fi

# Activate for the rest of the script (so `python -m app` works).
# shellcheck disable=SC1091
source "$SCRIPT_DIR/.venv/bin/activate"

# ---------------------------------------------------------------------------
# 4. xray-core binary
# ---------------------------------------------------------------------------
mkdir -p "$BIN_DIR"

if [ -x "$XRAY_BIN" ]; then
  ok "xray binary present: $XRAY_BIN ($("$XRAY_BIN" version 2>/dev/null | head -1))"
else
  # Prefer a copy already downloaded to Downloads.
  if [ -x "/home/amir/Downloads/xray" ]; then
    log "Copying xray from /home/amir/Downloads/xray ..."
    cp "/home/amir/Downloads/xray" "$XRAY_BIN"
    chmod +x "$XRAY_BIN"
    ok "xray copied"
  else
    log "Downloading xray-core v$XRAY_VERSION ..."
    # Resolve the concrete asset for this platform.
    ASSET="xray-linux-64.zip"
    URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${ASSET}"
    TMP="$(mktemp -d)"
    if dl "$URL" "$TMP/xray.zip"; then
      ( cd "$TMP" && (command -v unzip >/dev/null && unzip -o xray.zip || python -c "import zipfile;zipfile.ZipFile('xray.zip').extractall('.')") )
      if [ -f "$TMP/xray" ]; then
        mv "$TMP/xray" "$XRAY_BIN"
        chmod +x "$XRAY_BIN"
        ok "xray downloaded: $("$XRAY_BIN" version 2>/dev/null | head -1)"
      else
        err "xray binary not found inside the downloaded archive"
      fi
    else
      warn "xray download failed — xray-dependent checks will be skipped"
    fi
    rm -rf "$TMP"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Geo data (geoip.dat / geosite.dat)
# ---------------------------------------------------------------------------
if [ -f "$BIN_DIR/geoip.dat" ]; then
  ok "geoip.dat present"
else
  log "Downloading geoip.dat ..."
  dl "$GEOIP_URL" "$BIN_DIR/geoip.dat" && ok "geoip.dat downloaded" || warn "geoip.dat download failed"
fi

if [ -f "$BIN_DIR/geosite.dat" ]; then
  ok "geosite.dat present"
else
  log "Downloading geosite.dat (dlc.dat) ..."
  dl "$GEO_SITE_URL" "$BIN_DIR/geosite.dat" && ok "geosite.dat downloaded" || warn "geosite.dat download failed"
fi

# ---------------------------------------------------------------------------
# 6. Validate + generate + xray config test
# ---------------------------------------------------------------------------
log "Validating configuration..."
"$PY" -m app validate || warn "validate reported issues (non-fatal)"

if [ -x "$XRAY_BIN" ] && [ -f "$BIN_DIR/geosite.dat" ] && [ -f "$BIN_DIR/geoip.dat" ]; then
  log "Generating xray config ..."
  "$PY" -m app generate
  log "Testing generated config with xray ..."
  if "$XRAY_BIN" -test -config config/xray.json >/tmp/xray_test.log 2>&1; then
    ok "xray config OK"
  else
    warn "xray config test failed:"; tail -5 /tmp/xray_test.log
  fi
else
  warn "skipping xray config generation (binary or geo data missing)"
fi

# ---------------------------------------------------------------------------
# 7. Test suite
# ---------------------------------------------------------------------------
log "Running pytest suite ..."
"$PY" -m pytest -q --cov=app --cov-report=term-missing || warn "some tests failed"

# ---------------------------------------------------------------------------
# 8. Optional live probing of sites (passed as arguments)
# ---------------------------------------------------------------------------
# Extract the --proxy flag (and --proxy=N port) from the args; the rest are sites.
PROXY_FLAG=0
PROXY_FLAG_PORT=""
SITES=()
for arg in "$@"; do
  case "$arg" in
    --proxy)          PROXY_FLAG=1 ;;
    --proxy=*)        PROXY_FLAG=1; PROXY_FLAG_PORT="${arg#--proxy=}" ;;
    *)                SITES+=("$arg") ;;
  esac
done

if [ "${#SITES[@]}" -gt 0 ]; then
  log "Probing requested sites: ${SITES[*]}"
  for site in "${SITES[@]}"; do
    echo "----- $site -----"
    if [ -x "$XRAY_BIN" ]; then
      # Bring xray up, proxy a request, then tear it down.
      "$XRAY_BIN" run -config config/xray.json >/tmp/xray_run.log 2>&1 &
      XPID=$!
      sleep 2
      timeout 15 curl -s --proxy socks5h://127.0.0.1:10808 "https://$site" \
        -o /dev/null -w "proxy $site: HTTP %{http_code} in %{time_total}s\n" || echo "proxy $site: failed"
      kill "$XPID" 2>/dev/null || true
      wait "$XPID" 2>/dev/null || true
    fi
    # Measurement/analysis scan (DNS/TLS/CDN/probe) — never modifies packets.
    timeout 60 "$PY" -m app scan "$site" 2>/dev/null | sed -n '/^Probe/,/^$/p;/^CDN/,/^$/p' || true
  done
fi

# ---------------------------------------------------------------------------
# 8b. Optional: launch the persistent local proxy (--proxy or PROXY=1)
# ---------------------------------------------------------------------------
if [ "$PROXY_FLAG" = "1" ] || [ "${PROXY:-0}" = "1" ]; then
  log "Starting the local SOCKS5/HTTP proxy (Ctrl+C to stop) ..."
  "$PY" -m app proxy --port "${PROXY_FLAG_PORT:-${PROXY_PORT:-10808}}"
fi

ok "Done. See README.md for the full command reference."
