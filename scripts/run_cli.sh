#!/bin/bash
# Convenience wrapper to run the NetProbe CLI.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python -m app "$@"
