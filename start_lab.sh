#!/usr/bin/env bash
# ===============================================================================
# Deprecated — use ./start.sh
#
# This was a second launcher that had drifted from start.sh: it used the system
# python instead of the venv, bound the API to 0.0.0.0 instead of loopback, skipped
# .env loading, and its trap killed the backend without stopping the containers.
#
# Two launchers meant two sets of bugs, so this now delegates. Kept as a shim so
# existing muscle memory and any docs referring to it still work.
# ===============================================================================

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[NOTE] start_lab.sh is deprecated — running ./start.sh instead."
echo ""
exec "$ROOT/start.sh" "$@"
