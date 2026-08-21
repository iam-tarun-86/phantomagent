#!/usr/bin/env bash
# ===============================================================================
# PhantomAgent — System Launcher
#
# The single entry point. Starts the Docker lab, the backend and the dashboard,
# and tears all three down on Ctrl+C.
#
#   ./start.sh          start everything
#   Ctrl+C              stop everything, including the containers
#
# Nothing else in this repo starts the lab. The demo scripts expect this to be
# running already and will refuse if it is not.
# ===============================================================================

# NOT `set -e`: a non-zero exit from any step must still reach cleanup() rather than
# aborting the script with services half-started.
set -uo pipefail

# Resolve the repo root once and stay there. The previous version ran `cd frontend &&
# npm run dev &` (which backgrounds the whole compound, leaving the parent's cwd alone)
# and then `cd ..`, which moved the shell to the PARENT of the repo. Every relative path
# in cleanup then silently missed — which is why containers used to survive Ctrl+C.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

COMPOSE_FILE="$ROOT/docker-compose.lab.yml"
BACKEND_PORT="${PHANTOM_PORT:-8000}"
FRONTEND_PORT=5173

BACKEND_PID=""
FRONTEND_PID=""
CLEANED=0

port_busy() { ss -ltn 2>/dev/null | grep -q ":$1 "; }

wait_for_port_free() {
    local port="$1" tries="${2:-20}"
    while [ "$tries" -gt 0 ] && port_busy "$port"; do
        sleep 0.25
        tries=$((tries - 1))
    done
    ! port_busy "$port"
}

# ─────────────────────────────────────────
# Teardown
# ─────────────────────────────────────────
cleanup() {
    [ "$CLEANED" = "1" ] && return
    CLEANED=1
    trap - INT TERM EXIT

    echo ""
    echo "[SYSTEM] Shutting down PhantomAgent..."

    # Frontend: npm spawns vite as a child, so signal the whole process group
    # (started with setsid, so PID == PGID). Killing npm alone orphans vite on :5173.
    if [ -n "$FRONTEND_PID" ]; then
        kill -TERM -- "-$FRONTEND_PID" 2>/dev/null || kill -TERM "$FRONTEND_PID" 2>/dev/null
    fi

    # Backend: runs under sudo, so the recorded PID is the root-owned sudo wrapper that
    # this user cannot signal. Target the real process by its command line, as root.
    #
    # SIGTERM, not SIGKILL: the FastAPI lifespan shutdown is what removes the PHANTOM
    # iptables chain. Killing it outright leaves live DROP rules on the host.
    echo "[SYSTEM] Stopping backend (graceful — lets it remove its firewall rules)..."
    sudo pkill -TERM -f "backend/venv/bin/python .*run.py" 2>/dev/null || true
    sudo pkill -TERM -f "uvicorn backend.main:app" 2>/dev/null || true

    if ! wait_for_port_free "$BACKEND_PORT" 40; then
        echo "[SYSTEM] Backend did not exit in time — forcing."
        sudo pkill -KILL -f "backend/venv/bin/python .*run.py" 2>/dev/null || true
        sudo pkill -KILL -f "uvicorn backend.main:app" 2>/dev/null || true
    fi

    wait_for_port_free "$FRONTEND_PORT" 12 || {
        pkill -KILL -f "vite.*$ROOT/frontend" 2>/dev/null || true
    }

    echo "[SYSTEM] Stopping Docker Lab containers..."
    docker compose -f "$COMPOSE_FILE" stop 2>/dev/null || true

    # Report honestly rather than claiming success unconditionally.
    local leftovers=""
    port_busy "$BACKEND_PORT"  && leftovers="${leftovers} backend:$BACKEND_PORT"
    port_busy "$FRONTEND_PORT" && leftovers="${leftovers} frontend:$FRONTEND_PORT"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'kali_attacker|juice_shop'; then
        leftovers="${leftovers} containers"
    fi
    if sudo iptables -L PHANTOM -n >/dev/null 2>&1; then
        leftovers="${leftovers} iptables:PHANTOM"
    fi

    if [ -n "$leftovers" ]; then
        echo "[SYSTEM] WARNING — still running:${leftovers}"
        echo "[SYSTEM] Inspect with: ss -ltn | grep -E '8000|5173' ; docker ps ; sudo iptables -L PHANTOM -n"
    else
        echo "[SYSTEM] All services stopped cleanly."
    fi
    exit 0
}

trap cleanup INT TERM EXIT

# ─────────────────────────────────────────
# 0. Preflight
# ─────────────────────────────────────────
if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] Docker is not running. Start Docker Desktop / the daemon first."
    exit 1
fi
if [ ! -x "$ROOT/backend/venv/bin/python" ]; then
    echo "[ERROR] Python venv missing at backend/venv."
    echo "        python3 -m venv backend/venv && backend/venv/bin/pip install -r backend/requirements.txt"
    exit 1
fi
if port_busy "$BACKEND_PORT"; then
    echo "[ERROR] Port $BACKEND_PORT is already in use — another PhantomAgent may be running."
    echo "        sudo ss -ltnp | grep :$BACKEND_PORT"
    exit 1
fi

# ─────────────────────────────────────────
# 1. Docker Lab Containers
# ─────────────────────────────────────────
echo "[1/4] Starting Docker Lab containers (kali_attacker & juice_shop)..."
docker compose -f "$COMPOSE_FILE" up -d || {
    echo "[ERROR] Could not start the Docker lab."
    exit 1
}

# ─────────────────────────────────────────
# 2. Storage and GNN model artefacts
# ─────────────────────────────────────────
echo "[2/4] Checking storage and model artefacts..."
mkdir -p "$ROOT/data" "$ROOT/backend/models"

# All three artefacts are load-bearing: the checkpoint carries the normalization
# statistics, and the two JSON files calibrate the conformal and behavioural signals.
# A missing one means those signals silently degrade to fallbacks.
NEEDS_TRAINING=0
for artefact in \
    "$ROOT/backend/models/gnn_phantom.pt" \
    "$ROOT/backend/models/calibration_scores.json" \
    "$ROOT/backend/models/benign_baseline.json"
do
    if [ ! -f "$artefact" ]; then
        echo "      Missing $(basename "$artefact") — training required."
        NEEDS_TRAINING=1
    fi
done

if [ "$NEEDS_TRAINING" = "1" ]; then
    [ -f "$ROOT/backend/data/synthetic_graphs.jsonl" ] || \
        PYTHONPATH="$ROOT" "$ROOT/backend/venv/bin/python" "$ROOT/backend/scripts/generate_dataset.py"
    PYTHONPATH="$ROOT" "$ROOT/backend/venv/bin/python" "$ROOT/backend/scripts/train_gnn.py" || {
        echo "[ERROR] Training failed — cannot start without model artefacts."
        exit 1
    }
else
    echo "      Model weights + calibration artefacts present."
fi

# ─────────────────────────────────────────
# 3. Backend (needs sudo for Scapy packet capture)
# ─────────────────────────────────────────
echo "[3/4] Starting backend (FastAPI + Scapy + GNN + Gemma)..."

# Load .env, then forward PHANTOM_* through sudo, which scrubs the environment.
# Without this, auth config set in your shell is silently lost.
if [ -f "$ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$ROOT/.env"
    set +a
fi

sudo PYTHONPATH="/usr/local/lib/python3.12/dist-packages:/home/tarun/.local/lib/python3.12/site-packages:$ROOT" \
    PHANTOM_API_TOKEN="${PHANTOM_API_TOKEN:-}" \
    PHANTOM_USER="${PHANTOM_USER:-admin}" \
    PHANTOM_PASSWORD_HASH="${PHANTOM_PASSWORD_HASH:-}" \
    PHANTOM_HOST="${PHANTOM_HOST:-127.0.0.1}" \
    PHANTOM_PORT="$BACKEND_PORT" \
    PHANTOM_CORS_ORIGINS="${PHANTOM_CORS_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}" \
    PHANTOM_APPROVAL_TIMEOUT="${PHANTOM_APPROVAL_TIMEOUT:-15}" \
    PHANTOM_DEMO_MODE="${PHANTOM_DEMO_MODE:-true}" \
    "$ROOT/backend/venv/bin/python" "$ROOT/run.py" &
BACKEND_PID=$!

for _ in $(seq 1 40); do
    port_busy "$BACKEND_PORT" && break
    sleep 0.5
done
if ! port_busy "$BACKEND_PORT"; then
    echo "[ERROR] Backend failed to bind port $BACKEND_PORT. See the output above."
    exit 1
fi
echo "      Backend listening on http://localhost:$BACKEND_PORT"

# ─────────────────────────────────────────
# 4. Frontend dashboard
# ─────────────────────────────────────────
echo "[4/4] Starting React dashboard..."
# setsid gives npm its own process group so cleanup can signal vite too. Note the
# subshell: this must not change the launcher's working directory.
( cd "$ROOT/frontend" && exec setsid npm run dev ) &
FRONTEND_PID=$!

for _ in $(seq 1 40); do
    port_busy "$FRONTEND_PORT" && break
    sleep 0.5
done

echo ""
echo "==============================================================================="
echo " PhantomAgent is running"
echo "==============================================================================="
echo "   Dashboard   : http://localhost:$FRONTEND_PORT"
echo "   Backend API : http://localhost:$BACKEND_PORT"
echo "   Target      : http://localhost:3000   (juice_shop, 172.28.0.5)"
echo "   Attacker    : container kali_attacker (172.28.0.10)"
echo ""
echo "   Attack demo : ./scripts/demo_attacks.sh   (second terminal)"
echo "   Judge demo  : ./scripts/demo_judges.sh    (second terminal)"
echo ""
echo "   Ctrl+C stops the app, the dashboard AND the containers."
echo "==============================================================================="
echo ""

# Block here. Any signal lands in cleanup().
wait
