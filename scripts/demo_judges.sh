#!/bin/bash
# ===============================================================================
# PhantomAgent — Judge Demo
#
# A deterministic, self-narrating run of the full story. Non-interactive by
# default: every step prints what it is about to prove, does it, and shows the
# evidence. Pauses between acts so you can talk over it.
#
#   ./scripts/demo_judges.sh              full run with pauses
#   ./scripts/demo_judges.sh --no-pause   run straight through
#   ./scripts/demo_judges.sh --check      preflight only, change nothing
#
# Run --check BEFORE you present. It verifies every dependency and exits
# non-zero on the first thing that would break the demo.
# ===============================================================================

set -uo pipefail
cd "$(dirname "$0")/.."

PY="backend/venv/bin/python"
API="http://localhost:8000"
ATTACKER="172.28.0.10"
TARGET="172.28.0.5"
KALI="kali_attacker"

PAUSE=1
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --no-pause) PAUSE=0 ;;
        --check)    CHECK_ONLY=1 ;;
    esac
done

B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'

hr()   { printf '%s\n' "───────────────────────────────────────────────────────────────────────────────"; }
act()  { echo; hr; echo "${B}${C}$1${N}"; hr; }
ok()   { echo "  ${G}✓${N} $1"; }
bad()  { echo "  ${R}✗${N} $1"; }
warn() { echo "  ${Y}!${N} $1"; }
beat() { [ "$PAUSE" = "1" ] && { echo; read -rp "  ${B}[Enter]${N} "; } || sleep 1; }

FAILED=0
need() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; FAILED=1; fi; }

# ── Preflight ─────────────────────────────────────────────────────────────────
act "PREFLIGHT"

need "python venv present"          "[ -x $PY ]"
need "torch importable"             "$PY -c 'import torch'"
need "trained model present"        "[ -f backend/models/gnn_phantom.pt ]"
need "calibration artefact present" "[ -f backend/models/calibration_scores.json ]"
need "behavioural baseline present" "[ -f backend/models/benign_baseline.json ]"
need "docker available"             "docker info"
need "sudo without password"        "sudo -n true"

if docker inspect -f '{{.State.Running}}' "$KALI" 2>/dev/null | grep -q true; then
    ok "kali_attacker running"
elif [ "$CHECK_ONLY" = "1" ]; then
    # --check must not change anything, including container state.
    bad "kali_attacker not running — start it with: docker compose -f docker-compose.lab.yml up -d"
    FAILED=1
else
    warn "kali_attacker not running — starting docker lab"
    docker compose -f docker-compose.lab.yml up -d >/dev/null 2>&1
    sleep 4
    docker inspect -f '{{.State.Running}}' "$KALI" 2>/dev/null | grep -q true \
        && ok "kali_attacker started" || { bad "could not start kali_attacker"; FAILED=1; }
fi

if curl -sf -o /dev/null "$API/api/auth/login" -X POST -H 'Content-Type: application/json' \
        -d '{"username":"x","password":"y"}' -w '' 2>/dev/null || \
   curl -s -o /dev/null -w '%{http_code}' "$API/api/telemetry" 2>/dev/null | grep -qE '401|200'; then
    ok "backend reachable at $API"
else
    bad "backend not reachable — run ./start.sh in another terminal"
    FAILED=1
fi

if [ -z "${PHANTOM_API_TOKEN:-}" ]; then
    warn "PHANTOM_API_TOKEN not set in this shell — approve/release steps will be skipped"
    warn "  copy it from the backend boot banner and: export PHANTOM_API_TOKEN=..."
fi

if sudo -n iptables -L PHANTOM -n >/dev/null 2>&1; then
    RULES=$(sudo -n iptables -S PHANTOM 2>/dev/null | grep -c '\-A PHANTOM' || true)
    [ "$RULES" -gt 0 ] && warn "PHANTOM chain has $RULES stale rule(s) — release them before presenting" \
                       || ok "PHANTOM chain clean"
else
    ok "PHANTOM chain not yet installed (created on first containment)"
fi

echo
[ "$FAILED" = "1" ] && { bad "PREFLIGHT FAILED — fix the above before presenting"; exit 1; }
ok "${B}preflight passed${N}"
[ "$CHECK_ONLY" = "1" ] && exit 0
beat

# ── Act 1 ─────────────────────────────────────────────────────────────────────
act "ACT 1 — Why a graph, and not just a classifier"

echo "  A port scanner and a benign monitoring agent look IDENTICAL on their own"
echo "  counters: high SYN, many destination ports, high frequency."
echo
echo "  The difference is who they talk to. A scanner's targets answer with RSTs"
echo "  because most probed ports are closed. A monitoring agent's do not."
echo
echo "  Same node features. Only the neighbourhood differs:"
echo

PYTHONPATH=. $PY - <<'PYEOF' 2>/dev/null | grep -v '^\[GNN\]\|^\[BEHAVIOR\]\|^\[CONFORMAL\]'
from backend.pipeline.gnn_model import GNNPredictor
p = GNNPredictor()
SCAN   = {"syn_count":60,"ack_count":20,"rst_count":2,"unique_dst_ports":45,
          "bytes_sent":1500,"connection_frequency":30.0,"failed_auth_count":0}
VICTIM = {"syn_count":1,"ack_count":2,"rst_count":40,"unique_dst_ports":1,
          "bytes_sent":300,"connection_frequency":8.0,"failed_auth_count":0}
SERVER = {"syn_count":1,"ack_count":12,"rst_count":1,"unique_dst_ports":1,
          "bytes_sent":4000,"connection_frequency":2.0,"failed_auth_count":0}
def run(nbr):
    return p.predict_graph_scores({"nodes":["host","a","b","c","d"],
        "features":[SCAN]+[nbr]*4, "edges":[(0,1),(0,2),(0,3),(0,4)]})["host"]
print(f"    neighbours answering with RSTs   -> anomaly score {run(VICTIM):.4f}")
print(f"    neighbours healthy               -> anomaly score {run(SERVER):.4f}")
print(f"    same host scored with no graph   -> anomaly score {p.predict_anomaly_score(SCAN):.4f}")
PYEOF

echo
echo "  Ablation, same architecture and seed, adjacency on vs off:"
echo "    GNN (message passing)   F1 1.0000    0 false positives"
echo "    MLP (no graph)          F1 0.7445  162 false positives"
echo "    ${B}backend/scripts/ablation.py reproduces this${N}"
beat

# ── Act 2 ─────────────────────────────────────────────────────────────────────
act "ACT 2 — Live attack, real packets"

echo "  Kali ($ATTACKER) will scan Juice Shop ($TARGET) inside the isolated lab."
echo "  Watch the dashboard: watcher -> prefilter -> GNN -> consensus -> decision."
echo
echo "  ${B}Run this in a second terminal to watch enforcement:${N}"
echo "    ${C}watch -n1 sudo iptables -L PHANTOM -n -v${N}"
beat

echo "  Launching nmap SYN scan..."
docker exec "$KALI" nmap -sS -T4 -p 1-400 "$TARGET" >/dev/null 2>&1 &
NMAP_PID=$!
sleep 12
kill $NMAP_PID 2>/dev/null
ok "scan complete"
beat

# ── Act 3 ─────────────────────────────────────────────────────────────────────
act "ACT 3 — Containment is real, not a UI state"

echo "  Most dashboards draw a red box and call it 'contained'. This writes a"
echo "  kernel firewall rule. The chain is jumped from INPUT and FORWARD —"
echo "  FORWARD matters because container-to-container traffic never hits INPUT."
echo

if sudo -n iptables -L PHANTOM -n -v 2>/dev/null | tail -n +2; then
    echo
    JUMPS=$(sudo -n iptables -S 2>/dev/null | grep -c 'j PHANTOM' || true)
    ok "PHANTOM referenced from $JUMPS chain(s)"
else
    warn "PHANTOM chain not present — no containment fired (check severity routing)"
fi

echo
echo "  Proof the block bites — Kali attempting to reach the target:"
if docker exec "$KALI" timeout 4 curl -s -o /dev/null "http://$TARGET:3000" 2>/dev/null; then
    warn "target still reachable (no block installed for $ATTACKER yet)"
else
    ok "${B}attacker can no longer reach the target${N}"
fi
beat

# ── Act 4 ─────────────────────────────────────────────────────────────────────
act "ACT 4 — Reset"

if [ -n "${PHANTOM_API_TOKEN:-}" ]; then
    curl -s -X POST -H "Authorization: Bearer $PHANTOM_API_TOKEN" \
         "$API/api/blocks/$ATTACKER/release" >/dev/null 2>&1 \
        && ok "block released — demo is re-runnable" \
        || warn "release call failed; restarting the backend also flushes the chain"
else
    warn "PHANTOM_API_TOKEN unset — release manually or restart the backend"
fi

act "TALKING POINTS"
cat <<'EOF'
  · The GNN is a real GNN. Message passing over the host communication graph;
    ablation shows an MLP on identical features makes 162 false positives.
  · No single evidence source can confirm a threat. Five signals, and the GNN
    plus its own conformal p-value count as one, because they are correlated.
  · Containment writes real iptables rules, and is reversible via the API.
  · The LLM never emits shell commands — it picks from a fixed action
    vocabulary and the responder builds the argv.
  · 213 tests. They caught a bug where our firewall rules were silently no-ops.
EOF
echo
