"""PhantomAgent Configuration"""

import hashlib
import os
import secrets
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Database — single source of truth. backend/database.py and backend/utils/event_logger.py
# both import this; do not hardcode a path in either.
DB_PATH = BASE_DIR.parent / "data" / "phantomagent.db"
EVENTS_JSONL_PATH = BASE_DIR.parent / "data" / "events_dataset.jsonl"

# Watcher Config
WATCHED_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
]

# Network Config
NETWORK_INTERFACE = None
PORT_SCAN_THRESHOLD = 20
DNS_TUNNEL_DOMAINS = [".tk", ".ml", ".ga", ".cf"]

# File System Config
WATCHED_PATHS = [
    "/tmp",
    "/var/tmp",
]

# Gemma / LLM Config
GEMMA_MODEL = "gemma4:e4b"
GEMMA_API_URL = "http://localhost:8085/v1/chat/completions"
GEMMA_TIMEOUT = 60

# Decision Engine Severity Thresholds
SEVERITY_THRESHOLDS = {
    "LOG": (1, 3),              # Tier 1: Informational / Noise -> Log only
    "AUTO_CONTAIN": (4, 8),     # Tier 2 & 3: Moderate / High -> Auto-containment
    "PENDING_APPROVAL": (9, 10),# Tier 4: Critical / Campaign -> Operator Approval Modal
}

# Responder
IPTABLES_CHAIN = "PHANTOM"
BLOCK_DURATION = 3600
# Seconds an operator has to answer a critical alert before it auto-contains.
APPROVAL_TIMEOUT_SECONDS = int(os.getenv("PHANTOM_APPROVAL_TIMEOUT", "15"))

# API
# Bind to loopback by default. The API can approve threats and shell out with sudo, so
# exposing it on 0.0.0.0 is opt-in, not the default.
API_HOST = os.getenv("PHANTOM_HOST", "127.0.0.1")
API_PORT = int(os.getenv("PHANTOM_PORT", "8000"))
WS_PING_INTERVAL = 20

CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("PHANTOM_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]

# ===== Authentication =====
# Every /api route and the WebSocket require this bearer token. If none is supplied via
# the environment, one is generated per boot and printed to the console so the demo still
# runs with zero setup — but it will not survive a restart.
API_TOKEN = os.getenv("PHANTOM_API_TOKEN") or ""
TOKEN_IS_EPHEMERAL = not API_TOKEN
if not API_TOKEN:
    API_TOKEN = secrets.token_urlsafe(32)

AUTH_USER = os.getenv("PHANTOM_USER", "admin")

# PBKDF2-SHA256 hash of the operator password, formatted "<hex_salt>$<hex_hash>".
# Generate one with:
#   python -c "from backend.config import hash_password; print(hash_password('yourpass'))"
PBKDF2_ITERATIONS = 240_000
AUTH_PASSWORD_HASH = os.getenv("PHANTOM_PASSWORD_HASH", "")

# Dev fallback: with no hash configured, fall back to the historical demo password so a
# fresh clone still logs in. A warning is printed at boot.
DEV_FALLBACK_PASSWORD = "phantom"


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Derive a "<hex_salt>$<hex_hash>" PBKDF2-SHA256 credential string."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored "<hex_salt>$<hex_hash>" string."""
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        expected = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS
        )
        return secrets.compare_digest(expected.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# Demo Mode — gates the /api/test/inject* endpoints, which emit fabricated threats.
DEMO_MODE = os.getenv("PHANTOM_DEMO_MODE", "true").lower() in ("1", "true", "yes")
DEMO_INTERVAL = 15
