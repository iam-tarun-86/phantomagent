"""PhantomAgent Configuration"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Database
DB_PATH = DATA_DIR / "phantom.db"

# Watcher Config
WATCHED_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
]

# Network Config
NETWORK_INTERFACE = "eth0"
PORT_SCAN_THRESHOLD = 20
DNS_TUNNEL_DOMAINS = [".tk", ".ml", ".ga", ".cf"]

# File System Config
WATCHED_PATHS = [
    "/tmp",
    "/var/tmp",
]

# Qwen Config
QWEN_MODEL = "qwen3:8b"
QWEN_API_URL = "http://localhost:8085/api/generate"
QWEN_TIMEOUT = 30

# Decision Engine
SEVERITY_THRESHOLDS = {
    "LOG": (1, 3),
    "ALERT": (4, 6),
    "AUTO_CONTAIN": (7, 8),
    "PENDING_APPROVAL": (9, 10),
}

# Responder
IPTABLES_CHAIN = "PHANTOM"
BLOCK_DURATION = 3600

# API
API_HOST = "0.0.0.0"
API_PORT = 8000
WS_PING_INTERVAL = 20

# Demo Mode - DISABLED for production
DEMO_MODE = False
DEMO_INTERVAL = 15