"""Event logger utility for persisting pipeline events to SQLite and JSONL for future retraining"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional

from backend.config import DB_PATH, EVENTS_JSONL_PATH


class EventLogger:
    """Logs raw features, GNN score, Gemma verdict, and action taken to SQLite and JSONL"""

    def __init__(
        self,
        db_path=None,
        jsonl_path=None
    ):
        # Paths come from config so database.py and this module cannot drift apart.
        self.db_path = str(db_path or DB_PATH)
        self.jsonl_path = str(jsonl_path or EVENTS_JSONL_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize SQLite events_log table if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    gnn_score REAL NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    action_taken TEXT NOT NULL,
                    raw_features TEXT NOT NULL,
                    gemma_verdict TEXT NOT NULL
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[EVENT_LOGGER] Failed to initialize SQLite database: {e}")

    def log_event(
        self,
        source_ip: str,
        features: Dict[str, Any],
        gnn_score: float,
        verdict: Dict[str, Any],
        action_taken: str
    ) -> Dict[str, Any]:
        """Record full event payload to SQLite database and JSONL file"""
        timestamp = datetime.now().isoformat()
        
        event_record = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "gnn_score": float(gnn_score),
            "threat_type": verdict.get("threat_type", "UNKNOWN"),
            "severity": int(verdict.get("severity", 5)),
            "action_taken": action_taken,
            "raw_features": features,
            "gemma_verdict": verdict
        }

        # 1. Store in JSONL
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_record) + "\n")
        except Exception as e:
            print(f"[EVENT_LOGGER] JSONL write error: {e}")

        # 2. Store in SQLite DB
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events_log (timestamp, source_ip, gnn_score, threat_type, severity, action_taken, raw_features, gemma_verdict)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                source_ip,
                float(gnn_score),
                verdict.get("threat_type", "UNKNOWN"),
                int(verdict.get("severity", 5)),
                action_taken,
                json.dumps(features),
                json.dumps(verdict)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[EVENT_LOGGER] SQLite insert error: {e}")

        return event_record
