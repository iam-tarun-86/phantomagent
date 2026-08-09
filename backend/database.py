"""PhantomAgent Database - SQLite persistence layer"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "phantomagent.db"


class Database:
    def __init__(self):
        self.db_path = DB_PATH
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_tables()

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        with self._connect() as conn:
            # Threats table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    source_ip TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    raw_log TEXT,
                    attack_pattern TEXT,
                    explanation TEXT,
                    reason TEXT,
                    confidence REAL,
                    indicators TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()

    # ===== THREATS =====

    def save_threat(self, threat: Dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO threats (
                    id, type, severity, source_ip, status, timestamp,
                    raw_log, attack_pattern, explanation,
                    reason, confidence, indicators
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat.get("id"),
                threat.get("type", "Unknown"),
                threat.get("severity", 5),
                threat.get("source_ip", "unknown"),
                threat.get("status", "DETECTED"),
                threat.get("timestamp", datetime.now().isoformat()),
                threat.get("raw_log", ""),
                threat.get("attack_pattern", ""),
                threat.get("explanation", ""),
                threat.get("reason", ""),
                threat.get("confidence", 0),
                json.dumps(threat.get("indicators", []))
            ))
            conn.commit()

    def load_threats(self, limit: int = 50) -> List[Dict]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM threats ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [self._row_to_threat(row) for row in rows]

    def _row_to_threat(self, row: sqlite3.Row) -> Dict:
        return {
            "id": row["id"],
            "type": row["type"],
            "severity": row["severity"],
            "source_ip": row["source_ip"],
            "status": row["status"],
            "timestamp": row["timestamp"],
            "raw_log": row["raw_log"] or "",
            "attack_pattern": row["attack_pattern"] or "",
            "explanation": row["explanation"] or "",
            "reason": row["reason"] or "",
            "confidence": row["confidence"] or 0,
            "indicators": json.loads(row["indicators"] or "[]")
        }

    # ===== LOGS =====

    def save_log(self, log: Dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO logs (timestamp, source, level, message)
                VALUES (?, ?, ?, ?)
            """, (
                log.get("timestamp"),
                log.get("source"),
                log.get("level"),
                log.get("message")
            ))
            conn.commit()

    def load_logs(self, limit: int = 100) -> List[Dict]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def clear_old_logs(self, days: int = 7):
        """Delete logs older than N days (optional cleanup)"""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM logs WHERE created_at < datetime('now', ?)",
                (f"-{days} days",)
            )
            conn.commit()

    def clear_all_logs(self):
        """Delete all logs from the database"""
        with self._connect() as conn:
            conn.execute("DELETE FROM logs")
            conn.commit()


# Singleton instance
db = Database()