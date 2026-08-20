"""PhantomAgent Database - SQLite persistence layer

Connection handling
-------------------
One long-lived connection guarded by a lock, rather than a fresh connect per call.
The previous version opened a connection for every log line and never closed it --
`with sqlite3.connect(...)` commits on exit but does not close, so connections
accumulated until garbage collection.

WAL mode lets the writer proceed without blocking readers, which matters because the
async event loop and the watcher threads both reach this layer.

All writes are synchronous and must be called via asyncio.to_thread from async code --
see the wrappers in backend/main.py. check_same_thread=False is safe here only because
every access goes through self._lock.
"""

import json
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional

from backend.config import DB_PATH


class Database:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_tables()

    def close(self):
        with self._lock:
            self._conn.close()

    def _init_tables(self):
        with self._lock:
            # Threats table
            self._conn.execute("""
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
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Added in Phase 3: status transitions are written after the fact, so the
            # status column is queried directly.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_threats_created ON threats(created_at DESC)"
            )

            # action_taken records what the responder actually did. Added after the
            # original schema, so existing databases need the column backfilled.
            columns = {
                row["name"]
                for row in self._conn.execute("PRAGMA table_info(threats)").fetchall()
            }
            if "action_taken" not in columns:
                self._conn.execute("ALTER TABLE threats ADD COLUMN action_taken TEXT")
            if "resolved_at" not in columns:
                self._conn.execute("ALTER TABLE threats ADD COLUMN resolved_at TEXT")

            self._conn.commit()

    # ===== THREATS =====

    def save_threat(self, threat: Dict):
        with self._lock:
            self._conn.execute("""
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
            self._conn.commit()

    def update_threat_status(
        self,
        threat_id: str,
        status: str,
        action_taken: Optional[str] = None,
    ) -> bool:
        """
        Record a post-detection status transition (approved, dismissed, contained).

        Without this the database permanently reports every critical threat as
        PENDING_APPROVAL: save_threat() runs once, while the threat is still pending,
        and nothing wrote back after the operator or the timeout resolved it.

        Returns True if a row was updated.
        """
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE threats
                   SET status = ?,
                       action_taken = COALESCE(?, action_taken),
                       resolved_at = ?
                 WHERE id = ?
                """,
                (status, action_taken, datetime.now().isoformat(), threat_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def load_threats(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM threats ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [self._row_to_threat(row) for row in rows]

    def get_threat(self, threat_id: str) -> Optional[Dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM threats WHERE id = ?", (threat_id,)
            ).fetchone()
        return self._row_to_threat(row) if row else None

    def _row_to_threat(self, row: sqlite3.Row) -> Dict:
        keys = row.keys()
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
            "indicators": json.loads(row["indicators"] or "[]"),
            "action_taken": (row["action_taken"] if "action_taken" in keys else None) or "",
            "resolved_at": (row["resolved_at"] if "resolved_at" in keys else None) or "",
        }

    # ===== LOGS =====

    def save_log(self, log: Dict):
        with self._lock:
            self._conn.execute("""
                INSERT INTO logs (timestamp, source, level, message)
                VALUES (?, ?, ?, ?)
            """, (
                log.get("timestamp"),
                log.get("source"),
                log.get("level"),
                log.get("message")
            ))
            self._conn.commit()

    def save_logs(self, logs: List[Dict]):
        """Batch insert — one transaction for many lines instead of one per line."""
        if not logs:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO logs (timestamp, source, level, message) VALUES (?, ?, ?, ?)",
                [
                    (l.get("timestamp"), l.get("source"), l.get("level"), l.get("message"))
                    for l in logs
                ],
            )
            self._conn.commit()

    def load_logs(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM logs ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_old_logs(self, days: int = 7):
        """Delete logs older than N days (optional cleanup)"""
        with self._lock:
            self._conn.execute(
                "DELETE FROM logs WHERE created_at < datetime('now', ?)",
                (f"-{days} days",)
            )
            self._conn.commit()

    def clear_all_logs(self):
        """Delete all logs from the database"""
        with self._lock:
            self._conn.execute("DELETE FROM logs")
            self._conn.commit()


# Singleton instance
db = Database()
