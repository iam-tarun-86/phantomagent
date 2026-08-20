"""Database persistence, especially status transitions.

The bug this guards: save_threat() runs once, while a critical threat is still
PENDING_APPROVAL, and nothing wrote back afterwards. Approve, dismiss and the auto
timeout all broadcast to the UI but left the database permanently claiming every
critical threat was awaiting approval.
"""

import pytest

from backend.database import Database


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=tmp_path / "test.db")
    yield database
    database.close()


def make_threat(threat_id="ABC123", status="PENDING_APPROVAL", **overrides):
    threat = {
        "id": threat_id,
        "type": "Port Scan",
        "severity": 9,
        "source_ip": "172.28.0.10",
        "status": status,
        "timestamp": "2026-08-20T09:00:00",
        "raw_log": "nmap scan detected",
        "attack_pattern": "T1046",
        "explanation": "consensus passed",
        "reason": "45 ports probed",
        "confidence": 0.94,
        "indicators": ["45 ports", "200 SYN"],
    }
    threat.update(overrides)
    return threat


# ===== Round trip =====

def test_threat_round_trips(db):
    db.save_threat(make_threat())
    loaded = db.get_threat("ABC123")

    assert loaded["id"] == "ABC123"
    assert loaded["severity"] == 9
    assert loaded["source_ip"] == "172.28.0.10"
    assert loaded["indicators"] == ["45 ports", "200 SYN"]


def test_missing_threat_returns_none(db):
    assert db.get_threat("NOPE") is None


# ===== Status transitions =====

def test_approval_is_persisted(db):
    db.save_threat(make_threat())
    assert db.get_threat("ABC123")["status"] == "PENDING_APPROVAL"

    assert db.update_threat_status("ABC123", "CONTAINED", "Blocked IP: 172.28.0.10") is True

    row = db.get_threat("ABC123")
    assert row["status"] == "CONTAINED"
    assert "Blocked IP" in row["action_taken"]
    assert row["resolved_at"]


def test_dismissal_is_persisted(db):
    db.save_threat(make_threat())
    db.update_threat_status("ABC123", "REJECTED")
    assert db.get_threat("ABC123")["status"] == "REJECTED"


def test_auto_containment_is_persisted(db):
    db.save_threat(make_threat())
    db.update_threat_status("ABC123", "AUTO_CONTAINED", "Blocked IP: 1.2.3.4")
    assert db.get_threat("ABC123")["status"] == "AUTO_CONTAINED"


def test_no_pending_threats_remain_after_resolution(db):
    """The symptom to guard against: everything stuck at PENDING_APPROVAL."""
    for i in range(5):
        db.save_threat(make_threat(threat_id=f"T{i}"))
    for i in range(5):
        db.update_threat_status(f"T{i}", "CONTAINED", "Blocked")

    statuses = {t["status"] for t in db.load_threats()}
    assert statuses == {"CONTAINED"}
    assert "PENDING_APPROVAL" not in statuses


def test_update_of_unknown_threat_reports_failure(db):
    """Returns False rather than silently succeeding, so callers can log it."""
    assert db.update_threat_status("GHOST", "CONTAINED") is False


def test_action_taken_is_preserved_across_later_updates(db):
    db.save_threat(make_threat())
    db.update_threat_status("ABC123", "CONTAINED", "Blocked IP: 1.2.3.4")
    # A later transition with no action must not blank the recorded action.
    db.update_threat_status("ABC123", "APPROVED")

    row = db.get_threat("ABC123")
    assert row["status"] == "APPROVED"
    assert "Blocked IP" in row["action_taken"]


# ===== Logs =====

def test_logs_round_trip(db):
    db.save_log({"timestamp": "2026-08-20 09:00:00", "source": "WATCHER",
                 "level": "INFO", "message": "hello"})
    logs = db.load_logs()
    assert len(logs) == 1
    assert logs[0]["message"] == "hello"


def test_batch_log_insert(db):
    db.save_logs([
        {"timestamp": "t", "source": "S", "level": "INFO", "message": f"m{i}"}
        for i in range(50)
    ])
    assert len(db.load_logs(limit=100)) == 50


def test_empty_batch_is_a_noop(db):
    db.save_logs([])
    assert db.load_logs() == []


def test_clear_all_logs(db):
    db.save_log({"timestamp": "t", "source": "S", "level": "INFO", "message": "m"})
    db.clear_all_logs()
    assert db.load_logs() == []


# ===== Schema / connection =====

def test_wal_mode_is_enabled(db):
    mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_status_index_exists(db):
    names = {r["name"] for r in db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    assert "idx_threats_status" in names


def test_legacy_schema_is_migrated(tmp_path):
    """An existing database predating action_taken/resolved_at must not break."""
    import sqlite3
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE threats (
            id TEXT PRIMARY KEY, type TEXT NOT NULL, severity INTEGER NOT NULL,
            source_ip TEXT NOT NULL, status TEXT NOT NULL, timestamp TEXT NOT NULL,
            raw_log TEXT, attack_pattern TEXT, explanation TEXT, reason TEXT,
            confidence REAL, indicators TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.execute("INSERT INTO threats (id,type,severity,source_ip,status,timestamp) "
                 "VALUES ('OLD','Port Scan',9,'1.2.3.4','PENDING_APPROVAL','t')")
    conn.commit()
    conn.close()

    database = Database(db_path=path)
    try:
        assert database.update_threat_status("OLD", "CONTAINED", "Blocked") is True
        assert database.get_threat("OLD")["status"] == "CONTAINED"
    finally:
        database.close()
