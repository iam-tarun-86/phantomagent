"""End-to-end: resolving a threat through the API must reach the database.

test_database.py proves update_threat_status() works in isolation. This proves the API
endpoints actually call it — the original bug was not a broken query, it was a query
nobody invoked.
"""

import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient

from backend.config import API_TOKEN
from backend.database import db
from backend.main import app, state

AUTH = {"Authorization": f"Bearer {API_TOKEN}"}


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """
    Point the module singleton at a throwaway database.

    main.py does `from backend.database import db`, so the endpoints hold a reference to
    this exact object -- swapping its connection redirects them without touching the
    real data/phantomagent.db.
    """
    real_conn = db._conn
    real_path = db.db_path

    test_conn = sqlite3.connect(str(tmp_path / "test.db"), check_same_thread=False)
    test_conn.row_factory = sqlite3.Row

    db._conn = test_conn
    db.db_path = tmp_path / "test.db"
    db._lock = threading.Lock()
    db._init_tables()

    yield

    test_conn.close()
    db._conn = real_conn
    db.db_path = real_path


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def pending_threat():
    """Register a pending threat in both the DB and the in-memory approval queue."""
    threat_id = "PERSIST1"
    threat = {
        "id": threat_id,
        "type": "Port Scan",
        "severity": 9,
        "source_ip": "172.28.0.10",
        "status": "PENDING_APPROVAL",
        "timestamp": "2026-08-20T09:00:00",
        "raw_log": "nmap",
        "indicators": [],
        "defense_action": {"action": "NONE", "target_ip": ""},
    }
    db.save_threat(threat)
    state.pending_approvals[threat_id] = {
        "threat": threat,
        "decision": {"action": "LOCKDOWN"},
        "timestamp": threat["timestamp"],
    }
    yield threat_id
    state.pending_approvals.pop(threat_id, None)


def test_approve_persists_contained_status(client, pending_threat, monkeypatch):
    async def fake_execute(action, threat):
        return {"success": True, "actions_taken": ["Blocked IP: 172.28.0.10"],
                "forensic_report": None}

    monkeypatch.setattr(state.responder, "execute", fake_execute)

    assert db.get_threat(pending_threat)["status"] == "PENDING_APPROVAL"

    response = client.post(f"/api/threats/{pending_threat}/approve", headers=AUTH)
    assert response.status_code == 200

    row = db.get_threat(pending_threat)
    assert row["status"] == "CONTAINED", "approval never reached the database"
    assert "Blocked IP" in row["action_taken"]


def test_dismiss_persists_rejected_status(client, pending_threat):
    assert db.get_threat(pending_threat)["status"] == "PENDING_APPROVAL"

    response = client.post(f"/api/threats/{pending_threat}/dismiss", headers=AUTH)
    assert response.status_code == 200

    assert db.get_threat(pending_threat)["status"] == "REJECTED"


def test_approve_all_persists_every_threat(client, monkeypatch):
    async def fake_execute(action, threat):
        return {"success": True, "actions_taken": ["Blocked"], "forensic_report": None}

    monkeypatch.setattr(state.responder, "execute", fake_execute)

    ids = [f"BULK{i}" for i in range(3)]
    for tid in ids:
        db.save_threat({"id": tid, "type": "Port Scan", "severity": 9,
                        "source_ip": "10.0.0.1", "status": "PENDING_APPROVAL",
                        "timestamp": "t", "indicators": []})
        state.pending_approvals[tid] = {"threat": {"id": tid, "source_ip": "10.0.0.1"},
                                        "decision": {}, "timestamp": "t"}

    try:
        response = client.post("/api/threats/approve-all", headers=AUTH)
        assert response.status_code == 200

        for tid in ids:
            assert db.get_threat(tid)["status"] == "CONTAINED", f"{tid} not persisted"
    finally:
        for tid in ids:
            state.pending_approvals.pop(tid, None)


def test_unknown_threat_does_not_raise(client):
    """A resolution for a threat with no DB row must log, not crash the request."""
    response = client.post("/api/threats/GHOST999/approve", headers=AUTH)
    assert response.status_code == 200
    assert response.json()["status"] == "NOT_FOUND"
