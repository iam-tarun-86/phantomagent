"""Verification test script for Phase 6 Logging Layer"""

import os
import json
import sqlite3
import asyncio
from backend.utils.event_logger import EventLogger
from backend.pipeline.decision_engine import DecisionEngine

async def test_phase6():
    print("=== Starting Phase 6 Logging Layer Verification ===")
    
    test_db = "data/test_phantomagent.db"
    test_jsonl = "data/test_events_dataset.jsonl"
    
    if os.path.exists(test_db): os.remove(test_db)
    if os.path.exists(test_jsonl): os.remove(test_jsonl)

    logger = EventLogger(db_path=test_db, jsonl_path=test_jsonl)

    sample_ip = "172.28.0.10"
    sample_features = {
        "packet_count": 50,
        "syn_count": 50,
        "ack_count": 0,
        "rst_count": 2,
        "unique_dst_ports": 50,
        "bytes_sent": 2900,
        "connection_frequency": 25.0,
        "failed_auth_count": 0
    }
    sample_gnn_score = 0.9985
    sample_verdict = {
        "threat_type": "PORT_SCAN",
        "severity": 7,
        "confidence": 0.95,
        "attack_pattern": "Nmap stealth SYN scan",
        "explanation": "Sequential port scan detected",
        "reason": "High unique destination port count and SYN frequency",
        "mitigation": "iptables -A INPUT -s 172.28.0.10 -j DROP"
    }

    print("\n1. Testing logger.log_event()...")
    record = logger.log_event(
        source_ip=sample_ip,
        features=sample_features,
        gnn_score=sample_gnn_score,
        verdict=sample_verdict,
        action_taken="CONTAIN"
    )
    print("  Event recorded successfully.")

    print("\n2. Verifying JSONL File Output...")
    assert os.path.exists(test_jsonl), "JSONL file was not created"
    with open(test_jsonl, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 1, f"Expected 1 JSONL entry, got {len(lines)}"
        data = json.loads(lines[0])
        assert data["source_ip"] == sample_ip
        assert data["gnn_score"] == sample_gnn_score
        assert data["threat_type"] == "PORT_SCAN"
        print(f"  JSONL Entry Verified: {data['threat_type']} from {data['source_ip']} (GNN: {data['gnn_score']})")

    print("\n3. Verifying SQLite Database Output...")
    assert os.path.exists(test_db), "SQLite DB file was not created"
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT source_ip, gnn_score, threat_type, severity, action_taken, raw_features FROM events_log")
    row = cursor.fetchone()
    conn.close()

    assert row is not None, "SQLite query returned no rows"
    db_ip, db_gnn, db_type, db_sev, db_action, db_features_str = row
    assert db_ip == sample_ip
    assert abs(db_gnn - sample_gnn_score) < 1e-4
    assert db_type == "PORT_SCAN"
    assert db_sev == 7
    assert db_action == "CONTAIN"
    
    db_features = json.loads(db_features_str)
    assert db_features["unique_dst_ports"] == 50

    print(f"  SQLite Row Verified: DB record #{row[0]} -> {db_type} (Sev: {db_sev}, Action: {db_action})")

    # Clean up test artifacts
    if os.path.exists(test_db): os.remove(test_db)
    if os.path.exists(test_jsonl): os.remove(test_jsonl)

    print("\n✅ All Phase 6 Logging Layer checks passed successfully!")

if __name__ == "__main__":
    asyncio.run(test_phase6())
