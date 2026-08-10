"""Verification test script for Phase 4 LLM 'Brain' reasoning engine"""

import asyncio
from backend.pipeline.gemma_engine import GemmaEngine

async def test_phase4():
    print("=== Starting Phase 4 LLM 'Brain' Reasoning Verification ===")
    
    engine = GemmaEngine()
    await engine.initialize()

    test_events = [
        {
            "name": "Benign Traffic Sample",
            "source_ip": "192.168.1.105",
            "gnn_score": 0.0006,
            "features": {
                "packet_count": 5,
                "syn_count": 1,
                "ack_count": 4,
                "rst_count": 0,
                "unique_dst_ports": 1,
                "bytes_sent": 450,
                "connection_frequency": 0.5,
                "failed_auth_count": 0
            }
        },
        {
            "name": "Nmap PortScan Attack Sample",
            "source_ip": "172.28.0.10",
            "gnn_score": 0.9985,
            "features": {
                "packet_count": 45,
                "syn_count": 45,
                "ack_count": 0,
                "rst_count": 2,
                "unique_dst_ports": 45,
                "bytes_sent": 2610,
                "connection_frequency": 22.5,
                "failed_auth_count": 0
            }
        },
        {
            "name": "Zero-Day Attack Sample",
            "source_ip": "10.0.0.188",
            "gnn_score": 0.8920,
            "features": {
                "packet_count": 60,
                "syn_count": 10,
                "ack_count": 10,
                "rst_count": 10,
                "unique_dst_ports": 2,
                "bytes_sent": 45000,
                "connection_frequency": 12.0,
                "failed_auth_count": 1
            }
        }
    ]

    for event_data in test_events:
        print(f"\n--- Testing: {event_data['name']} ---")
        res = await engine.analyze(event_data)
        
        print(f"  Threat Type : {res.get('threat_type')}")
        print(f"  Severity    : {res.get('severity')}/10")
        print(f"  Confidence  : {res.get('confidence')}")
        print(f"  Action      : {res.get('action')}")
        print(f"  Mitigation  : {res.get('mitigation')}")
        print(f"  Explanation : {res.get('explanation')}")
        print(f"  Reasoning   : {res.get('reason')}")
        
        # Schema assertions
        assert "threat_type" in res, "Missing threat_type key"
        assert "confidence" in res, "Missing confidence key"
        assert "severity" in res, "Missing severity key"
        assert "mitigation" in res, "Missing mitigation key"
        assert "explanation" in res, "Missing explanation key"

    print("\n✅ All Phase 4 LLM 'Brain' integration checks passed successfully!")

if __name__ == "__main__":
    asyncio.run(test_phase4())
