"""Live end-to-end verification script for Phase 5 Full Pipeline Wiring"""

import asyncio
import time
import json
from backend.watchers.network_watcher import NetworkWatcher
from backend.pipeline.decision_engine import DecisionEngine

async def test_full_pipeline():
    print("=== Starting Phase 5 Full Pipeline Live Verification (20s Window) ===")
    decision_engine = DecisionEngine()
    
    events_captured = []

    async def pipeline_callback(raw_event):
        print(f"\n[PIPELINE INTERCEPTOR] Raw Event Received from Scapy Watcher!")
        print(f"  Source IP : {raw_event.get('source_ip')}")
        print(f"  Type      : {raw_event.get('type')}")
        
        result = await decision_engine.analyze_and_route(raw_event)
        analysis = result['analysis']
        decision = result['decision']
        gnn_score = result['gnn_score']

        print(f"\n[PIPELINE OUTPUT VERDICT]")
        print(f"  GNN Anomaly Score : {gnn_score:.4f}")
        print(f"  Gemma Threat Type : {analysis.get('threat_type')}")
        print(f"  Severity          : {analysis.get('severity')}/10")
        print(f"  Action            : {decision.get('action')}")
        print(f"  Mitigation        : {analysis.get('mitigation')}")
        print(f"  Reasoning         : {analysis.get('reason')}")

        events_captured.append((analysis, decision))

    watcher = NetworkWatcher(callback=pipeline_callback)
    await watcher.start()

    print("\nLive network watcher active. Run attacks from Kali container now.")
    for i in range(20):
        await asyncio.sleep(1)

    await watcher.stop()

    if events_captured:
        print(f"\n✅ Phase 5 Verification Complete! Total live alerts processed by full pipeline: {len(events_captured)}")
    else:
        print("\n⚠️ No alerts triggered in 20s window.")

if __name__ == "__main__":
    asyncio.run(test_full_pipeline())
