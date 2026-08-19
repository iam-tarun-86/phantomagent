import asyncio
import json
from backend.pipeline.decision_engine import DecisionEngine

async def verify_system():
    de = DecisionEngine()
    
    # Wait for Gemma engine to initialize
    await de.gemma.initialize()
    print("Gemma Available:", de.gemma.is_available)
    
    # 1. Test Port Scan Event (should be contained)
    event_scan = {
        'source_ip': '172.28.0.10',
        'type': 'PORT_SCAN',
        'severity': 6,
        'features': {
            'packet_count': 30,
            'unique_dst_ports': 30,  # 30 unique ports => Port Scan!
            'syn_count': 30,
            'connection_frequency': 10.0,
            'failed_auth_count': 0
        }
    }
    
    print("\n--- Testing PORT_SCAN Event ---")
    result1 = await de.analyze_and_route(event_scan)
    print("Threat Type:", result1['analysis']['threat_type'])
    print("Severity:", result1['analysis']['severity'])
    print("Action:", result1['decision']['action'])
    print("Reason:", result1['analysis'].get('reason', 'N/A'))
    
    # 2. Test DoS Event (should be lockdown)
    event_dos = {
        'source_ip': '172.28.0.20',
        'type': 'DOS_ATTACK',
        'severity': 8,
        'features': {
            'packet_count': 150,
            'unique_dst_ports': 1,  # 1 port => DoS!
            'syn_count': 150,
            'connection_frequency': 40.0,
            'failed_auth_count': 0
        }
    }
    
    print("\n--- Testing DOS_ATTACK Event ---")
    result2 = await de.analyze_and_route(event_dos)
    print("Threat Type:", result2['analysis']['threat_type'])
    print("Severity:", result2['analysis']['severity'])
    print("Action:", result2['decision']['action'])
    print("Reason:", result2['analysis'].get('reason', 'N/A'))
    
    print("\n✅ E2E Verification Complete!")

if __name__ == "__main__":
    asyncio.run(verify_system())
