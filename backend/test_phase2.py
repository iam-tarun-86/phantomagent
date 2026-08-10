"""Verification script for Phase 2: Live packet capture and feature extraction"""

import asyncio
import time
from backend.watchers.network_watcher import NetworkWatcher

async def main():
    print("=== Starting Phase 2 Packet Capture Verification (15 seconds) ===")
    
    async def sample_callback(event):
        print(f"\n[ALERT TRIGGERED] Source: {event['source_ip']} | Type: {event['type']}")
        print(f"Features: {event['features']}")

    watcher = NetworkWatcher(callback=sample_callback)
    await watcher.start()
    
    print("Listening for packets... Run ping/curl/nmap in another terminal now.")
    for i in range(15):
        await asyncio.sleep(1)
        features = watcher.feature_extractor.get_features("172.28.0.10")
        if features['packet_count'] > 0:
            print(f"[Stats @ t+{i+1}s for 172.28.0.10] Packets: {features['packet_count']} | Unique Ports: {features['unique_dst_ports']} | SYN: {features['syn_count']} | Bytes: {features['bytes_sent']}")
            
    await watcher.stop()
    print("=== Verification Complete ===")

if __name__ == "__main__":
    asyncio.run(main())
