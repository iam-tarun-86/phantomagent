import asyncio
from backend.watchers.network_watcher import NetworkWatcher

class MockExtractor:
    def get_features(self, ip):
        return self.mock_features

class MockLogger:
    def log_event(self, **kwargs):
        pass

class MockFeatureExtractor:
    def __init__(self, features):
        self.features = features
    def get_features(self, ip):
        return self.features

class MockWatcher(NetworkWatcher):
    def __init__(self, loop, callback, features):
        super().__init__(loop, callback)
        self.feature_extractor = MockFeatureExtractor(features)
        self.alerts_sent = []
        
    def _dispatch_alert(self, threat_type, severity, src_ip, features, msg):
        self.alerts_sent.append((threat_type, severity))

def test_watcher():
    # Test 1: Nmap Scan (30 packets, 30 unique ports)
    features_scan = {
        'packet_count': 30,
        'unique_dst_ports': 30,
        'syn_count': 30,
        'connection_frequency': 10.0,
        'failed_auth_count': 0
    }
    w1 = MockWatcher(None, lambda x: None, features_scan)
    w1.loop = True
    w1.analyze_connections("172.28.0.10")
    print("Nmap Scan Test (30 packets, 30 ports):", w1.alerts_sent)
    assert len(w1.alerts_sent) > 0 and w1.alerts_sent[0][0] == 'PORT_SCAN'

    # Test 2: DoS Flood (100 packets, 1 unique port)
    features_dos = {
        'packet_count': 100,
        'unique_dst_ports': 1,
        'syn_count': 100,
        'connection_frequency': 30.0,
        'failed_auth_count': 0
    }
    w2 = MockWatcher(None, lambda x: None, features_dos)
    w2.loop = True
    w2.analyze_connections("172.28.0.10")
    print("DoS Flood Test (100 packets, 1 port):", w2.alerts_sent)
    assert len(w2.alerts_sent) > 0 and w2.alerts_sent[0][0] == 'DOS_ATTACK'

    # Test 3: Brute Force (15 packets, 1 unique port, failed auth)
    features_brute = {
        'packet_count': 15,
        'unique_dst_ports': 1,
        'syn_count': 5,
        'connection_frequency': 5.0,
        'failed_auth_count': 5
    }
    w3 = MockWatcher(None, lambda x: None, features_brute)
    w3.loop = True
    w3.analyze_connections("172.28.0.10")
    print("Brute Force Test (15 packets, 1 port, 5 failed auths):", w3.alerts_sent)
    assert len(w3.alerts_sent) > 0 and w3.alerts_sent[0][0] == 'BRUTE_FORCE'
    
    print("All watcher priority tests passed!")

test_watcher()
