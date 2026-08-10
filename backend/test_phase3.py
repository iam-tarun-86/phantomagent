"""Verification test script for Phase 3 standalone GNN inference"""

from backend.pipeline.gnn_model import GNNPredictor

def test_inference():
    print("=== Starting Phase 3 GNN Inference Verification ===")
    predictor = GNNPredictor()

    benign_sample = {
        'syn_count': 1,
        'ack_count': 5,
        'rst_count': 0,
        'unique_dst_ports': 1,
        'bytes_sent': 350,
        'connection_frequency': 0.5,
        'failed_auth_count': 0
    }

    portscan_sample = {
        'syn_count': 45,
        'ack_count': 1,
        'rst_count': 2,
        'unique_dst_ports': 45,
        'bytes_sent': 1800,
        'connection_frequency': 25.0,
        'failed_auth_count': 0
    }

    dos_sample = {
        'syn_count': 250,
        'ack_count': 5,
        'rst_count': 1,
        'unique_dst_ports': 2,
        'bytes_sent': 25000,
        'connection_frequency': 120.0,
        'failed_auth_count': 0
    }

    score_benign = predictor.predict_anomaly_score(benign_sample)
    score_scan = predictor.predict_anomaly_score(portscan_sample)
    score_dos = predictor.predict_anomaly_score(dos_sample)

    print(f"\n[RESULTS]")
    print(f"  Benign Traffic Sample  -> Anomaly Score: {score_benign:.4f}")
    print(f"  PortScan Attack Sample -> Anomaly Score: {score_scan:.4f}")
    print(f"  DoS Attack Sample      -> Anomaly Score: {score_dos:.4f}")

    assert 0.0 <= score_benign <= 1.0, f"Score out of bounds: {score_benign}"
    assert 0.0 <= score_scan <= 1.0, f"Score out of bounds: {score_scan}"
    assert 0.0 <= score_dos <= 1.0, f"Score out of bounds: {score_dos}"
    assert score_scan > 0.7, f"PortScan anomaly score expected high (>0.7), got {score_scan}"
    assert score_dos > 0.7, f"DoS anomaly score expected high (>0.7), got {score_dos}"

    print("\n✅ All GNN inference checks passed successfully!")

if __name__ == "__main__":
    test_inference()
