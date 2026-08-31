"""PyTorch GraphSAGE Neural Network for Network Anomaly Detection with pure Python fallback"""

import os
import math
from pathlib import Path
from backend.config import BASE_DIR

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    nn = None
    F = None

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

CHECKPOINT_VERSION = 3
DEFAULT_MODEL_PATH = BASE_DIR / "models" / "gnn_phantom.pt"


if TORCH_AVAILABLE:
    class GraphSAGEAnomalyModel(nn.Module):
        """
        GraphSAGE anomaly scorer over a host communication graph.
        """
        def __init__(self, in_features: int = 7, hidden_dim: int = 32):
            super().__init__()
            self.fc1 = nn.Linear(in_features, hidden_dim)
            self.sage = nn.Linear(hidden_dim * 2, hidden_dim)
            self.fc2 = nn.Linear(hidden_dim, 16)
            self.out = nn.Linear(16, 1)
            self.dropout = nn.Dropout(0.2)

        def forward(self, x, adj_matrix=None):
            h = F.relu(self.fc1(x))
            h = self.dropout(h)

            if adj_matrix is not None:
                neighbor_agg = torch.matmul(adj_matrix, h)
            else:
                neighbor_agg = torch.zeros_like(h)

            h = F.relu(self.sage(torch.cat([h, neighbor_agg], dim=-1)))
            h = F.relu(self.fc2(h))
            score = torch.sigmoid(self.out(h))
            return score
else:
    class GraphSAGEAnomalyModel:
        pass


def build_adjacency(num_nodes: int, edges):
    """Row-normalized adjacency (mean aggregator), treated as undirected."""
    if not TORCH_AVAILABLE:
        return None
    adj = torch.zeros((num_nodes, num_nodes), dtype=torch.float32)
    for a, b in edges:
        if 0 <= a < num_nodes and 0 <= b < num_nodes and a != b:
            adj[a, b] = 1.0
            adj[b, a] = 1.0

    degree = adj.sum(dim=1, keepdim=True)
    degree[degree == 0] = 1.0
    return adj / degree


class GNNPredictor:
    """Inference helper to load saved GNN model and predict anomaly score from live feature dict"""

    FEATURE_KEYS = [
        'syn_count', 'ack_count', 'rst_count',
        'unique_dst_ports', 'bytes_sent', 'connection_frequency', 'failed_auth_count'
    ]

    MEANS = [15.0, 8.0, 2.0, 10.0, 2500.0, 12.0, 1.5]
    STDS = [45.0, 15.0, 5.0, 25.0, 8000.0, 30.0, 5.0]

    def __init__(self, model_path: str = None):
        self.model_path = str(model_path or DEFAULT_MODEL_PATH)
        self.model = None
        self.means = list(self.MEANS)
        self.stds = list(self.STDS)
        
        if TORCH_AVAILABLE:
            self.model = GraphSAGEAnomalyModel()
            if os.path.exists(self.model_path):
                try:
                    self._load_checkpoint()
                except Exception as e:
                    print(f"[GNN] Failed to load model weights from {self.model_path}: {e}")
            else:
                print(f"[GNN] Warning: Model file '{self.model_path}' not found. Using untrained weights.")
            self.model.eval()
        else:
            print("[GNN] PyTorch/NumPy not installed. Using rule-weighted heuristic anomaly scoring.")

    def _load_checkpoint(self):
        checkpoint = torch.load(self.model_path, weights_only=True, map_location="cpu")
        if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
            self.model.load_state_dict(checkpoint["state_dict"])
            if "means" in checkpoint and "stds" in checkpoint:
                self.means = list(checkpoint["means"])
                self.stds = list(checkpoint["stds"])
            print(f"[GNN] Loaded trained weights + stats from '{self.model_path}'")
        else:
            self.model.load_state_dict(checkpoint)
            print(f"[GNN] Loaded legacy weights from '{self.model_path}'")

    def predict_anomaly_score(self, feature_dict: dict) -> float:
        """
        Input: feature dictionary from FeatureExtractor
        Output: Anomaly score float between 0.0 and 1.0
        """
        raw_vals = [float(feature_dict.get(k, 0)) for k in self.FEATURE_KEYS]

        if not TORCH_AVAILABLE or self.model is None:
            norm_vals = [(raw - m) / (s + 1e-6) for raw, m, s in zip(raw_vals, self.means, self.stds)]
            pos_norms = [max(0.0, v) for v in norm_vals]
            z_score = sum(pos_norms) / max(1, len(pos_norms))
            score = 1.0 / (1.0 + math.exp(-z_score))
            return round(float(score), 4)

        if NUMPY_AVAILABLE:
            raw_arr = np.array(raw_vals, dtype=np.float32)
            means_arr = np.array(self.means, dtype=np.float32)
            stds_arr = np.array(self.stds, dtype=np.float32)
            norm_arr = (raw_arr - means_arr) / (stds_arr + 1e-6)
            tensor_x = torch.tensor(norm_arr, dtype=torch.float32).unsqueeze(0)
        else:
            norm_vals = [(raw - m) / (s + 1e-6) for raw, m, s in zip(raw_vals, self.means, self.stds)]
            tensor_x = torch.tensor(norm_vals, dtype=torch.float32).unsqueeze(0)

        with torch.no_grad():
            score_tensor = self.model(tensor_x)
            score = float(score_tensor.squeeze().item())

        return round(score, 4)

    def predict_graph_scores(self, snapshot: dict) -> dict:
        """Score every host in a communication graph in one pass."""
        nodes = snapshot.get("nodes") or []
        if not nodes:
            return {}

        if not TORCH_AVAILABLE or self.model is None:
            return {ip: self.predict_anomaly_score(f) for ip, f in zip(nodes, snapshot.get("features", []))}

        features = snapshot.get("features") or []
        if NUMPY_AVAILABLE:
            x = np.stack([
                (np.array([float(f.get(k, 0)) for k in self.FEATURE_KEYS], dtype=np.float32) - np.array(self.means, dtype=np.float32)) / (np.array(self.stds, dtype=np.float32) + 1e-6)
                for f in features
            ])
            tensor_x = torch.tensor(x, dtype=torch.float32)
        else:
            norm_feats = [
                [(float(f.get(k, 0)) - m) / (s + 1e-6) for k, m, s in zip(self.FEATURE_KEYS, self.means, self.stds)]
                for f in features
            ]
            tensor_x = torch.tensor(norm_feats, dtype=torch.float32)

        edges = snapshot.get("edges") or []
        adj = build_adjacency(len(nodes), edges) if edges else None

        with torch.no_grad():
            scores = self.model(tensor_x, adj).squeeze(-1).tolist()

        if isinstance(scores, float):
            scores = [scores]

        return {ip: round(float(sc), 4) for ip, sc in zip(nodes, scores)}
