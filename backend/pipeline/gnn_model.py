"""PyTorch GraphSAGE Neural Network for Network Anomaly Detection"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

class GraphSAGEAnomalyModel(nn.Module):
    """
    Graph Neural Network model (GraphSAGE-style aggregation)
    node_features: [syn_count, ack_count, rst_count, unique_dst_ports, bytes_sent, connection_frequency, failed_auth_count]
    """
    def __init__(self, in_features: int = 7, hidden_dim: int = 32):
        super().__init__()
        # Layer 1: Local Feature Aggregation (Self + Neighbor Graph Embedding)
        self.fc1 = nn.Linear(in_features, hidden_dim)
        self.gnn_layer = nn.Linear(hidden_dim, hidden_dim)
        
        # Layer 2: Graph Context & Anomaly Score Head
        self.fc2 = nn.Linear(hidden_dim, 16)
        self.out = nn.Linear(16, 1)
        
        self.dropout = nn.Dropout(0.2)

    def forward(self, x, adj_matrix=None):
        """
        x: [batch_size, in_features]
        adj_matrix: optional adjacency matrix for graph neighborhood message passing
        """
        h = F.relu(self.fc1(x))
        h = self.dropout(h)

        if adj_matrix is not None:
            # Message passing: Aggregate neighbor node embeddings
            neighbor_agg = torch.matmul(adj_matrix, h)
            h = F.relu(self.gnn_layer(neighbor_agg))
        else:
            h = F.relu(self.gnn_layer(h))

        h = F.relu(self.fc2(h))
        # Anomaly score between 0.0 and 1.0 (Sigmoid)
        score = torch.sigmoid(self.out(h))
        return score


class GNNPredictor:
    """Inference helper to load saved GNN model and predict anomaly score from live feature dict"""

    FEATURE_KEYS = [
        'syn_count', 'ack_count', 'rst_count',
        'unique_dst_ports', 'bytes_sent', 'connection_frequency', 'failed_auth_count'
    ]

    # Normalization mean/std values computed during CICIDS2017 training
    MEANS = np.array([15.0, 8.0, 2.0, 10.0, 2500.0, 12.0, 1.5], dtype=np.float32)
    STDS = np.array([45.0, 15.0, 5.0, 25.0, 8000.0, 30.0, 5.0], dtype=np.float32)

    def __init__(self, model_path: str = "backend/models/gnn_cicids2017.pt"):
        self.model = GraphSAGEAnomalyModel()
        self.model_path = model_path
        
        if os.path.exists(model_path):
            try:
                self.model.load_state_dict(torch.load(model_path, weights_only=True))
                print(f"[GNN] Successfully loaded trained weights from '{model_path}'")
            except Exception as e:
                print(f"[GNN] Failed to load model weights from {model_path}: {e}")
        else:
            print(f"[GNN] Warning: Model file '{model_path}' not found. Using untrained weights.")

        self.model.eval()

    def predict_anomaly_score(self, feature_dict: dict) -> float:
        """
        Input: feature dictionary from FeatureExtractor
        Output: Anomaly score float between 0.0 and 1.0
        """
        raw_vals = [float(feature_dict.get(k, 0)) for k in self.FEATURE_KEYS]
        raw_arr = np.array(raw_vals, dtype=np.float32)

        # Z-score normalization
        norm_arr = (raw_arr - self.MEANS) / (self.STDS + 1e-6)

        tensor_x = torch.tensor(norm_arr, dtype=torch.float32).unsqueeze(0)

        with torch.no_grad():
            score_tensor = self.model(tensor_x)
            score = float(score_tensor.squeeze().item())

        return round(score, 4)
