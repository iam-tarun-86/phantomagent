"""PyTorch GraphSAGE Neural Network for Network Anomaly Detection"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

from backend.config import BASE_DIR

# Bumped when the checkpoint format changes. v2 carries normalization statistics
# alongside the weights; v1 was a bare state_dict.
CHECKPOINT_VERSION = 2

DEFAULT_MODEL_PATH = BASE_DIR / "models" / "gnn_cicids2017.pt"


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
    """
    Inference helper: loads the trained GNN and scores a live feature dict.

    Normalization statistics travel *with* the weights in the checkpoint. They must be
    the ones computed on the training set — normalizing inference inputs with different
    statistics feeds the network differently-scaled data than it was fit on, which shifts
    scores by up to 0.7 in the mid-range and silently flips consensus votes.
    """

    FEATURE_KEYS = [
        'syn_count', 'ack_count', 'rst_count',
        'unique_dst_ports', 'bytes_sent', 'connection_frequency', 'failed_auth_count'
    ]

    # Legacy fallback only — used when a v1 (bare state_dict) checkpoint is loaded.
    # These do NOT match the current training set and exist purely so an old model file
    # degrades loudly rather than crashing. Retrain to replace them.
    LEGACY_MEANS = np.array([15.0, 8.0, 2.0, 10.0, 2500.0, 12.0, 1.5], dtype=np.float32)
    LEGACY_STDS = np.array([45.0, 15.0, 5.0, 25.0, 8000.0, 30.0, 5.0], dtype=np.float32)

    def __init__(self, model_path: str | None = None):
        self.model = GraphSAGEAnomalyModel()
        self.model_path = str(model_path or DEFAULT_MODEL_PATH)
        self.means = self.LEGACY_MEANS.copy()
        self.stds = self.LEGACY_STDS.copy()
        self.stats_source = "legacy-fallback"

        if os.path.exists(self.model_path):
            try:
                self._load_checkpoint()
            except Exception as e:
                print(
                    f"[GNN] CRITICAL: failed to load '{self.model_path}': {e}\n"
                    f"[GNN] Running on UNTRAINED weights — every anomaly score is meaningless. "
                    f"Retrain with backend/scripts/train_gnn.py."
                )
        else:
            print(f"[GNN] Warning: Model file '{self.model_path}' not found. Using untrained weights.")

        self.model.eval()

    def _load_checkpoint(self):
        checkpoint = torch.load(self.model_path, weights_only=True, map_location="cpu")

        # v1 format: a bare state_dict with no normalization statistics.
        if not isinstance(checkpoint, dict) or "state_dict" not in checkpoint:
            self.model.load_state_dict(checkpoint)
            print(
                f"[GNN] WARNING: '{self.model_path}' is a legacy v1 checkpoint with no "
                f"normalization statistics. Falling back to hardcoded values that do NOT "
                f"match the training set — anomaly scores will be unreliable. "
                f"Retrain with backend/scripts/train_gnn.py to fix."
            )
            return

        saved_keys = checkpoint.get("feature_keys")
        if saved_keys and list(saved_keys) != self.FEATURE_KEYS:
            raise ValueError(
                f"Checkpoint feature order does not match FEATURE_KEYS.\n"
                f"  checkpoint: {list(saved_keys)}\n"
                f"  expected:   {self.FEATURE_KEYS}\n"
                f"Scoring with mismatched columns would silently produce garbage."
            )

        self.model.load_state_dict(checkpoint["state_dict"])
        self.means = np.asarray(checkpoint["means"], dtype=np.float32)
        self.stds = np.asarray(checkpoint["stds"], dtype=np.float32)
        self.stats_source = f"checkpoint-v{checkpoint.get('version', '?')}"

        print(
            f"[GNN] Loaded trained weights + normalization stats from "
            f"'{self.model_path}' ({self.stats_source})"
        )

    def normalize(self, feature_dict: dict) -> np.ndarray:
        """Z-score normalize a feature dict using the checkpoint's training statistics."""
        raw_vals = [float(feature_dict.get(k, 0)) for k in self.FEATURE_KEYS]
        raw_arr = np.array(raw_vals, dtype=np.float32)
        return (raw_arr - self.means) / (self.stds + 1e-6)

    def predict_anomaly_score(self, feature_dict: dict) -> float:
        """
        Input: feature dictionary from FeatureExtractor
        Output: Anomaly score float between 0.0 and 1.0
        """
        norm_arr = self.normalize(feature_dict)
        tensor_x = torch.tensor(norm_arr, dtype=torch.float32).unsqueeze(0)

        with torch.no_grad():
            score_tensor = self.model(tensor_x)
            score = float(score_tensor.squeeze().item())

        return round(score, 4)
