"""PyTorch GraphSAGE Neural Network for Network Anomaly Detection"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

from backend.config import BASE_DIR

# Bumped when the checkpoint format changes.
#   v1  bare state_dict
#   v2  + normalization statistics
#   v3  + real neighbourhood aggregation (sage layer input is 2*hidden, so v2 weights
#       are structurally incompatible and must be retrained)
CHECKPOINT_VERSION = 3

DEFAULT_MODEL_PATH = BASE_DIR / "models" / "gnn_phantom.pt"


class GraphSAGEAnomalyModel(nn.Module):
    """
    GraphSAGE anomaly scorer over a host communication graph.

    Nodes are IP addresses observed in a time window; edges are "A sent packets to B".
    Node features are the 7 per-host flow statistics.

    Why a graph and not an MLP: several attack patterns are invisible in any single
    host's scalar features but obvious in the structure. A horizontal port scan is a
    fan-out star; lateral movement is a chain of hosts each contacting the next; a
    botnet is many sources converging on one destination. Message passing lets each
    node's score depend on who it is talking to, not just on its own counters.

    Aggregation follows GraphSAGE: the layer sees the node's own embedding concatenated
    with the mean of its neighbours', rather than the neighbour mean alone -- keeping
    self-information is what lets an isolated benign host still score correctly.
    """
    def __init__(self, in_features: int = 7, hidden_dim: int = 32):
        super().__init__()
        # Layer 1: per-node encoding
        self.fc1 = nn.Linear(in_features, hidden_dim)

        # Layer 2: GraphSAGE aggregation over [self_embedding ; neighbour_mean]
        self.sage = nn.Linear(hidden_dim * 2, hidden_dim)

        # Head
        self.fc2 = nn.Linear(hidden_dim, 16)
        self.out = nn.Linear(16, 1)

        self.dropout = nn.Dropout(0.2)

    def forward(self, x, adj_matrix=None):
        """
        x:          [num_nodes, in_features]
        adj_matrix: [num_nodes, num_nodes] row-normalized, WITHOUT self-loops
                    (self-information enters through the concatenation instead).
                    None means every node is isolated -- neighbour mean is zero.
        """
        h = F.relu(self.fc1(x))
        h = self.dropout(h)

        if adj_matrix is not None:
            neighbor_agg = torch.matmul(adj_matrix, h)
        else:
            # No graph context: an isolated node has no neighbours to aggregate.
            neighbor_agg = torch.zeros_like(h)

        h = F.relu(self.sage(torch.cat([h, neighbor_agg], dim=-1)))

        h = F.relu(self.fc2(h))
        # Anomaly score between 0.0 and 1.0 (Sigmoid)
        score = torch.sigmoid(self.out(h))
        return score


def build_adjacency(num_nodes: int, edges) -> "torch.Tensor":
    """
    Row-normalized adjacency (mean aggregator), treated as undirected.

    Communication is evidence of a relationship in both directions: a scanned host is
    just as structurally implicated as the scanner. Rows with no neighbours stay zero,
    which the concatenation above handles.
    """
    adj = torch.zeros((num_nodes, num_nodes), dtype=torch.float32)
    for a, b in edges:
        if 0 <= a < num_nodes and 0 <= b < num_nodes and a != b:
            adj[a, b] = 1.0
            adj[b, a] = 1.0

    degree = adj.sum(dim=1, keepdim=True)
    degree[degree == 0] = 1.0
    return adj / degree


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
        Score a single host with no graph context (isolated node).

        Kept for callers that only have one host's features. Prefer
        predict_graph_scores() where the communication graph is available -- structural
        patterns like scan fan-out are invisible to this path by construction.
        """
        norm_arr = self.normalize(feature_dict)
        tensor_x = torch.tensor(norm_arr, dtype=torch.float32).unsqueeze(0)

        with torch.no_grad():
            score_tensor = self.model(tensor_x)
            score = float(score_tensor.squeeze().item())

        return round(score, 4)

    def predict_graph_scores(self, snapshot: dict) -> dict:
        """
        Score every host in a communication graph in one pass.

        snapshot: {"nodes": [ip, ...], "features": [featdict, ...], "edges": [(i, j), ...]}
                  as produced by FeatureExtractor.get_graph_snapshot()

        Returns {ip: score}. Each score reflects both the host's own flow statistics and
        the structure of its neighbourhood.
        """
        nodes = snapshot.get("nodes") or []
        if not nodes:
            return {}

        features = snapshot.get("features") or []
        x = np.stack([self.normalize(f) for f in features])
        tensor_x = torch.tensor(x, dtype=torch.float32)

        edges = snapshot.get("edges") or []
        adj = build_adjacency(len(nodes), edges) if edges else None

        with torch.no_grad():
            scores = self.model(tensor_x, adj).squeeze(-1).tolist()

        if isinstance(scores, float):  # single-node graph
            scores = [scores]

        return {ip: round(float(sc), 4) for ip, sc in zip(nodes, scores)}
