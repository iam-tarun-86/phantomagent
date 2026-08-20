"""Ablation study: does each component actually earn its place?

Two questions, answered by measurement rather than assertion:

  1. Does message passing matter, or would an MLP on the same features do just as well?
     Trains the identical architecture with and without the adjacency matrix.

  2. Does each consensus-gate signal matter, or is one carrying the others?
     Removes one signal at a time and counts what changes.

Run:  PYTHONPATH=. backend/venv/bin/python backend/scripts/ablation.py
"""

import json

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score

from backend.pipeline.gnn_model import GNNPredictor, GraphSAGEAnomalyModel, build_adjacency
from backend.scripts.train_gnn import (
    BATCH_WINDOWS,
    EPOCHS,
    GRAPH_DATASET_PATH,
    HELD_OUT_SCENARIO,
    LEARNING_RATE,
    batch_windows,
    load_windows,
)


def train_variant(train_w, means, stds, use_graph: bool, seed: int = 42):
    """Train the same architecture with message passing on or off."""
    torch.manual_seed(seed)
    np.random.seed(seed)

    model = GraphSAGEAnomalyModel(in_features=len(GNNPredictor.FEATURE_KEYS))
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    criterion = nn.BCELoss(reduction="none")

    n_pos = sum(sum(w["labels"]) for w in train_w)
    n_neg = sum(len(w["labels"]) for w in train_w) - n_pos
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)], dtype=torch.float32)

    order = list(train_w)
    for _ in range(EPOCHS):
        model.train()
        np.random.shuffle(order)
        for i in range(0, len(order), BATCH_WINDOWS):
            x, y, adj = batch_windows(order[i:i + BATCH_WINDOWS], means, stds)
            optimizer.zero_grad()
            preds = model(x, adj if use_graph else None).clamp(1e-7, 1 - 1e-7)
            weights = torch.where(y > 0.5, pos_weight, torch.ones_like(y))
            (criterion(preds, y) * weights).mean().backward()
            optimizer.step()
    return model


def score(model, windows, means, stds, use_graph: bool):
    model.eval()
    scores, labels = [], []
    with torch.no_grad():
        for i in range(0, len(windows), BATCH_WINDOWS):
            x, y, adj = batch_windows(windows[i:i + BATCH_WINDOWS], means, stds)
            preds = model(x, adj if use_graph else None).squeeze(-1).numpy()
            scores.extend(np.atleast_1d(preds).tolist())
            labels.extend(y.squeeze(-1).numpy().tolist())
    return np.array(scores), np.array(labels)


def metrics(scores, labels):
    preds = (scores > 0.5).astype(np.float32)
    benign = labels == 0
    return {
        "precision": precision_score(labels, preds, zero_division=0),
        "recall": recall_score(labels, preds, zero_division=0),
        "f1": f1_score(labels, preds, zero_division=0),
        "roc_auc": roc_auc_score(labels, scores) if len(set(labels)) > 1 else float("nan"),
        "pr_auc": average_precision_score(labels, scores) if len(set(labels)) > 1 else float("nan"),
        "fp": int(((preds == 1) & benign).sum()),
        "n_benign": int(benign.sum()),
    }


def scenario_subset(windows, scenario):
    return [w for w in windows if w["scenario"] in ("BENIGN", scenario)]


def model_ablation():
    windows = load_windows(GRAPH_DATASET_PATH)
    held_out = [w for w in windows if w["scenario"] == HELD_OUT_SCENARIO]
    usable = [w for w in windows if w["scenario"] != HELD_OUT_SCENARIO]

    split = int(len(usable) * 0.8)
    train_w, test_w = usable[:split], usable[split:]

    train_feats = np.asarray([f for w in train_w for f in w["features"]], dtype=np.float32)
    means, stds = train_feats.mean(axis=0), train_feats.std(axis=0)

    print("=" * 78)
    print("ABLATION 1 — does message passing matter?")
    print("Same architecture, same data, same seed. Only the adjacency matrix differs.")
    print("=" * 78)

    results = {}
    for label, use_graph in [("GNN  (message passing)", True), ("MLP  (no graph)", False)]:
        model = train_variant(train_w, means, stds, use_graph)
        s, y = score(model, test_w, means, stds, use_graph)
        m = metrics(s, y)

        # Port scan in isolation: a scanner and a benign monitoring agent have identical
        # scalar features by construction, so this is the case only topology can settle.
        s_ps, y_ps = score(model, scenario_subset(test_w, "PortScan"), means, stds, use_graph)
        m_ps = metrics(s_ps, y_ps)

        zs, zy = score(model, held_out, means, stds, use_graph)
        zd_recall = float((zs[zy == 1] > 0.5).mean()) if (zy == 1).any() else 0.0

        results[label] = (m, m_ps, zd_recall)

    print(f"\n{'variant':<26}{'F1':>8}{'Prec':>8}{'Recall':>8}{'PR-AUC':>9}{'FPs':>7}")
    print("-" * 78)
    for label, (m, _, _) in results.items():
        print(f"{label:<26}{m['f1']:>8.4f}{m['precision']:>8.4f}{m['recall']:>8.4f}"
              f"{m['pr_auc']:>9.4f}{m['fp']:>7}")

    print(f"\nPort-scan windows only (scanner vs benign monitoring agent — identical features):")
    print(f"{'variant':<26}{'F1':>8}{'Prec':>8}{'Recall':>8}{'FPs':>7}")
    print("-" * 78)
    for label, (_, m_ps, _) in results.items():
        print(f"{label:<26}{m_ps['f1']:>8.4f}{m_ps['precision']:>8.4f}"
              f"{m_ps['recall']:>8.4f}{m_ps['fp']:>7}")

    print(f"\nHeld-out zero-day ('{HELD_OUT_SCENARIO}', never trained on):")
    for label, (_, _, zd) in results.items():
        print(f"  {label:<26}recall {zd * 100:>6.2f}%")

    return results


def consensus_ablation():
    """Remove one consensus signal at a time and count what changes."""
    from backend.pipeline.consensus_gate import ConsensusGate

    BENIGN = {"packet_count": 3, "syn_count": 2, "ack_count": 5, "rst_count": 0,
              "unique_dst_ports": 1, "bytes_sent": 900, "connection_frequency": 0.7,
              "failed_auth_count": 0}
    SCAN = {"packet_count": 220, "syn_count": 200, "ack_count": 2, "rst_count": 60,
            "unique_dst_ports": 45, "bytes_sent": 13200, "connection_frequency": 44.0,
            "failed_auth_count": 0}

    cases = (
        [({"source_ip": f"10.1.0.{i}", "type": "UNKNOWN", "raw_log": "GET / HTTP/1.1 200",
           "features": BENIGN}, 0.02, 0) for i in range(40)]
        + [({"source_ip": f"10.2.0.{i}", "type": "PORT_SCAN", "raw_log": "scan",
             "features": SCAN}, 0.97, 1) for i in range(20)]
        # The hard case: GNN screams but nothing corroborates it.
        + [({"source_ip": f"10.3.0.{i}", "type": "UNKNOWN", "raw_log": "GET / HTTP/1.1 200",
             "features": BENIGN}, 0.99, 0) for i in range(20)]
    )

    print("\n" + "=" * 78)
    print("ABLATION 2 — does each consensus signal matter?")
    print("80 events: 40 benign, 20 real scans, 20 benign with a false-alarming GNN.")
    print("=" * 78)

    SIGNALS = ["gnn_structural", "conformal_pvalue", "behavioral_zscore",
               "payload_entropy", "killchain_campaign"]

    def run(disabled=None, flat_vote=False):
        gate = ConsensusGate()
        tp = fp = fn = 0
        for event, gnn, truth in cases:
            res = gate.evaluate(dict(event), gnn)
            votes = dict(res["vote_breakdown"])
            if disabled:
                votes[disabled] = False

            if flat_vote:
                # The pre-Phase-2 rule: any 3 of 5 signals, treating the GNN score and
                # its own conformal p-value as if they were independent evidence.
                fired = sum(1 for v in votes.values() if v) >= 3
            elif disabled:
                structural = any(votes[s] for s in ("gnn_structural", "conformal_pvalue"))
                independent = [s for s in ("behavioral_zscore", "payload_entropy",
                                           "killchain_campaign") if votes[s]]
                fired = (len(independent) + (1 if structural else 0)) >= 2 and independent
            else:
                fired = res["has_consensus"]

            if fired and truth:
                tp += 1
            elif fired and not truth:
                fp += 1
            elif not fired and truth:
                fn += 1
        return tp, fp, fn

    print(f"\n{'configuration':<34}{'detected':>10}{'false alarms':>15}{'missed':>9}")
    print("-" * 78)
    tp, fp, fn = run(flat_vote=True)
    print(f"{'flat 3-of-5 vote (pre-Phase-2)':<34}{tp:>10}{fp:>15}{fn:>9}")
    tp, fp, fn = run()
    print(f"{'evidence-source rule (current)':<34}{tp:>10}{fp:>15}{fn:>9}")
    for sig in SIGNALS:
        tp, fp, fn = run(disabled=sig)
        print(f"{'  without ' + sig:<34}{tp:>10}{fp:>15}{fn:>9}")

    print("\nNote: 'false alarms' counts benign events that reached consensus. The 20")
    print("GNN-false-alarm events are the ones a flat 3-of-5 vote used to let through.")


def gate_rule_comparison():
    """
    Enumerate all 32 vote combinations under each candidate gate rule.

    Hand-built scenarios can flatter a rule by accident; enumeration cannot. This is how
    the claim "the evidence-source rule is a correctness fix, not a tightening" was
    checked -- and it is how the earlier, stronger claim was found to be wrong.
    """
    from itertools import product

    SIGNALS = ["gnn", "conf", "behav", "entr", "kill"]
    STRUCTURAL, INDEPENDENT = {"gnn", "conf"}, {"behav", "entr", "kill"}

    def flat(v):
        return sum(v.values()) >= 3

    def evidence(v, need):
        sources = (1 if any(v[s] for s in STRUCTURAL) else 0) + sum(1 for s in INDEPENDENT if v[s])
        return sources >= need and any(v[s] for s in INDEPENDENT)

    combos = [dict(zip(SIGNALS, c)) for c in product([False, True], repeat=5)]

    print("\n" + "=" * 78)
    print("ABLATION 3 — gate rule comparison over all 32 vote combinations")
    print("=" * 78)
    print(f"\n{'rule':<38}{'combinations passing':>22}")
    print("-" * 78)
    print(f"{'flat 3-of-5 (pre-Phase-2)':<38}{sum(map(flat, combos)):>22}")
    for need in (2, 3):
        label = f"evidence-source, need {need}" + ("   <- current" if need == 2 else "")
        print(f"{label:<38}{sum(evidence(c, need) for c in combos):>22}")

    gnn_only = {"gnn": True, "conf": True, "behav": False, "entr": False, "kill": False}
    one_corrob = {**gnn_only, "behav": True}
    scan = one_corrob  # what a single-window port scan actually produces

    print("\nKey cases:")
    print(f"  {'GNN + conformal only':<34}flat={flat(gnn_only)!s:<7}evidence2={evidence(gnn_only, 2)}")
    print(f"  {'+ one independent signal':<34}flat={flat(one_corrob)!s:<7}evidence2={evidence(one_corrob, 2)}")
    print(f"  {'live single-window port scan':<34}evidence2={evidence(scan, 2)!s:<7}evidence3={evidence(scan, 3)}")
    print("\nRaising the threshold to 3 would suppress single-window scans, which is why")
    print("it stays at 2. The gate is a correctness fix, not a false-positive reduction.")


if __name__ == "__main__":
    model_ablation()
    consensus_ablation()
    gate_rule_comparison()
