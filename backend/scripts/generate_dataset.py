"""Generate synthetic host-communication graphs for GNN training.

WHAT THIS IS
------------
Synthetic traffic, not a public dataset. It is generated to match exactly what
FeatureExtractor produces at runtime: per-source-IP aggregates over a 5-second window,
plus the communication graph between hosts in that window.

Why synthetic rather than CICIDS2017: CICIDS2017 ships per-flow CICFlowMeter features
(~78 columns, one row per flow). Our detector consumes per-host-per-window aggregates
and the graph between hosts. Six of our seven features could be recovered by regrouping
the real flows into windows keyed by source IP, but failed_auth_count has no equivalent
(CICFlowMeter does not inspect payloads), and the graph would have to be rebuilt anyway.
Training on data shaped like the runtime input is the point; see README.

WHAT A SAMPLE IS
----------------
One time window:
  nodes    - IP addresses observed
  features - 7 flow statistics per node
  edges    - (i, j) where host i sent packets to host j
  labels   - 1 for hosts behaving maliciously, 0 otherwise

Only the actor is labelled malicious. A scanned victim is structurally involved but is
not itself an attacker, and labelling it 1 would teach the model to flag victims.

Attack topologies are the reason this is a graph problem at all:
  PortScan     one source fanning out across many ports on few targets
  DoS          one or more sources converging on a single target
  BruteForce   one source hammering one service port with failed auth
  Lateral      a chain -- A contacts B, B then contacts C -- held out as the zero-day
"""

import json
import os

import numpy as np
import pandas as pd

GRAPH_OUTPUT_PATH = "backend/data/synthetic_graphs.jsonl"
FLAT_OUTPUT_PATH = "backend/data/synthetic_flows.csv"

FEATURE_KEYS = [
    'syn_count', 'ack_count', 'rst_count',
    'unique_dst_ports', 'bytes_sent', 'connection_frequency', 'failed_auth_count'
]

N_WINDOWS = {
    "BENIGN": 1200,
    "PortScan": 400,
    "DoS": 300,
    "BruteForce": 250,
    "Lateral": 150,     # held out at training time as the zero-day category
}

rng = np.random.default_rng(42)


def benign_host():
    """A normal client: a few packets to one service."""
    return {
        'syn_count': int(rng.integers(1, 4)),
        'ack_count': int(rng.integers(1, 10)),
        'rst_count': int(rng.integers(0, 2)),
        'unique_dst_ports': 1,
        'bytes_sent': int(rng.integers(100, 5000)),
        'connection_frequency': round(float(rng.uniform(0.1, 2.0)), 2),
        'failed_auth_count': 0,
    }


def server_host(n_clients):
    """A server replying to several clients: high ACK, low SYN, still benign."""
    return {
        'syn_count': int(rng.integers(0, 3)),
        'ack_count': int(rng.integers(5, 15)) * max(n_clients, 1),
        'rst_count': int(rng.integers(0, 3)),
        'unique_dst_ports': 1,
        'bytes_sent': int(rng.integers(2000, 9000)),
        'connection_frequency': round(float(rng.uniform(0.5, 4.0)), 2),
        'failed_auth_count': 0,
    }


def multi_service_client():
    """
    A benign host legitimately touching several services -- a monitoring agent, a CI
    runner, a backup job. Its scalar features deliberately OVERLAP a port scanner's.

    This is what makes the graph necessary. If benign and malicious hosts were
    separable on their own counters, the model would learn those counters and ignore
    topology entirely (measured: it did exactly that, and zero-day recall collapsed
    to 0.9%). The two are told apart by who they talk to, not by what they look like.
    """
    return {
        'syn_count': int(rng.integers(15, 90)),
        'ack_count': int(rng.integers(10, 40)),
        'rst_count': int(rng.integers(0, 4)),
        'unique_dst_ports': int(rng.integers(8, 60)),
        'bytes_sent': int(rng.integers(500, 4000)),
        'connection_frequency': round(float(rng.uniform(8.0, 45.0)), 2),
        'failed_auth_count': 0,
    }


def scanned_victim():
    """
    A host being probed. Most of the probed ports are closed, so it answers with RSTs.

    This is the structural tell: a scanner's neighbours look like this, a monitoring
    agent's neighbours do not. One hop of message passing is enough to see it.
    """
    return {
        'syn_count': int(rng.integers(0, 3)),
        'ack_count': int(rng.integers(0, 4)),
        'rst_count': int(rng.integers(12, 60)),
        'unique_dst_ports': 1,
        'bytes_sent': int(rng.integers(50, 600)),
        'connection_frequency': round(float(rng.uniform(2.0, 20.0)), 2),
        'failed_auth_count': 0,
    }


def scanner_host():
    """Feature-identical to multi_service_client by construction."""
    return multi_service_client()


def flooder_host():
    return {
        'syn_count': int(rng.integers(100, 500)),
        'ack_count': int(rng.integers(0, 10)),
        'rst_count': int(rng.integers(0, 5)),
        'unique_dst_ports': int(rng.integers(1, 3)),
        'bytes_sent': int(rng.integers(5000, 50000)),
        'connection_frequency': round(float(rng.uniform(50.0, 200.0)), 2),
        'failed_auth_count': 0,
    }


def bruteforcer_host():
    return {
        'syn_count': int(rng.integers(10, 50)),
        'ack_count': int(rng.integers(10, 50)),
        'rst_count': int(rng.integers(0, 5)),
        'unique_dst_ports': 1,
        'bytes_sent': int(rng.integers(2000, 10000)),
        'connection_frequency': round(float(rng.uniform(5.0, 25.0)), 2),
        'failed_auth_count': int(rng.integers(5, 30)),
    }


def lateral_host():
    """
    Deliberately unremarkable per-host numbers. A lateral-movement hop looks like an
    ordinary client in isolation -- only the chain topology gives it away, which is
    exactly what the held-out zero-day evaluation is testing.
    """
    return {
        'syn_count': int(rng.integers(4, 14)),
        'ack_count': int(rng.integers(4, 18)),
        'rst_count': int(rng.integers(0, 3)),
        'unique_dst_ports': int(rng.integers(1, 4)),
        'bytes_sent': int(rng.integers(3000, 15000)),
        'connection_frequency': round(float(rng.uniform(1.5, 6.0)), 2),
        'failed_auth_count': int(rng.integers(0, 2)),
    }


def build_benign_window():
    """Clients talking to one or two servers. Star topology, benign."""
    n_clients = int(rng.integers(2, 7))
    n_servers = int(rng.integers(1, 3))

    features, labels, edges = [], [], []
    for _ in range(n_clients):
        features.append(benign_host())
        labels.append(0)
    for _ in range(n_servers):
        features.append(server_host(n_clients))
        labels.append(0)

    for c in range(n_clients):
        srv = n_clients + int(rng.integers(0, n_servers))
        edges.append((c, srv))

    # ~35% of windows contain a benign multi-service client fanning out to healthy
    # hosts. Same scalar profile as a scanner; different neighbourhood.
    if rng.random() < 0.35:
        agent = len(features)
        features.append(multi_service_client())
        labels.append(0)
        for _ in range(int(rng.integers(3, 8))):
            features.append(server_host(1))   # healthy targets: low RST
            labels.append(0)
            edges.append((agent, len(features) - 1))

    return features, labels, edges


def build_attack_window(kind):
    """One attacker embedded in otherwise benign background traffic."""
    features, labels, edges = build_benign_window()
    attacker = len(features)

    maker = {
        "PortScan": scanner_host,
        "DoS": flooder_host,
        "BruteForce": bruteforcer_host,
    }[kind]
    features.append(maker())
    labels.append(1)

    if kind == "PortScan":
        # Fan out to targets that answer with RSTs — the structural signature of a scan,
        # and the only thing separating this host from a benign monitoring agent.
        n_targets = int(rng.integers(3, 8))
        for _ in range(n_targets):
            features.append(scanned_victim())
            labels.append(0)
            edges.append((attacker, len(features) - 1))
    elif kind == "DoS":
        # Converge on a single victim, sometimes with co-attackers.
        features.append(server_host(1))
        labels.append(0)
        victim = len(features) - 1
        edges.append((attacker, victim))
        for _ in range(int(rng.integers(0, 3))):
            features.append(flooder_host())
            labels.append(1)
            edges.append((len(features) - 1, victim))
    else:  # BruteForce
        features.append(server_host(1))
        labels.append(0)
        edges.append((attacker, len(features) - 1))

    return features, labels, edges


def build_lateral_window():
    """A -> B -> C -> D chain. Each hop looks benign alone; the path does not."""
    features, labels, edges = build_benign_window()
    chain_len = int(rng.integers(3, 6))

    chain = []
    for _ in range(chain_len):
        features.append(lateral_host())
        labels.append(1)
        chain.append(len(features) - 1)

    for a, b in zip(chain, chain[1:]):
        edges.append((a, b))
    return features, labels, edges


def main():
    os.makedirs("backend/data", exist_ok=True)

    windows = []
    for kind, count in N_WINDOWS.items():
        for _ in range(count):
            if kind == "BENIGN":
                f, l, e = build_benign_window()
            elif kind == "Lateral":
                f, l, e = build_lateral_window()
            else:
                f, l, e = build_attack_window(kind)

            windows.append({
                "scenario": kind,
                "features": [[float(h[k]) for k in FEATURE_KEYS] for h in f],
                "labels": l,
                "edges": [[int(a), int(b)] for a, b in e],
            })

    rng.shuffle(windows)

    with open(GRAPH_OUTPUT_PATH, "w") as fh:
        for w in windows:
            fh.write(json.dumps(w) + "\n")

    n_nodes = sum(len(w["labels"]) for w in windows)
    n_mal = sum(sum(w["labels"]) for w in windows)
    n_edges = sum(len(w["edges"]) for w in windows)

    print(f"[DATASET] {len(windows)} windows -> '{GRAPH_OUTPUT_PATH}'")
    print(f"[DATASET]   nodes {n_nodes:,}  edges {n_edges:,}")
    print(f"[DATASET]   malicious nodes {n_mal:,} ({n_mal / n_nodes * 100:.1f}%)")
    for kind in N_WINDOWS:
        print(f"[DATASET]   {kind:<12} {sum(1 for w in windows if w['scenario'] == kind):>5} windows")

    # Flat per-node table, used for the behavioural cold-start baseline.
    rows = []
    for w in windows:
        for feats, label in zip(w["features"], w["labels"]):
            row = dict(zip(FEATURE_KEYS, feats))
            row["label"] = w["scenario"] if label else "BENIGN"
            rows.append(row)
    pd.DataFrame(rows).to_csv(FLAT_OUTPUT_PATH, index=False)
    print(f"[DATASET] flat per-node table -> '{FLAT_OUTPUT_PATH}' ({len(rows):,} rows)")


if __name__ == "__main__":
    main()
