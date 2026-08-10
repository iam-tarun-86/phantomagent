"""Generate CICIDS2017 subset dataset with held-out attack categories"""

import pandas as pd
import numpy as np

np.random.seed(42)

n_benign = 3000
n_portscan = 800
n_dos = 600
n_bruteforce = 400
n_infiltration = 200 # Held-out zero-day attack category

data = []

# Benign traffic
for _ in range(n_benign):
    data.append({
        'src_ip': f"192.168.1.{np.random.randint(2, 250)}",
        'dst_ip': "10.0.0.5",
        'dst_port': np.random.choice([80, 443, 8080, 22, 53]),
        'syn_count': np.random.randint(1, 4),
        'ack_count': np.random.randint(1, 10),
        'rst_count': np.random.randint(0, 2),
        'unique_dst_ports': 1,
        'bytes_sent': np.random.randint(100, 5000),
        'connection_frequency': round(np.random.uniform(0.1, 2.0), 2),
        'failed_auth_count': 0,
        'label': 'BENIGN'
    })

# PortScan attacks
for _ in range(n_portscan):
    data.append({
        'src_ip': f"172.16.0.{np.random.randint(2, 100)}",
        'dst_ip': "10.0.0.5",
        'dst_port': np.random.randint(1, 1000),
        'syn_count': np.random.randint(15, 100),
        'ack_count': np.random.randint(0, 5),
        'rst_count': np.random.randint(0, 10),
        'unique_dst_ports': np.random.randint(15, 150),
        'bytes_sent': np.random.randint(500, 3000),
        'connection_frequency': round(np.random.uniform(10.0, 50.0), 2),
        'failed_auth_count': 0,
        'label': 'PortScan'
    })

# DoS attacks
for _ in range(n_dos):
    data.append({
        'src_ip': f"172.16.0.{np.random.randint(2, 100)}",
        'dst_ip': "10.0.0.5",
        'dst_port': np.random.choice([80, 443]),
        'syn_count': np.random.randint(100, 500),
        'ack_count': np.random.randint(0, 10),
        'rst_count': np.random.randint(0, 5),
        'unique_dst_ports': np.random.randint(1, 3),
        'bytes_sent': np.random.randint(5000, 50000),
        'connection_frequency': round(np.random.uniform(50.0, 200.0), 2),
        'failed_auth_count': 0,
        'label': 'DoS'
    })

# BruteForce attacks
for _ in range(n_bruteforce):
    data.append({
        'src_ip': f"172.16.0.{np.random.randint(2, 100)}",
        'dst_ip': "10.0.0.5",
        'dst_port': np.random.choice([22, 80, 443]),
        'syn_count': np.random.randint(10, 50),
        'ack_count': np.random.randint(10, 50),
        'rst_count': np.random.randint(0, 5),
        'unique_dst_ports': 1,
        'bytes_sent': np.random.randint(2000, 10000),
        'connection_frequency': round(np.random.uniform(5.0, 25.0), 2),
        'failed_auth_count': np.random.randint(5, 30),
        'label': 'BruteForce'
    })

# Infiltration (Zero-Day Held Out Category)
for _ in range(n_infiltration):
    data.append({
        'src_ip': f"10.0.0.{np.random.randint(100, 200)}",
        'dst_ip': "10.0.0.5",
        'dst_port': np.random.randint(1024, 65535),
        'syn_count': np.random.randint(20, 80),
        'ack_count': np.random.randint(5, 20),
        'rst_count': np.random.randint(5, 15),
        'unique_dst_ports': np.random.randint(5, 20),
        'bytes_sent': np.random.randint(10000, 80000),
        'connection_frequency': round(np.random.uniform(15.0, 60.0), 2),
        'failed_auth_count': np.random.randint(1, 5),
        'label': 'Infiltration'
    })

df = pd.DataFrame(data)
df.to_csv('backend/data/cicids2017_subset.csv', index=False)
print(f"[CICIDS2017] Subset dataset created at backend/data/cicids2017_subset.csv with {len(df)} records.")
