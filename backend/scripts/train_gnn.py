"""Training script for GraphSAGE GNN model on CICIDS2017 with held-out zero-day category"""

import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from backend.pipeline.gnn_model import GraphSAGEAnomalyModel, GNNPredictor

def train():
    dataset_path = "backend/data/cicids2017_subset.csv"
    model_output_path = "backend/models/gnn_cicids2017.pt"

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}. Run generate_dataset.py first.")

    df = pd.read_csv(dataset_path)
    print(f"[TRAIN] Loaded {len(df)} records from {dataset_path}")

    # Step 1: Held-out attack category split (Methodology: Exclude 'Infiltration' for zero-day test)
    HELD_OUT_CATEGORY = 'Infiltration'
    
    train_val_df = df[df['label'] != HELD_OUT_CATEGORY].copy()
    zero_day_df = df[df['label'] == HELD_OUT_CATEGORY].copy()

    print(f"[METHODOLOGY] Held-out zero-day attack category: '{HELD_OUT_CATEGORY}' ({len(zero_day_df)} samples excluded from training)")

    feature_cols = GNNPredictor.FEATURE_KEYS

    # Binary label: BENIGN = 0.0, ATTACK = 1.0
    train_val_df['target'] = (train_val_df['label'] != 'BENIGN').astype(np.float32)
    zero_day_df['target'] = 1.0

    X = train_val_df[feature_cols].values.astype(np.float32)
    y = train_val_df['target'].values.astype(np.float32)

    # Normalize features
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)
    GNNPredictor.MEANS = means
    GNNPredictor.STDS = stds

    X_norm = (X - means) / (stds + 1e-6)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(X_norm, y, test_size=0.2, random_state=42, stratify=y)

    X_train_t = torch.tensor(X_train, dtype=torch.float32)
    y_train_t = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    X_test_t = torch.tensor(X_test, dtype=torch.float32)
    y_test_t = torch.tensor(y_test, dtype=torch.float32).unsqueeze(1)

    model = GraphSAGEAnomalyModel(in_features=len(feature_cols))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    criterion = nn.BCELoss()

    print("[TRAIN] Training GraphSAGE model over 50 epochs...")
    model.train()
    for epoch in range(50):
        optimizer.zero_grad()
        preds = model(X_train_t)
        loss = criterion(preds, y_train_t)
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            print(f"  Epoch [{epoch+1}/50] - Loss: {loss.item():.4f}")

    # Evaluation on Test set
    model.eval()
    with torch.no_grad():
        test_preds = model(X_test_t).numpy().squeeze()
        test_pred_labels = (test_preds > 0.5).astype(np.float32)

        acc = accuracy_score(y_test, test_pred_labels)
        f1 = f1_score(y_test, test_pred_labels)
        auc = roc_auc_score(y_test, test_preds)

        print(f"\n[EVALUATION - STANDARD TEST SET]")
        print(f"  Accuracy: {acc:.4f}")
        print(f"  F1-Score: {f1:.4f}")
        print(f"  ROC-AUC : {auc:.4f}")

        # Evaluation on Zero-Day Held Out Category
        X_zero_day = zero_day_df[feature_cols].values.astype(np.float32)
        X_zero_day_norm = (X_zero_day - means) / (stds + 1e-6)
        X_zero_day_t = torch.tensor(X_zero_day_norm, dtype=torch.float32)

        zero_day_preds = model(X_zero_day_t).numpy().squeeze()
        avg_zero_day_anomaly = np.mean(zero_day_preds)
        zero_day_detected = np.mean(zero_day_preds > 0.5)

        print(f"\n[EVALUATION - HELD-OUT ZERO-DAY ('{HELD_OUT_CATEGORY}')]")
        print(f"  Average Anomaly Score: {avg_zero_day_anomaly:.4f}")
        print(f"  Zero-Day Detection Rate (Score > 0.5): {zero_day_detected * 100:.2f}%")

    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    torch.save(model.state_dict(), model_output_path)
    print(f"\n[SAVED] Saved model weights to '{model_output_path}'")

if __name__ == "__main__":
    train()
