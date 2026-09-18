"""
train_trust_model.py
---------------------
Trains the core trust-scoring classifier: given IIoT device traffic
features, predict P(malicious). trust_score = 1 - P(malicious), in [0,1].

MODEL CHOICE: XGBoost, chosen empirically (see model_comparison.py /
results/model_comparison.json), not assumed. On the real Edge-IIoTset
data it outperformed both Random Forest and Logistic Regression on
every measured axis -- F1 0.986 vs 0.969 vs 0.807, and ~3x FASTER
inference than RF (0.007ms vs 0.020ms/sample) -- while remaining
TreeSHAP-compatible, which Logistic Regression is not. TreeSHAP still
matters here for the same reason it mattered for RF:
  1) exact, fast Shapley values (vs. slow KernelSHAP for black-box
     deep models) -> keeps explanation latency low, which matters for
     a *real-time* zero-trust gateway.
  2) matches prior work (SHAP+LIME on WUSTL-IIoT-2021) showing
     tree-ensemble models retain near-state-of-the-art IIoT intrusion
     accuracy while staying cheap enough for edge/gateway deployment.
"""

import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, f1_score, roc_auc_score,
                              precision_score, recall_score, confusion_matrix)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

DATA_PATH = "./data/iiot_traffic.csv"
MODEL_PATH = "./results/trust_model.joblib"
METRICS_PATH = "./results/baseline_metrics.json"

# Columns that are never features regardless of which CSV is loaded
# (synthetic generator's or the real Edge-IIoTset adapter's output).
NON_FEATURE_COLUMNS = {"label_binary", "label_attack_type", "device_id"}

# Cap on distinct values for a column to be treated as categorical
# rather than dropped as too high-cardinality to encode usefully.
MAX_CATEGORY_CARDINALITY = 50


def load_and_encode(path=DATA_PATH):
    """
    Schema-agnostic loader: works for both the synthetic dataset
    (fixed schema) and the real Edge-IIoTset adapter output (whatever
    columns survive preprocessing), by auto-detecting numeric vs.
    categorical columns instead of relying on a hardcoded list.
    """
    df = pd.read_csv(path)
    candidate_cols = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]

    numeric_cols, categorical_cols = [], []
    for col in candidate_cols:
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric_cols.append(col)
        else:
            n_unique = df[col].nunique(dropna=True)
            if n_unique <= MAX_CATEGORY_CARDINALITY:
                categorical_cols.append(col)
            # else: too high-cardinality (e.g. free-text/id-like) -> skip

    encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        df[col + "_enc"] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    feature_cols = numeric_cols + [c + "_enc" for c in categorical_cols]
    print(f"Auto-detected {len(numeric_cols)} numeric + "
          f"{len(categorical_cols)} categorical features "
          f"({len(feature_cols)} total)")
    return df, feature_cols, encoders


def main():
    df, feature_cols, encoders = load_and_encode()
    X = df[feature_cols]
    y = df["label_binary"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    clf = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                         eval_metric="logloss", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    # inference latency per sample (ms) -- relevant for real-time gateway
    t0 = time.perf_counter()
    _ = clf.predict_proba(X_test.iloc[:200])
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) / 200 * 1000

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_proba),
        "inference_latency_ms_per_sample": latency_ms,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    print(json.dumps(metrics, indent=2))

    joblib.dump({"model": clf, "feature_cols": feature_cols,
                 "encoders": encoders}, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    # also persist the test split for downstream SHAP / policy scripts
    X_test.assign(label_binary=y_test.values,
                   device_id=df.loc[X_test.index, "device_id"].values,
                   attack_type=df.loc[X_test.index, "label_attack_type"].values
                   ).to_csv("./results/test_split.csv", index=False)

    print(f"\nSaved model -> {MODEL_PATH}")
    print(f"Saved metrics -> {METRICS_PATH}")


if __name__ == "__main__":
    main()
