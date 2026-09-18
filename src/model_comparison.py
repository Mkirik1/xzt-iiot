"""
model_comparison.py
----------------------
Compares Random Forest (our chosen model) against XGBoost and
Logistic Regression on the SAME real Edge-IIoTset train/test split,
to justify (rather than just assert) the RF choice for TreeSHAP
compatibility and latency. All three trained and evaluated for real --
no numbers assumed from literature.
"""

import json
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

import sys
sys.path.insert(0, ".")
from train_trust_model import load_and_encode, DATA_PATH  # noqa: E402

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

RESULTS_PATH = "./results/model_comparison.json"


def evaluate(name, clf, X_train, X_test, y_train, y_test, needs_scaling=False):
    if needs_scaling:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

    t0 = time.perf_counter()
    clf.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    inf_time_ms = (time.perf_counter() - t0) / len(X_test) * 1000

    return {
        "model": name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "f1": round(f1_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_proba), 4),
        "train_time_s": round(train_time, 2),
        "inference_latency_ms_per_sample": round(inf_time_ms, 5),
        "treeshap_compatible": name in ("Random Forest", "XGBoost"),
    }


def main():
    df, feature_cols, _ = load_and_encode(DATA_PATH)
    X = df[feature_cols]
    y = df["label_binary"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    results = []

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=3,
                                 class_weight="balanced_subsample", random_state=42, n_jobs=-1)
    results.append(evaluate("Random Forest", rf, X_train, X_test, y_train, y_test))

    if HAS_XGB:
        print("Training XGBoost...")
        xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                             eval_metric="logloss", random_state=42, n_jobs=-1)
        results.append(evaluate("XGBoost", xgb, X_train, X_test, y_train, y_test))
    else:
        print("xgboost not installed -- skipping (pip install xgboost to include it)")

    print("Training Logistic Regression...")
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    results.append(evaluate("Logistic Regression", lr, X_train, X_test, y_train, y_test,
                             needs_scaling=True))

    for r in results:
        print(f"\n{r['model']}: Acc={r['accuracy']} F1={r['f1']} ROC-AUC={r['roc_auc']} "
              f"latency={r['inference_latency_ms_per_sample']}ms "
              f"TreeSHAP-compatible={r['treeshap_compatible']}")

    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
