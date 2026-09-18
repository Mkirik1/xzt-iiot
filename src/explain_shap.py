"""
explain_shap.py
-----------------
Adds interpretability to the trust-scoring model via TreeSHAP.

Produces two things the zero-trust policy engine (and a human
operator) can use:
  1. Global feature importance -- which behavioral signals matter
     most across the whole fleet of devices.
  2. Local explanations -- for a specific device's trust decision,
     which features pushed the score down (and by how much), so an
     access-denial is auditable rather than a black-box verdict.

Also benchmarks SHAP's computational overhead, since RQ2 of the
paper is exactly this: how much does explainability cost?
"""

import json
import time

import joblib
import numpy as np
import pandas as pd
import shap

MODEL_PATH = "./results/trust_model.joblib"
TEST_SPLIT_PATH = "./results/test_split.csv"
OUT_GLOBAL = "./results/shap_global_importance.json"
OUT_LOCAL = "./results/shap_local_examples.json"
OUT_OVERHEAD = "./results/shap_overhead.json"


def main():
    bundle = joblib.load(MODEL_PATH)
    clf, feature_cols = bundle["model"], bundle["feature_cols"]

    test_df = pd.read_csv(TEST_SPLIT_PATH)
    X_test = test_df[feature_cols]

    explainer = shap.TreeExplainer(clf)

    # ---- overhead benchmark: explained vs unexplained inference ----
    sample = X_test.iloc[:200]

    t0 = time.perf_counter()
    _ = clf.predict_proba(sample)
    t1 = time.perf_counter()
    plain_ms = (t1 - t0) / len(sample) * 1000

    t0 = time.perf_counter()
    sv = explainer.shap_values(sample, check_additivity=False)
    t1 = time.perf_counter()
    shap_ms = (t1 - t0) / len(sample) * 1000

    overhead = {
        "plain_inference_ms_per_sample": plain_ms,
        "shap_explained_ms_per_sample": shap_ms,
        "overhead_ms_per_sample": shap_ms - plain_ms,
        "overhead_multiplier": shap_ms / plain_ms if plain_ms > 0 else None,
    }
    print("SHAP overhead:", json.dumps(overhead, indent=2))
    with open(OUT_OVERHEAD, "w") as f:
        json.dump(overhead, f, indent=2)

    # ---- global feature importance (mean |SHAP value|) ----
    sv_full = explainer.shap_values(X_test, check_additivity=False)
    # Handle the different shapes returned across shap versions for a
    # binary RandomForestClassifier: list [class0, class1], or a single
    # (n_samples, n_features) array, or (n_samples, n_features, n_classes).
    if isinstance(sv_full, list):
        sv_pos = sv_full[1]
    elif sv_full.ndim == 3:
        sv_pos = sv_full[:, :, 1]
    else:
        sv_pos = sv_full
    mean_abs = np.abs(sv_pos).mean(axis=0)
    global_importance = sorted(
        zip(feature_cols, mean_abs.tolist()), key=lambda x: -x[1])
    print("\nTop-5 global features:")
    for name, val in global_importance[:5]:
        print(f"  {name}: {val:.4f}")
    with open(OUT_GLOBAL, "w") as f:
        json.dump(global_importance, f, indent=2)

    # ---- local explanation examples: one malicious, one benign ----
    proba = clf.predict_proba(X_test)[:, 1]
    idx_malicious = int(np.argmax(proba))          # most confidently malicious
    idx_benign = int(np.argmin(proba))              # most confidently benign

    def local_explanation(idx):
        row = X_test.iloc[idx]
        contrib = dict(zip(feature_cols, sv_pos[idx].tolist()))
        contrib_sorted = sorted(contrib.items(), key=lambda x: -abs(x[1]))
        return {
            "device_id": test_df.iloc[idx]["device_id"],
            "attack_type": test_df.iloc[idx]["attack_type"],
            "trust_score": round(1 - float(proba[idx]), 4),
            "top_contributing_features": [
                {"feature": k, "shap_value": round(v, 4),
                 "raw_value": float(row[k])}
                for k, v in contrib_sorted[:5]
            ],
        }

    examples = {
        "most_suspicious_device": local_explanation(idx_malicious),
        "most_trusted_device": local_explanation(idx_benign),
    }
    print("\nLocal explanation example (most suspicious device):")
    print(json.dumps(examples["most_suspicious_device"], indent=2))

    with open(OUT_LOCAL, "w") as f:
        json.dump(examples, f, indent=2)


if __name__ == "__main__":
    main()
