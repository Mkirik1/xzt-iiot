"""
adversarial_training_defense.py
-----------------------------------
Tests the most standard defense against feature-space evasion:
adversarial training. Generates evasive examples against the TRAINING
set (not the held-out test set, to avoid leakage), adds them to the
training data as additional "attack" examples, retrains, then
re-runs the IDENTICAL evasion search against the hardened model on
the SAME held-out test attacks used in adversarial_evasion.py --
giving a fair, leakage-free before/after comparison.

Also re-checks clean-data F1 on the untouched test set, to confirm
the defense doesn't wreck normal performance.
"""

import json
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

sys.path.insert(0, ".")
from train_trust_model import load_and_encode, DATA_PATH  # noqa: E402
from policy_engine import decide, TAU_ALLOW  # noqa: E402
from adversarial_evasion import (compute_feature_bounds, predict_p_malicious,  # noqa: E402
                                  evasion_search, N_SAMPLES, RNG)

RESULTS_PATH = "./results/adversarial_training_defense.json"
N_ADV_TRAIN_SAMPLES = 300


def main():
    print("Reproducing the original train/test split...")
    df, feature_cols, _ = load_and_encode(DATA_PATH)
    X = df[feature_cols]
    y = df["label_binary"]
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, df.index, test_size=0.25, random_state=42, stratify=y)

    print("Training the ORIGINAL (undefended) model...")
    clf_orig = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                              eval_metric="logloss", random_state=42, n_jobs=-1)
    clf_orig.fit(X_train, y_train)

    bounds = compute_feature_bounds(df, feature_cols)

    print(f"Generating {N_ADV_TRAIN_SAMPLES} adversarial examples from the TRAINING "
          f"set (not test set -- avoids leakage)...")
    train_attack_idx = idx_train[y_train == 1]
    adv_sample_idx = np.random.RandomState(1).choice(
        train_attack_idx, size=min(N_ADV_TRAIN_SAMPLES, len(train_attack_idx)), replace=False)

    adv_rows = []
    rng = np.random.default_rng(7)
    for i in adv_sample_idx:
        orig_row = df.loc[i, feature_cols].to_dict()
        adv_row, adv_p, _ = evasion_search(clf_orig, feature_cols, bounds, orig_row, rng, max_iters=60)
        adv_rows.append(adv_row)
    adv_df = pd.DataFrame(adv_rows)[feature_cols]
    adv_labels = pd.Series([1] * len(adv_df))  # still genuinely malicious traffic, just disguised

    print("Augmenting training set with adversarial examples and retraining...")
    X_train_aug = pd.concat([X_train, adv_df], ignore_index=True)
    y_train_aug = pd.concat([y_train.reset_index(drop=True), adv_labels], ignore_index=True)

    clf_defended = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                                  eval_metric="logloss", random_state=42, n_jobs=-1)
    clf_defended.fit(X_train_aug, y_train_aug)

    # ---- Re-check clean-data performance (didn't we break normal accuracy?) ----
    def clean_metrics(clf):
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)[:, 1]
        return {"accuracy": round(accuracy_score(y_test, y_pred), 4),
                "f1": round(f1_score(y_test, y_pred), 4),
                "precision": round(precision_score(y_test, y_pred), 4),
                "recall": round(recall_score(y_test, y_pred), 4),
                "roc_auc": round(roc_auc_score(y_test, y_proba), 4)}

    metrics_orig = clean_metrics(clf_orig)
    metrics_defended = clean_metrics(clf_defended)
    print("\nClean-data performance (original vs defended):")
    print("  Original: ", metrics_orig)
    print("  Defended: ", metrics_defended)

    # ---- Re-run the IDENTICAL evasion search against the hardened model ----
    print(f"\nRe-running evasion search against the DEFENDED model "
          f"on the same {N_SAMPLES} held-out test attacks...")
    test_attack_df = df.loc[idx_test][df.loc[idx_test, "label_binary"] == 1].sample(
        n=N_SAMPLES, random_state=42)

    n_evaded_defended = 0
    rng2 = np.random.default_rng(42)
    for idx, row in test_attack_df.iterrows():
        orig = row[feature_cols].to_dict()
        orig_p = predict_p_malicious(clf_defended, feature_cols, orig)
        orig_decision = decide(1 - orig_p)
        adv, adv_p, _ = evasion_search(clf_defended, feature_cols, bounds, orig, rng2)
        adv_decision = decide(1 - adv_p)
        if adv_decision == "ALLOW" and orig_decision != "ALLOW":
            n_evaded_defended += 1

    evasion_rate_defended = n_evaded_defended / N_SAMPLES

    summary = {
        "n_adversarial_training_examples_added": len(adv_df),
        "clean_metrics_original_model": metrics_orig,
        "clean_metrics_defended_model": metrics_defended,
        "evasion_success_rate_original_model": 0.915,  # from adversarial_evasion.py
        "evasion_success_rate_defended_model": round(evasion_rate_defended, 4),
        "relative_evasion_reduction_pct": round((0.915 - evasion_rate_defended) / 0.915 * 100, 1),
    }
    print("\n" + "=" * 60)
    print(json.dumps(summary, indent=2))

    with open(RESULTS_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
