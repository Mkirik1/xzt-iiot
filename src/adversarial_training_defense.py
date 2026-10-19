"""
adversarial_training_defense.py
-----------------------------------
Tests the most standard defense against feature-space evasion:
adversarial training. Generates evasive examples against the TRAINING
set (not the held-out test set, to avoid leakage), adds them to the
training data as additional "attack" examples, and retrains.

EVALUATION (rewritten after review). Both the original and the defended
model are attacked on the SAME 200 attacks from the held-out test split
(adversarial_evasion.held_out_attack_sample), with the SAME search
seeds, under two threat models from adversarial_evasion_constrained.py:
  permissive  every feature may change
  strict      protocol/capture fields and TCP control flags frozen
Nothing is copied in from another script. An earlier version hard-coded
the original model's rate (0.915) from adversarial_evasion.py, which had
been measured on a different sample that included training rows, so its
"before vs after" compared two different attack sets.

Reported per model and tier: single-run evasion (mean +/- std over
seeds) and the best-known rate (pooled over every search valid for the
tier; see adversarial_evasion_constrained.py). Clean-data metrics on the
untouched test set are reported for both models.
"""

import json
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

sys.path.insert(0, ".")
from train_trust_model import load_and_encode, DATA_PATH  # noqa: E402
from adversarial_evasion import (compute_feature_bounds, evasion_search,  # noqa: E402
                                  held_out_attack_sample)
from adversarial_evasion_constrained import (SEARCH_SEEDS, TIERS, add_best_known,  # noqa: E402
                                              run_tier, split_features)

RESULTS_PATH = "./results/adversarial_training_defense.json"
N_ADV_TRAIN_SAMPLES = 300
EVAL_TIERS = ["permissive", "strict"]


def train_xgb(X, y):
    clf = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                        eval_metric="logloss", random_state=42, n_jobs=-1)
    clf.fit(X, y)
    return clf


def evaluate_evasion(model, feature_cols, bounds, attack_rows, label):
    """Attack one model under each evaluation tier with every search seed."""
    tiers = {}
    for tier in EVAL_TIERS:
        mutable, frozen = split_features(feature_cols, TIERS[tier])
        runs = []
        for seed in SEARCH_SEEDS:
            r = run_tier(model, feature_cols, bounds, attack_rows, mutable, seed)
            r["seed"] = seed
            runs.append(r)
            print(f"  [{label} / {tier}] seed {seed}: "
                  f"{r['n_successfully_evaded_to_allow']}/{r['n_originally_blocked']}")
        rates = np.array([r["evasion_success_rate_of_blocked"] for r in runs], dtype=float)
        tiers[tier] = {"evasion_rate_mean": round(float(rates.mean()), 4),
                       "evasion_rate_std": round(float(rates.std()), 4),
                       "per_seed": runs, "frozen_features": frozen}
    add_best_known(tiers)
    return tiers


def main():
    print("Reproducing the original train/test split...")
    df, feature_cols, _ = load_and_encode(DATA_PATH)
    X = df[feature_cols]
    y = df["label_binary"]
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, df.index, test_size=0.25, random_state=42, stratify=y)

    print("Training the ORIGINAL (undefended) model...")
    clf_orig = train_xgb(X_train, y_train)
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
        adv_row, _, _ = evasion_search(clf_orig, feature_cols, bounds, orig_row, rng, max_iters=60)
        adv_rows.append(adv_row)
    adv_df = pd.DataFrame(adv_rows)[feature_cols]
    adv_labels = pd.Series([1] * len(adv_df))  # still malicious traffic, just disguised

    print("Augmenting training set with adversarial examples and retraining...")
    clf_defended = train_xgb(pd.concat([X_train, adv_df], ignore_index=True),
                             pd.concat([y_train.reset_index(drop=True), adv_labels], ignore_index=True))

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

    attack_df = held_out_attack_sample(df, feature_cols)
    assert set(attack_df.index) <= set(idx_test), "evaluation attacks must come from the test split"
    attack_rows = [row[feature_cols].to_dict() for _, row in attack_df.iterrows()]

    print(f"\nAttacking both models on the same {len(attack_rows)} held-out attacks...")
    evasion = {"original": evaluate_evasion(clf_orig, feature_cols, bounds, attack_rows, "original"),
               "defended": evaluate_evasion(clf_defended, feature_cols, bounds, attack_rows, "defended")}

    p_orig = evasion["original"]["permissive"]["evasion_rate_mean"]
    p_def = evasion["defended"]["permissive"]["evasion_rate_mean"]
    summary = {
        "samples": f"{len(attack_rows)} attacks from the held-out test split, identical for both models",
        "search_seeds": SEARCH_SEEDS,
        "n_adversarial_training_examples_added": len(adv_df),
        "adversarial_examples_generated_under": "permissive",
        "clean_metrics_original_model": metrics_orig,
        "clean_metrics_defended_model": metrics_defended,
        "evasion": evasion,
        # Headline pair kept under the old key names for make_defense_figure.py
        # and older readers: permissive tier, single-run mean, same samples.
        "evasion_success_rate_original_model": p_orig,
        "evasion_success_rate_defended_model": p_def,
        "relative_evasion_reduction_pct": round((p_orig - p_def) / p_orig * 100, 1) if p_orig else None,
    }

    print("\n" + "=" * 60)
    for model in ("original", "defended"):
        for tier in EVAL_TIERS:
            t = evasion[model][tier]
            print(f"{model:9s} {tier:11s} single run = {t['evasion_rate_mean']:.3f} ± "
                  f"{t['evasion_rate_std']:.3f} | best known = {t['evasion_rate_best_known']:.3f}")
    print(f"Permissive single-run reduction: {summary['relative_evasion_reduction_pct']}% relative")

    with open(RESULTS_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
