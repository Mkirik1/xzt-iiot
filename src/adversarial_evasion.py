"""
adversarial_evasion.py
-------------------------
Tests whether an attacker who can craft their own traffic could evade
our XGBoost trust classifier -- i.e., attacks the ML MODEL itself
(Barrier 2), not the ABAC policy layer (which self_hardening/ already
tests). This is a black-box, query-based evasion search: the attacker
doesn't see model internals, only the trust_score/decision each probe
returns -- the same access a real attacker probing our live API would
have.

THREAT MODEL (state this explicitly in the paper -- it's an
assumption, not a proof of real-world feasibility): the attacker can
freely set ANY of the model's input features to any value within the
range actually observed in the training data (i.e., physically
plausible packet-level values, not values outside what real traffic
ever showed). This is a common, standard feature-space threat model in
adversarial ML research; it is more permissive than most real
attackers (who can't fully control protocol-state fields like
tcp.seq/tcp.ack, which are determined by the TCP handshake, not
freely chosen) -- so the resulting evasion rate is a pessimistic/
worst-case upper bound, not a claim that this exact attack is
practically executable by a real adversary. State this honestly.

SUCCESS CRITERION: matches the actual deployed decision threshold in
policy_engine.py (TAU_ALLOW=0.80), not just flipping the raw 0.5
classifier boundary -- an evasion only "counts" if it would actually
get ALLOW from the real system.
"""

import json
import sys
import time

import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, ".")
from train_trust_model import load_and_encode, DATA_PATH  # noqa: E402
from policy_engine import decide, TAU_ALLOW  # noqa: E402

RNG = np.random.default_rng(42)
MODEL_PATH = "./results/trust_model.joblib"
N_SAMPLES = 200
MAX_ITERS = 80
FEATURES_PER_STEP = 6
RESULTS_PATH = "./results/adversarial_evasion.json"


def load_model():
    bundle = joblib.load(MODEL_PATH)
    return bundle["model"], bundle["feature_cols"]


def compute_feature_bounds(df, feature_cols):
    """Attacker may only set features within the range actually
    observed in real traffic -- not arbitrary/impossible values."""
    bounds = {}
    for c in feature_cols:
        bounds[c] = (float(df[c].min()), float(df[c].max()), float(df[c].std()))
    return bounds


def predict_p_malicious(model, feature_cols, row_dict):
    X = pd.DataFrame([row_dict])[feature_cols]
    return float(model.predict_proba(X)[0, 1])


def evasion_search(model, feature_cols, bounds, original_row, rng,
                    max_iters=MAX_ITERS, step_features=FEATURES_PER_STEP):
    """Black-box hill-climbing: only queries predict_proba (no gradient/
    internals access), mutates a random feature subset each step, keeps
    the mutation only if it lowers P(malicious). Stops early once the
    ACTUAL deployed ALLOW threshold would be crossed."""
    best = dict(original_row)
    best_p = predict_p_malicious(model, feature_cols, best)
    history = [best_p]
    target_p = 1 - TAU_ALLOW  # trust_score = 1-p >= TAU_ALLOW  <=>  p <= 1-TAU_ALLOW

    for _ in range(max_iters):
        candidate = dict(best)
        feats = rng.choice(feature_cols, size=min(step_features, len(feature_cols)), replace=False)
        for f in feats:
            lo, hi, std = bounds[f]
            if std == 0:
                continue
            delta = rng.normal(0, std * 0.6)
            candidate[f] = float(np.clip(candidate[f] + delta, lo, hi))
        p = predict_p_malicious(model, feature_cols, candidate)
        if p < best_p:
            best, best_p = candidate, p
        history.append(best_p)
        if best_p <= target_p:
            break
    return best, best_p, history


def main():
    print("Loading model and real Edge-IIoTset attack samples...")
    model, feature_cols = load_model()
    df, _, _ = load_and_encode(DATA_PATH)
    attack_df = df[df.label_binary == 1].sample(n=N_SAMPLES, random_state=42)
    bounds = compute_feature_bounds(df, feature_cols)

    results = []
    t0 = time.perf_counter()
    for i, (idx, row) in enumerate(attack_df.iterrows()):
        orig = row[feature_cols].to_dict()
        orig_p = predict_p_malicious(model, feature_cols, orig)
        orig_trust = 1 - orig_p
        orig_decision = decide(orig_trust)

        adv, adv_p, history = evasion_search(model, feature_cols, bounds, orig, RNG)
        adv_trust = 1 - adv_p
        adv_decision = decide(adv_trust)

        perturbation = {f: round(adv[f] - orig[f], 4) for f in feature_cols
                         if abs(adv[f] - orig[f]) > 1e-6}
        top_perturbed = sorted(perturbation.items(), key=lambda kv: -abs(kv[1]))[:5]

        results.append({
            "sample_idx": int(idx),
            "attack_type": df.loc[idx, "label_attack_type"],
            "original_trust_score": round(orig_trust, 4),
            "original_decision": orig_decision,
            "adversarial_trust_score": round(adv_trust, 4),
            "adversarial_decision": adv_decision,
            "evaded_to_allow": adv_decision == "ALLOW" and orig_decision != "ALLOW",
            "search_iterations_used": len(history) - 1,
            "top_perturbed_features": top_perturbed,
        })
        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{N_SAMPLES} samples tested...")

    elapsed = time.perf_counter() - t0
    n_evaded = sum(r["evaded_to_allow"] for r in results)
    n_orig_blocked = sum(1 for r in results if r["original_decision"] != "ALLOW")

    summary = {
        "n_samples_tested": N_SAMPLES,
        "n_originally_blocked": n_orig_blocked,
        "n_successfully_evaded_to_allow": n_evaded,
        "evasion_success_rate_of_blocked": round(n_evaded / n_orig_blocked, 4) if n_orig_blocked else None,
        "evasion_success_rate_overall": round(n_evaded / N_SAMPLES, 4),
        "avg_search_iterations": round(float(np.mean([r["search_iterations_used"] for r in results])), 1),
        "wall_time_s": round(elapsed, 1),
        "threat_model": "feature-space, black-box query access, bounded to observed real-data ranges",
        "success_criterion": f"adversarial trust_score >= TAU_ALLOW ({TAU_ALLOW}), i.e. would get real ALLOW decision",
    }

    print("\n" + "=" * 60)
    print(json.dumps(summary, indent=2))

    # Feature frequency: which features get perturbed most across successful evasions
    from collections import Counter
    feat_counter = Counter()
    for r in results:
        if r["evaded_to_allow"]:
            for f, _ in r["top_perturbed_features"]:
                feat_counter[f] += 1
    print("\nMost-perturbed features among successful evasions:")
    for f, count in feat_counter.most_common(10):
        print(f"  {f}: appeared in {count} successful evasions")

    with open(RESULTS_PATH, "w") as f:
        json.dump({"summary": summary, "per_sample": results,
                    "top_perturbed_features_overall": feat_counter.most_common(10)}, f, indent=2)
    print(f"\nSaved -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
