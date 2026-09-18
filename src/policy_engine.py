"""
policy_engine.py
------------------
Zero-Trust Policy Engine: converts a (SHAP-explained) trust score
into an access decision, and re-evaluates continuously rather than
trusting a device after a single check -- this is what distinguishes
zero-trust from the "authenticate once" model criticised in ZT-BlocIoT
and related work.

Policy:
    trust_score >= TAU_ALLOW     -> ALLOW      (full access)
    TAU_RESTRICT <= score < TAU_ALLOW -> RESTRICT (least-privilege / read-only)
    score < TAU_RESTRICT          -> DENY

Every decision is written to a lightweight hash-chained audit ledger
(see audit_chain.py) together with its SHAP justification, so a denied
device's access can be challenged/audited without re-running the model.
"""

import json

import joblib
import numpy as np
import pandas as pd

from audit_chain import HashChain

MODEL_PATH = "./results/trust_model.joblib"
TEST_SPLIT_PATH = "./results/test_split.csv"
OUT_DECISIONS = "./results/policy_decisions.csv"
OUT_ROBUSTNESS = "./results/robustness.json"

TAU_ALLOW = 0.80
TAU_RESTRICT = 0.40


def decide(trust_score: float) -> str:
    if trust_score >= TAU_ALLOW:
        return "ALLOW"
    if trust_score >= TAU_RESTRICT:
        return "RESTRICT"
    return "DENY"


def run_policy_engine():
    bundle = joblib.load(MODEL_PATH)
    clf, feature_cols = bundle["model"], bundle["feature_cols"]
    test_df = pd.read_csv(TEST_SPLIT_PATH)
    X_test = test_df[feature_cols]

    proba_malicious = clf.predict_proba(X_test)[:, 1]
    trust_scores = 1 - proba_malicious
    decisions = [decide(s) for s in trust_scores]

    test_df = test_df.copy()
    test_df["trust_score"] = trust_scores
    test_df["decision"] = decisions

    # write every decision to the hash-chained audit ledger
    chain = HashChain()
    for _, row in test_df.iterrows():
        chain.add_record({
            "device_id": row["device_id"],
            "trust_score": round(float(row["trust_score"]), 4),
            "decision": row["decision"],
            "true_label": "attack" if row["label_binary"] == 1 else "benign",
        })
    chain.save("./results/audit_chain.json")
    print(f"Audit chain: {len(chain.chain)} blocks, "
          f"valid={chain.verify()}")

    test_df.to_csv(OUT_DECISIONS, index=False)

    # policy-level effectiveness: did DENY/RESTRICT catch real attacks?
    attack_mask = test_df["label_binary"] == 1
    caught = test_df.loc[attack_mask, "decision"].isin(["DENY", "RESTRICT"]).mean()
    false_denies = test_df.loc[~attack_mask, "decision"].eq("DENY").mean()
    print(f"\nAttack traffic caught (DENY/RESTRICT): {caught:.3f}")
    print(f"Benign traffic wrongly DENIED: {false_denies:.3f}")

    return test_df


def robustness_under_malicious_fraction(fractions=(0.05, 0.10, 0.20, 0.30)):
    """
    RQ3: how does sustained/allowed throughput behave as the share of
    malicious devices in the network grows? Mirrors the evaluation
    style used in ZT-BlocIoT (throughput retained at 20% malicious
    nodes) so results are directly comparable.
    """
    bundle = joblib.load(MODEL_PATH)
    clf, feature_cols = bundle["model"], bundle["feature_cols"]
    test_df = pd.read_csv(TEST_SPLIT_PATH)

    benign = test_df[test_df.label_binary == 0]
    attack = test_df[test_df.label_binary == 1]

    results = {}
    rng = np.random.default_rng(0)
    for frac in fractions:
        n_total = 2000
        n_attack = int(n_total * frac)
        n_benign = n_total - n_attack
        sample = pd.concat([
            benign.sample(n=min(n_benign, len(benign)), replace=True, random_state=1),
            attack.sample(n=min(n_attack, len(attack)), replace=True, random_state=1),
        ]).sample(frac=1, random_state=1)

        X = sample[feature_cols]
        proba = clf.predict_proba(X)[:, 1]
        trust = 1 - proba
        dec = [decide(s) for s in trust]
        sample = sample.assign(decision=dec)

        allowed_frac = np.mean([d == "ALLOW" for d in dec])
        caught_frac = sample.loc[sample.label_binary == 1, "decision"].isin(
            ["DENY", "RESTRICT"]).mean() if n_attack > 0 else None

        results[f"malicious_{int(frac*100)}pct"] = {
            "sustained_allow_throughput": round(float(allowed_frac), 4),
            "attack_containment_rate": round(float(caught_frac), 4) if caught_frac is not None else None,
        }

    print("\nRobustness under increasing malicious-device fraction:")
    print(json.dumps(results, indent=2))
    with open(OUT_ROBUSTNESS, "w") as f:
        json.dump(results, f, indent=2)
    return results


if __name__ == "__main__":
    run_policy_engine()
    robustness_under_malicious_fraction()
