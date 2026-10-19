"""
generalization_experiment.py
-------------------------------
Reviewer R4: the self-hardening loop was only ever evaluated on the same
scenario family it was hardened against, with no unseen attacks and no
boundary-case workflows. This experiment asks whether hardening
generalizes, and what it costs on legitimate work near the boundaries.

Protocol, per seed (10 seeds) and per Blue Agent mode (objective, rule):
  1. Harden for 5 cycles seeing ONLY the five original attack classes
     (SEEN). Attack sets and the Blue Agent's tuning set are restricted
     to SEEN; everything else is the canonical loop.
  2. Evaluate the INITIAL (Cycle-0) policy and the FINAL hardened policy
     on fresh evaluation sets that the loop never saw:
       seen       the five SEEN classes, new draws
       held_out   three classes withheld from hardening
       ood        two classes that exist nowhere else in the project
                  (red_agent.OOD_SCENARIOS): insider_flood (ABAC-clean,
                  malicious traffic) and low_and_slow (just inside the
                  thresholds, ordinary traffic)
       normal     100 standard legitimate workflows (vs 20 in the loop)
       boundary   54 legitimate boundary-case workflows (night-shift
                  maintenance, aging devices, unusual but authorised
                  tasks; normal_scenarios.generate_boundary_normal_scenarios)
     Evaluation request IDs are prefixed so the ML bridge draws traffic
     records independent of those used during hardening.

Reported: ASR per group and per class, NWFSR on standard and boundary
workflows (also per boundary kind), initial vs final, mean +/- std over
seeds. ALLOW counts as a bypass; STEP_UP_AUTH, DENY and QUARANTINE count
as blocked, exactly as in the rest of Track 2.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from agents.coordinator_agent import CoordinatorAgent, CONFIG  # noqa: E402
from ml_trust_bridge import get_bridge  # noqa: E402
from normal_scenarios import (BOUNDARY_KINDS, generate_boundary_normal_scenarios,  # noqa: E402
                              generate_normal_scenarios)
from policy_engine import PolicyEngine  # noqa: E402
from red_agent import OOD_SCENARIOS, generate_attack_scenarios  # noqa: E402
from trust_engine import TrustEngine, TrustWeights  # noqa: E402

RESULTS = Path(__file__).parent / "results"
SEEDS = [42, 101, 202, 303, 404, 505, 606, 707, 808, 909]
MODES = ["objective", "rule"]
SEEN = ["stolen_credentials", "compromised_device", "network_zone_mismatch",
        "behavioral_anomaly", "abnormal_access_time"]
HELD_OUT = ["privilege_escalation_attempt", "replay_simulation", "firmware_integrity_failure"]
GROUPS = {"seen": SEEN, "held_out": HELD_OUT, "ood": OOD_SCENARIOS}
N_EVAL_PER_CLASS = 30
N_NORMAL_EVAL = 100
N_BOUNDARY_EVAL = 54   # multiple of 9: every boundary kind on every resource equally


def fresh_engine() -> PolicyEngine:
    trust = TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")), ml_bridge=get_bridge())
    return PolicyEngine(str(CONFIG / "policies.yaml"), trust)


def evaluation_sets(seed: int) -> dict:
    sets = {}
    for g, classes in GROUPS.items():
        reqs = generate_attack_scenarios(n_per_type=N_EVAL_PER_CLASS, seed=seed + 70_000, scenarios=classes)
        for r in reqs:
            r.request_id = f"gen_{g}_{r.request_id}"
        sets[g] = reqs
    normal = generate_normal_scenarios(n=N_NORMAL_EVAL, seed=seed + 71_000)
    boundary = generate_boundary_normal_scenarios(n=N_BOUNDARY_EVAL, seed=seed + 72_000)
    for r in normal + boundary:
        r.request_id = "gen_" + r.request_id
    sets["normal"], sets["boundary"] = normal, boundary
    return sets


def evaluate(engine: PolicyEngine, sets: dict) -> dict:
    out = {}
    for g in GROUPS:
        allowed = defaultdict(int)
        total = defaultdict(int)
        for r in sets[g]:
            total[r.label] += 1
            if engine.evaluate(r).decision == "ALLOW":
                allowed[r.label] += 1
        out[f"asr_{g}"] = sum(allowed.values()) / sum(total.values())
        for c in total:
            out[f"asr_class_{c}"] = allowed[c] / total[c]
    for g in ("normal", "boundary"):
        ok = [engine.evaluate(r).decision == "ALLOW" for r in sets[g]]
        out[f"nwfsr_{g}"] = float(np.mean(ok))
    for kind in BOUNDARY_KINDS:
        reqs = [r for r in sets["boundary"] if r.metadata.get("boundary_kind") == kind]
        out[f"nwfsr_boundary_{kind}"] = float(np.mean([engine.evaluate(r).decision == "ALLOW" for r in reqs]))
    return out


def run_seed(seed: int, mode: str, sets: dict) -> dict:
    res = CoordinatorAgent(blue_mode=mode).run_experiment(seed=seed, attack_scenarios=SEEN, verbose=False)
    return evaluate(res.output["final_policy_engine"], sets)


def summarise(rows: list) -> dict:
    keys = rows[0].keys()
    return {k: {"mean": round(float(np.mean([r[k] for r in rows])), 4),
                "std": round(float(np.std([r[k] for r in rows])), 4)} for k in keys}


def main():
    if get_bridge() is None:
        raise SystemExit("Track-1 model not trained; run src/train_trust_model.py first.")
    per_seed = {"initial": [], **{m: [] for m in MODES}}
    for seed in SEEDS:
        sets = evaluation_sets(seed)
        per_seed["initial"].append(evaluate(fresh_engine(), sets))
        for mode in MODES:
            per_seed[mode].append(run_seed(seed, mode, sets))
        print(f"  seed {seed}: initial ASR held_out={per_seed['initial'][-1]['asr_held_out']:.3f} | "
              + " | ".join(f"{m} final held_out={per_seed[m][-1]['asr_held_out']:.3f}" for m in MODES))

    summary = {name: summarise(rows) for name, rows in per_seed.items()}
    out = {
        "seeds": SEEDS, "hardened_on": SEEN, "held_out": HELD_OUT, "ood": OOD_SCENARIOS,
        "n_eval_per_class": N_EVAL_PER_CLASS, "n_normal_eval": N_NORMAL_EVAL,
        "n_boundary_eval": N_BOUNDARY_EVAL,
        "policies": {"initial": "Cycle-0 policy, no hardening",
                     **{m: f"after 5 cycles hardened on SEEN only, Blue Agent mode={m}" for m in MODES}},
        "summary": summary, "per_seed": per_seed,
    }

    print("\n" + "=" * 78)
    cols = ["initial"] + MODES
    print(f"{'metric':38s}" + "".join(f"{c:>14s}" for c in cols))
    for k in ["asr_seen", "asr_held_out", "asr_ood", "asr_class_insider_flood", "asr_class_low_and_slow",
              "nwfsr_normal", "nwfsr_boundary"] + [f"nwfsr_boundary_{b}" for b in BOUNDARY_KINDS]:
        print(f"{k:38s}" + "".join(f"{summary[c][k]['mean']*100:9.1f}±{summary[c][k]['std']*100:4.1f}" for c in cols))

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "generalization.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved -> {RESULTS / 'generalization.json'}")


if __name__ == "__main__":
    main()
