"""
ablation_experiment.py
-------------------------
Implements the brief's Section 24 Experiments A-E as a real, measured
ablation study -- isolating what each architectural layer actually
contributes, rather than just reporting the full system's numbers.

  Experiment A: Baseline ABAC       -- role+zone match only, no dynamic
                                        trust score, no adaptive AI, no
                                        blockchain audit, no explainability
  Experiment B: Zero-Trust ABAC     -- full dynamic TrustScore + ABAC
                                        conditions (Cycle 0 policy), no
                                        adaptive AI / audit / XAI overhead
  Experiment C: ZT + Explainability -- same decisions as B, + measures
                                        real per-decision explanation latency
  Experiment D: ZT + Blockchain     -- same decisions as B, + measures
                                        real per-decision audit-write latency
  Experiment E: Full XZT-IIoT       -- B + C + D + the 5-cycle adaptive
                                        self-hardening loop (final-cycle ASR)

HONEST FRAMING (put this in the paper too): C and D do not change WHICH
decisions get made relative to B -- explainability and audit logging are
observability layers, not decision-policy changes, in this architecture.
Their real, measured contribution is transparency/auditability at a
latency cost, not a different ASR. Only A (no zero-trust) and E (with
adaptive hardening) actually change the decision outcomes. Reporting
identical ASR/NWFSR for B/C/D is the correct, non-fabricated result --
resist the temptation to invent artificial differences to make the
table look more dramatic than the system actually is.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from agents.coordinator_agent import _policy_snapshot_hash  # noqa: E402
from agents.explainability_agent import ExplainabilityAgent  # noqa: E402
from attributes import AccessRequest  # noqa: E402
from normal_scenarios import generate_normal_scenarios  # noqa: E402
from policy_engine import Decision, PolicyEngine  # noqa: E402
from red_agent import generate_attack_scenarios  # noqa: E402
from trust_engine import TrustEngine, TrustWeights  # noqa: E402
from validation_agent import validate  # noqa: E402

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "audit_chain_reused", Path(__file__).parent.parent / "src" / "audit_chain.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
HashChain = _mod.HashChain

CONFIG = Path(__file__).parent / "config"
RESULTS = Path(__file__).parent / "results"
SEED = 42
N_PER_TYPE = 20
N_NORMAL = 20


def baseline_abac_decision(req: AccessRequest, allowed_roles_by_resource: dict) -> str:
    """Experiment A: role+zone match only -- no dynamic trust, no
    device-integrity/anomaly checks. This is the "static ABAC" world
    the whole zero-trust literature argues is insufficient; measuring
    it honestly (rather than skipping straight to our own system) is
    what makes B's improvement a real, demonstrated claim."""
    allowed = allowed_roles_by_resource.get(req.resource, [])
    if req.subject.role not in allowed:
        return "DENY"
    if req.network.source_zone != req.network.expected_zone and req.network.source_zone == "unknown_external":
        # even naive ABAC in practice usually has SOME network check;
        # without this, Experiment A would be a strawman. Still no
        # trust score, no anomaly, no device integrity -- that's the point.
        return "DENY"
    return "ALLOW"


def run_experiment_a():
    attack_reqs = generate_attack_scenarios(n_per_type=N_PER_TYPE, seed=SEED)
    normal_reqs = generate_normal_scenarios(n=N_NORMAL, seed=SEED + 1000)
    allowed_roles_by_resource = {
        "PLC_CONTROLLER": ["engineer", "maintenance"],
        "HMI_WORKSTATION": ["engineer", "operator", "maintenance"],
        "PUMP_CONTROLLER": ["operator", "engineer"],
    }
    attack_decisions = [baseline_abac_decision(r, allowed_roles_by_resource) for r in attack_reqs]
    normal_decisions = [baseline_abac_decision(r, allowed_roles_by_resource) for r in normal_reqs]
    asr = sum(1 for d in attack_decisions if d == "ALLOW") / len(attack_decisions)
    nwfsr = sum(1 for d in normal_decisions if d == "ALLOW") / len(normal_decisions)
    return {"asr": round(asr, 4), "nwfsr": round(nwfsr, 4)}


def run_experiment_b():
    """Zero-Trust ABAC, Cycle-0 policy, single static evaluation
    (no adaptive hardening loop applied)."""
    trust_engine = TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")))
    policy_engine = PolicyEngine(str(CONFIG / "policies.yaml"), trust_engine)
    attack_reqs = generate_attack_scenarios(n_per_type=N_PER_TYPE, seed=SEED)
    normal_reqs = generate_normal_scenarios(n=N_NORMAL, seed=SEED + 1000)
    result = validate(policy_engine, attack_reqs, normal_reqs)
    return {"asr": round(result.asr, 4), "nwfsr": round(result.nwfsr, 4)}, policy_engine, trust_engine, attack_reqs, normal_reqs


def run_experiment_c(policy_engine, trust_engine, attack_reqs):
    """ZT + Explainability: same decisions as B, measure real
    explanation-generation latency (rule-based, per decision)."""
    explain_agent = ExplainabilityAgent(trust_engine)
    decisions = [policy_engine.evaluate(r) for r in attack_reqs]
    t0 = time.perf_counter()
    for req, dec in zip(attack_reqs, decisions):
        explain_agent.explain(req, dec)
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) / len(attack_reqs) * 1000
    return {"explanation_latency_ms_per_decision": round(latency_ms, 5)}


def run_experiment_d(policy_engine, attack_reqs):
    """ZT + Blockchain audit: same decisions as B, measure real
    hash-chain append latency per decision."""
    chain = HashChain()
    decisions = [policy_engine.evaluate(r) for r in attack_reqs]
    t0 = time.perf_counter()
    for req, dec in zip(attack_reqs, decisions):
        chain.add_record({"request_id": dec.request_id, "decision": dec.decision,
                           "trust_score": round(dec.trust_score, 4)})
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) / len(attack_reqs) * 1000
    return {"audit_write_latency_ms_per_decision": round(latency_ms, 5),
            "audit_valid": chain.verify(), "audit_blocks": len(chain.chain)}


def run_experiment_e():
    """Full XZT-IIoT: read the already-computed 5-cycle, 5-seed
    multi-seed result (final cycle) -- do not recompute/duplicate,
    single source of truth is hardening_multiseed_summary.json."""
    with open(RESULTS / "hardening_multiseed_summary.json") as f:
        summary = json.load(f)
    return {"asr": summary["asr_mean_by_cycle"][-1], "asr_std": summary["asr_std_by_cycle"][-1],
            "nwfsr": summary["nwfsr_mean_by_cycle"][-1], "n_cycles": summary["n_cycles"],
            "n_seeds": summary["n_seeds"]}


def main():
    print("Running Experiment A (Baseline ABAC)...")
    exp_a = run_experiment_a()
    print(f"  ASR={exp_a['asr']:.3f}  NWFSR={exp_a['nwfsr']:.3f}")

    print("Running Experiment B (Zero-Trust ABAC, static)...")
    exp_b, policy_engine, trust_engine, attack_reqs, normal_reqs = run_experiment_b()
    print(f"  ASR={exp_b['asr']:.3f}  NWFSR={exp_b['nwfsr']:.3f}")

    print("Running Experiment C (ZT + Explainability)...")
    exp_c_overhead = run_experiment_c(policy_engine, trust_engine, attack_reqs)
    exp_c = {**exp_b, **exp_c_overhead}
    print(f"  ASR={exp_c['asr']:.3f}  NWFSR={exp_c['nwfsr']:.3f}  "
          f"explain_latency={exp_c_overhead['explanation_latency_ms_per_decision']:.5f} ms")

    print("Running Experiment D (ZT + Blockchain audit)...")
    exp_d_overhead = run_experiment_d(policy_engine, attack_reqs)
    exp_d = {**exp_b, **exp_d_overhead}
    print(f"  ASR={exp_d['asr']:.3f}  NWFSR={exp_d['nwfsr']:.3f}  "
          f"audit_latency={exp_d_overhead['audit_write_latency_ms_per_decision']:.5f} ms  "
          f"audit_valid={exp_d_overhead['audit_valid']}")

    print("Loading Experiment E (Full XZT-IIoT, from multi-seed result)...")
    exp_e = run_experiment_e()
    print(f"  ASR={exp_e['asr']:.3f}±{exp_e['asr_std']:.3f}  NWFSR={exp_e['nwfsr']:.3f} "
          f"(after {exp_e['n_cycles']} cycles, {exp_e['n_seeds']} seeds)")

    table = {
        "Experiment A (Baseline ABAC)": {
            "Zero_Trust": "No", "Dynamic_Trust": "No", "Explainability": "No",
            "Blockchain_Audit": "No", "Adaptive_AI": "No",
            "ASR": exp_a["asr"], "NWFSR": exp_a["nwfsr"],
        },
        "Experiment B (Zero-Trust ABAC)": {
            "Zero_Trust": "Yes", "Dynamic_Trust": "Yes", "Explainability": "No",
            "Blockchain_Audit": "No", "Adaptive_AI": "No",
            "ASR": exp_b["asr"], "NWFSR": exp_b["nwfsr"],
        },
        "Experiment C (ZT + Explainability)": {
            "Zero_Trust": "Yes", "Dynamic_Trust": "Yes", "Explainability": "Yes",
            "Blockchain_Audit": "No", "Adaptive_AI": "No",
            "ASR": exp_c["asr"], "NWFSR": exp_c["nwfsr"],
            "Explanation_latency_ms": exp_c_overhead["explanation_latency_ms_per_decision"],
        },
        "Experiment D (ZT + Blockchain)": {
            "Zero_Trust": "Yes", "Dynamic_Trust": "Yes", "Explainability": "No",
            "Blockchain_Audit": "Yes", "Adaptive_AI": "No",
            "ASR": exp_d["asr"], "NWFSR": exp_d["nwfsr"],
            "Audit_write_latency_ms": exp_d_overhead["audit_write_latency_ms_per_decision"],
        },
        "Experiment E (Full XZT-IIoT)": {
            "Zero_Trust": "Yes", "Dynamic_Trust": "Yes", "Explainability": "Yes",
            "Blockchain_Audit": "Yes", "Adaptive_AI": "Yes",
            "ASR": f"{exp_e['asr']}±{exp_e['asr_std']}", "NWFSR": exp_e["nwfsr"],
        },
    }

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "ablation_table.json", "w") as f:
        json.dump(table, f, indent=2)

    # also write a flat CSV for direct paste into the paper
    import csv
    with open(RESULTS / "ablation_table.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Experiment", "Zero-Trust", "Dynamic Trust", "Explainability",
                          "Blockchain Audit", "Adaptive AI", "ASR", "NWFSR"])
        for name, row in table.items():
            writer.writerow([name, row["Zero_Trust"], row["Dynamic_Trust"], row["Explainability"],
                              row["Blockchain_Audit"], row["Adaptive_AI"], row["ASR"], row["NWFSR"]])

    print(f"\nSaved -> {RESULTS / 'ablation_table.json'} and ablation_table.csv")


if __name__ == "__main__":
    main()
