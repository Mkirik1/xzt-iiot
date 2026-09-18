"""
hardening_loop.py
--------------------
Orchestrates the multi-cycle self-hardening experiment (brief Section
3.1 item 9 / Section 28). Every decision and every policy version is
written to the SAME hash-chained audit ledger already built for the
traffic-classification part of the project (src/audit_chain.py) --
one unified audit trail across both contributions of the paper.

SCIENTIFIC INTEGRITY: every ASR/NWFSR number below comes from actually
calling ValidationResult on freshly-run scenarios against the actual
current policy state. Nothing is hardcoded or backfilled. If a run
fails, the script raises rather than silently producing a plausible
number.
"""

import copy
import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))                 # self_hardening/ modules

# Import audit_chain.py by explicit file path (not via sys.path) to avoid a
# module-name collision: both src/ and self_hardening/ have their own
# policy_engine.py / trust_engine.py, and letting src/ onto sys.path would
# shadow the self_hardening versions.
_audit_chain_path = Path(__file__).parent.parent / "src" / "audit_chain.py"
_spec = importlib.util.spec_from_file_location("audit_chain_reused", _audit_chain_path)
_audit_chain_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_audit_chain_mod)
HashChain = _audit_chain_mod.HashChain

from blue_agent import propose_and_apply  # noqa: E402
from normal_scenarios import generate_normal_scenarios  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from red_agent import generate_attack_scenarios  # noqa: E402
from trust_engine import TrustEngine, TrustWeights  # noqa: E402
from validation_agent import validate  # noqa: E402

BASE = Path(__file__).parent
CONFIG = BASE / "config"
RESULTS = BASE / "results"
N_CYCLES = 5
N_PER_ATTACK_TYPE = 20   # 5 scenario types x 20 = 100 attack requests per cycle (was 8/40)
N_NORMAL = 20            # was 10


def policy_snapshot_hash(engine: PolicyEngine) -> str:
    """Cheap content hash of the current policy set, for the audit ledger."""
    import hashlib
    blob = json.dumps([{
        "policy_id": p.policy_id,
        "min_trust_score": p.conditions.min_trust_score,
        "min_device_integrity": p.conditions.min_device_integrity,
        "max_anomaly_score": p.conditions.max_anomaly_score,
        "require_step_up_if_zone_mismatch": p.conditions.require_step_up_if_zone_mismatch,
    } for p in engine.policies], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def run(seed: int = 42, n_per_attack_type: int = N_PER_ATTACK_TYPE, n_normal: int = N_NORMAL,
        write_audit: bool = True, verbose: bool = True):
    """Run one full 5-cycle hardening experiment with a fresh policy/trust
    state and a scenario set drawn from `seed`. Returns cycle_results.
    Called repeatedly with different seeds by run_multiseed.py to test
    whether the ASR-reduction trend is a robust effect or a single-draw
    artifact."""
    trust_engine = TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")))
    policy_engine = PolicyEngine(str(CONFIG / "policies.yaml"), trust_engine)

    attack_reqs = generate_attack_scenarios(n_per_type=n_per_attack_type, seed=seed)
    normal_reqs = generate_normal_scenarios(n=n_normal, seed=seed + 1000)

    chain = HashChain() if write_audit else None
    cycle_results = []

    for cycle in range(N_CYCLES):
        result = validate(policy_engine, attack_reqs, normal_reqs)

        if chain is not None:
            for req, dec in zip(attack_reqs, result.attack_decisions):
                chain.add_record({
                    "cycle": cycle, "request_id": dec.request_id, "policy_id": dec.policy_id,
                    "decision": dec.decision, "trust_score": round(dec.trust_score, 4),
                    "scenario_label": req.label, "explanation": dec.explanation,
                })
            for req, dec in zip(normal_reqs, result.normal_decisions):
                chain.add_record({
                    "cycle": cycle, "request_id": dec.request_id, "policy_id": dec.policy_id,
                    "decision": dec.decision, "trust_score": round(dec.trust_score, 4),
                    "scenario_label": "normal", "explanation": dec.explanation,
                })

        old_hash = policy_snapshot_hash(policy_engine)
        record = {
            "cycle": cycle, "asr": round(result.asr, 4), "nwfsr": round(result.nwfsr, 4),
            "n_attacks": result.n_attacks, "n_normal": result.n_normal,
            "bypassed_scenarios": result.bypassed_scenarios,
            "policy_hash_before_mitigation": old_hash,
        }

        if cycle < N_CYCLES - 1:
            proposal = propose_and_apply(policy_engine, trust_engine, result, cycle)
            new_hash = policy_snapshot_hash(policy_engine)
            record["mitigation_changes"] = proposal.changes
            record["policy_hash_after_mitigation"] = new_hash
            if chain is not None:
                chain.add_record({
                    "event": "POLICY_VERSION_UPDATE", "cycle": cycle,
                    "old_policy_hash": old_hash, "new_policy_hash": new_hash,
                    "changes": proposal.changes,
                })
        else:
            record["mitigation_changes"] = []
            record["policy_hash_after_mitigation"] = old_hash

        cycle_results.append(record)
        if verbose:
            bd = {s: result.bypassed_scenarios.count(s) for s in set(result.bypassed_scenarios)}
            print(f"  [seed={seed}] Cycle {cycle}: ASR={result.asr:.3f}  NWFSR={result.nwfsr:.3f}  bypassed={bd}")

    if write_audit:
        RESULTS.mkdir(exist_ok=True)
        chain.save(str(RESULTS / f"hardening_audit_chain_seed{seed}.json"))
        verify_ok = chain.verify()
        if verbose:
            print(f"  Audit chain (seed={seed}): {len(chain.chain)} blocks, valid={verify_ok}")
        policy_engine.save(str(RESULTS / f"final_policies_seed{seed}.yaml"))

    return cycle_results


if __name__ == "__main__":
    RESULTS.mkdir(exist_ok=True)
    cycle_results = run(seed=42, write_audit=True)
    with open(RESULTS / "hardening_cycles.json", "w") as f:
        json.dump(cycle_results, f, indent=2)
    with open(RESULTS / "hardening_summary.json", "w") as f:
        json.dump({
            "n_cycles": N_CYCLES,
            "asr_by_cycle": [r["asr"] for r in cycle_results],
            "nwfsr_by_cycle": [r["nwfsr"] for r in cycle_results],
        }, f, indent=2)
    print("\nSingle-seed run complete. For the statistically robust "
          "multi-seed result, run: python3 run_multiseed.py")
