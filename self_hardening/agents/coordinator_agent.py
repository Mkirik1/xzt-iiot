"""
coordinator_agent.py (agents package)
------------------------------------------
Orchestrates the full 8-agent self-hardening cycle:

  ThreatIntelAgent -> RedAgent -> PolicyAgent (x2: attack + normal)
    -> ValidationAgent -> ExplainabilityAgent -> BlueAgent -> AuditAgent
  repeated for N_CYCLES, with a fresh TrustEngine/PolicyEngine per
  experiment run (per seed).

This supersedes the procedural hardening_loop.run() function with an
explicit multi-agent architecture matching the brief's Section 30
agent roster (ThreatIntelAgent, RedAgent, BlueAgent, ValidationAgent,
PolicyAgent, ExplainabilityAgent, AuditAgent, CoordinatorAgent = 8
agents). The underlying logic is IDENTICAL to hardening_loop.py --
this is an architectural reorganization, not a behavior change, so
results are reproducible against the numbers already reported.
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.audit_agent import AuditAgent  # noqa: E402
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
from agents.blue_agent import BlueAgent  # noqa: E402
from agents.explainability_agent import ExplainabilityAgent  # noqa: E402
from agents.policy_agent import PolicyAgent  # noqa: E402
from agents.red_agent import RedAgent  # noqa: E402
from agents.threat_intel_agent import ThreatIntelAgent  # noqa: E402
from agents.validation_agent import ValidationAgent  # noqa: E402
from evolutionary_red_agent import EvolutionaryRedAgent  # noqa: E402
from normal_scenarios import generate_normal_scenarios  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from trust_engine import TrustEngine, TrustWeights  # noqa: E402

CONFIG = Path(__file__).parent.parent / "config"
N_CYCLES = 5
N_PER_ATTACK_TYPE_BASE = 20
N_NORMAL = 20


def _policy_snapshot_hash(engine: PolicyEngine) -> str:
    blob = json.dumps([{
        "policy_id": p.policy_id, "min_trust_score": p.conditions.min_trust_score,
        "min_device_integrity": p.conditions.min_device_integrity,
        "max_anomaly_score": p.conditions.max_anomaly_score,
        "require_step_up_if_zone_mismatch": p.conditions.require_step_up_if_zone_mismatch,
    } for p in engine.policies], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class CoordinatorAgent(BaseAgent):
    agent_id = "coordinator_agent"
    name = "Coordinator Agent"

    def __init__(self):
        super().__init__()
        self.threat_intel = ThreatIntelAgent()
        self.red = RedAgent()
        self.evolutionary_red = EvolutionaryRedAgent()
        self.validation = ValidationAgent()
        self.blue = BlueAgent()
        self.audit = AuditAgent()
        # policy_agent, explainability_agent are created per-run below
        # since they hold references to a per-run TrustEngine/PolicyEngine

    def run_experiment(self, seed: int = 42, n_cycles: int = N_CYCLES,
                        n_per_attack_type_base: int = N_PER_ATTACK_TYPE_BASE,
                        n_normal: int = N_NORMAL, write_explanations: bool = False,
                        use_evolutionary_red: bool = False, try_live_threat_intel: bool = False,
                        verbose: bool = True) -> AgentResult:
        self.status = "running"
        trust_engine = TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")))
        policy_engine = PolicyEngine(str(CONFIG / "policies.yaml"), trust_engine)
        policy_agent = PolicyAgent(policy_engine)
        explain_agent = ExplainabilityAgent(trust_engine)

        ti_result = self.threat_intel.run(try_live=try_live_threat_intel)
        threat_weights = ti_result.output
        if verbose:
            print(f"  [ThreatIntelAgent] {ti_result.reasoning_summary}")

        normal_reqs = generate_normal_scenarios(n=n_normal, seed=seed + 1000)
        cycle_results = []
        sample_explanations = []

        for cycle in range(n_cycles):
            if use_evolutionary_red:
                evo_result = self.evolutionary_red.run(policy_engine, seed=seed * 100 + cycle)
                attack_reqs = evo_result.output["requests"]
                if verbose:
                    print(f"  [EvolutionaryRedAgent] {evo_result.reasoning_summary}")
            else:
                red_result = self.red.run(n_per_attack_type_base, threat_weights, seed=seed * 100 + cycle)
                attack_reqs = red_result.output

            attack_policy_result = policy_agent.run(attack_reqs)
            normal_policy_result = policy_agent.run(normal_reqs)

            val_result = self.validation.run(policy_engine, attack_reqs, normal_reqs)
            result = val_result.output

            if write_explanations and cycle == 0:
                exp_result = explain_agent.run(attack_reqs[:5], attack_policy_result.output[:5])
                sample_explanations = exp_result.output

            for req, dec in zip(attack_reqs, attack_policy_result.output):
                self.audit.append({"cycle": cycle, "request_id": dec.request_id,
                                    "policy_id": dec.policy_id, "decision": dec.decision,
                                    "trust_score": round(dec.trust_score, 4),
                                    "scenario_label": req.label, "explanation": dec.explanation})
            for req, dec in zip(normal_reqs, normal_policy_result.output):
                self.audit.append({"cycle": cycle, "request_id": dec.request_id,
                                    "policy_id": dec.policy_id, "decision": dec.decision,
                                    "trust_score": round(dec.trust_score, 4),
                                    "scenario_label": "normal", "explanation": dec.explanation})

            old_hash = _policy_snapshot_hash(policy_engine)
            record = {"cycle": cycle, "asr": round(result.asr, 4), "nwfsr": round(result.nwfsr, 4),
                      "n_attacks": result.n_attacks, "n_normal": result.n_normal,
                      "bypassed_scenarios": result.bypassed_scenarios,
                      "policy_hash_before_mitigation": old_hash}

            if cycle < n_cycles - 1:
                blue_result = self.blue.run(policy_engine, trust_engine, result, cycle)
                new_hash = _policy_snapshot_hash(policy_engine)
                record["mitigation_changes"] = blue_result.output.changes
                record["policy_hash_after_mitigation"] = new_hash
                self.audit.append({"event": "POLICY_VERSION_UPDATE", "cycle": cycle,
                                    "old_policy_hash": old_hash, "new_policy_hash": new_hash,
                                    "changes": blue_result.output.changes})
            else:
                record["mitigation_changes"] = []
                record["policy_hash_after_mitigation"] = old_hash

            cycle_results.append(record)
            if verbose:
                print(f"  [seed={seed}] Cycle {cycle}: ASR={result.asr:.3f}  NWFSR={result.nwfsr:.3f}")

        audit_result = self.audit.run()
        if verbose:
            print(f"  [AuditAgent] {audit_result.reasoning_summary}")

        threat_intel_source = ("LIVE_NVD" if "LIVE NVD feed" in ti_result.reasoning_summary
                                else "local_static_feed")

        return self._result(
            output={"cycle_results": cycle_results, "audit_valid": audit_result.output["valid"],
                    "audit_blocks": audit_result.output["blocks"], "audit_chain": self.audit.chain,
                    "sample_explanations": sample_explanations,
                    "threat_intel_source": threat_intel_source},
            confidence=1.0,
            reasoning_summary=(f"Coordinated {n_cycles}-cycle self-hardening run (seed={seed}) "
                                f"across 8 agents; final ASR="
                                f"{cycle_results[-1]['asr']:.3f}, audit_valid={audit_result.output['valid']}."))
