"""
blue_agent.py (agents package)
-----------------------------------
The defender. Two modes:

  objective (default)  GOAL-BASED AGENT. Percepts: the current policy
                       and trust weights, plus this cycle's validation
                       result. Goal: maximise J = aS - bL - gFPR - dO
                       (objective_function.py). Action selection: build
                       candidate mitigations, measure each on a TUNING
                       scenario set that is separate from the scenarios
                       the cycle is evaluated on, commit the best one.
                       State: the policy it modified persists across
                       cycles, so each decision starts from its last one.
  rule                 SIMPLE REFLEX AGENT (the pre-v4 behaviour, kept
                       for comparison): fixed condition-action rules,
                       "scenario X bypassed -> tighten threshold Y".

Proposals are auto-applied; the PROPOSED/VALIDATED/APPROVED/DEPLOYED
state machine in policy_versioning.py is not wired to a human approval
step yet, and the recorded state says so.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
from objective_function import apply_candidate, search_best_candidate  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from trust_engine import TrustEngine  # noqa: E402
import blue_agent as _engine  # noqa: E402  (self_hardening/blue_agent.py, rule mode)

BLUE_MODES = ("objective", "rule")


class BlueAgent(BaseAgent):
    agent_id = "blue_agent"
    name = "Blue Agent"
    agent_kind = "goal_based_agent"   # in "objective" mode; "simple_reflex_agent" in "rule" mode

    def __init__(self, mode: str = "objective"):
        super().__init__()
        if mode not in BLUE_MODES:
            raise ValueError(f"mode must be one of {BLUE_MODES}, got {mode!r}")
        self.mode = mode
        if mode == "rule":
            self.agent_kind = "simple_reflex_agent"

    def run(self, policy_engine: PolicyEngine, trust_engine: TrustEngine,
            validation_result, cycle: int, tuning_attack=None, tuning_normal=None) -> AgentResult:
        self.status = "running"
        if self.mode == "rule":
            proposal = _engine.propose_and_apply(policy_engine, trust_engine, validation_result, cycle)
            changes = proposal.changes
            acted = bool(changes) and changes[0] != "No bypasses this cycle -- no mitigation needed."
            output = {"mode": "rule", "changes": changes}
        else:
            if tuning_attack is None or tuning_normal is None:
                raise ValueError("objective mode needs a separate tuning scenario set")
            best, evaluated = search_best_candidate(policy_engine, tuning_attack, tuning_normal,
                                                    return_all=True)
            apply_candidate(policy_engine, best)
            acted = best.describe() != "no change"
            changes = [f"Applied highest-J candidate of {len(evaluated)}: {best.describe()} "
                       f"(tuning set: ASR={best.asr:.3f}, NWFSR={best.nwfsr:.3f}, J={best.J:.4f})"]
            output = {"mode": "objective", "changes": changes, "chosen": best.describe(),
                      "J": round(best.J, 4), "tuning_asr": round(best.asr, 4),
                      "tuning_nwfsr": round(best.nwfsr, 4), "n_candidates": len(evaluated)}
        state = ("DEPLOYED (auto-applied; no human-approval step wired yet)" if acted
                 else "NO_ACTION")
        return self._result(output=output, confidence=1.0,
                            reasoning_summary=f"[{self.mode} | {state}] " + " | ".join(changes))
