"""
validation_agent.py (agents package)
----------------------------------------
Wraps the ASR/NWFSR computation as a named agent.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
import validation_agent as _engine  # noqa: E402  (self_hardening/validation_agent.py)


class ValidationAgent(BaseAgent):
    agent_id = "validation_agent"
    name = "Validation Agent"
    agent_kind = "service"   # computes ASR/NWFSR; an evaluator

    def run(self, engine: PolicyEngine, attack_reqs: list, normal_reqs: list) -> AgentResult:
        self.status = "running"
        result = _engine.validate(engine, attack_reqs, normal_reqs)
        return self._result(
            output=result, confidence=1.0,
            reasoning_summary=(f"ASR={result.asr:.3f} over {result.n_attacks} attack scenarios, "
                                f"NWFSR={result.nwfsr:.3f} over {result.n_normal} normal scenarios. "
                                f"{len(result.bypassed_scenarios)} bypasses observed."))
