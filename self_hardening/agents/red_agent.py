"""
red_agent.py (agents package)
--------------------------------
SAFETY: unchanged from the engine-layer red_agent.py this wraps --
generates only abstract attribute-perturbation scenarios, never real
attack traffic or connections. See the engine module's own safety
docstring for the full rationale.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
import red_agent as _engine  # noqa: E402  (self_hardening/red_agent.py)


class RedAgent(BaseAgent):
    agent_id = "red_agent"
    name = "Red Agent"

    def run(self, base_n_per_type: int, threat_weights: dict, seed: int) -> AgentResult:
        self.status = "running"
        scenarios = _engine.generate_attack_scenarios_weighted(base_n_per_type, threat_weights, seed)
        counts = {s: sum(1 for r in scenarios if r.label == s) for s in _engine.SCENARIOS}
        return self._result(
            output=scenarios, confidence=1.0,
            reasoning_summary=(f"Generated {len(scenarios)} adversarial test scenarios "
                                f"against local lab targets only, weighted by threat-intel "
                                f"severity: {counts}."))
