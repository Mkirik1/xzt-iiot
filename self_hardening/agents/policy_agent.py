"""
policy_agent.py (agents package)
------------------------------------
Wraps the ABAC PolicyEngine as a named agent (brief's "Policy Agent:
analyzes why access was allowed/denied" -- here the engine already
returns that analysis in Decision.explanation; the agent layer adds
the confidence/reasoning_summary framing over a batch of decisions).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402


class PolicyAgent(BaseAgent):
    agent_id = "policy_agent"
    name = "Policy Agent"
    agent_kind = "service"   # the policy decision point: a deterministic request -> decision function

    def __init__(self, engine: PolicyEngine):
        super().__init__()
        self.engine = engine

    def run(self, requests: list) -> AgentResult:
        self.status = "running"
        decisions = [self.engine.evaluate(r) for r in requests]
        allow = sum(1 for d in decisions if d.decision == "ALLOW")
        deny = sum(1 for d in decisions if d.decision == "DENY")
        step_up = sum(1 for d in decisions if d.decision == "STEP_UP_AUTH")
        return self._result(
            output=decisions, confidence=1.0,
            reasoning_summary=(f"Evaluated {len(requests)} requests against "
                                f"{len(self.engine.policies)} ABAC policies: "
                                f"{allow} ALLOW, {deny} DENY, {step_up} STEP_UP_AUTH."))
