"""
blue_agent.py (agents package)
-----------------------------------
Wraps the rule-based mitigation proposer as a named agent. Per the
brief's state machine (PROPOSED / VALIDATED / APPROVED / DEPLOYED /
REJECTED) -- Track A/this prototype auto-applies proposals and lets
the Validation Agent's next-cycle measurement stand in for approval
(no human-in-the-loop UI exists yet; that is Track B scope), but the
state name is recorded honestly in the output rather than skipped.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from trust_engine import TrustEngine  # noqa: E402
import blue_agent as _engine  # noqa: E402  (self_hardening/blue_agent.py)


class BlueAgent(BaseAgent):
    agent_id = "blue_agent"
    name = "Blue Agent"

    def run(self, policy_engine: PolicyEngine, trust_engine: TrustEngine,
            validation_result, cycle: int) -> AgentResult:
        self.status = "running"
        proposal = _engine.propose_and_apply(policy_engine, trust_engine, validation_result, cycle)
        state = "DEPLOYED (auto-applied; Track A has no human-approval UI yet)" if proposal.changes and \
            proposal.changes[0] != "No bypasses this cycle -- no mitigation needed." else "NO_ACTION"
        return self._result(
            output=proposal, confidence=1.0,
            reasoning_summary=f"[{state}] " + " | ".join(proposal.changes))
