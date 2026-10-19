"""
explainability_agent.py (agents package)
--------------------------------------------
Rule-based explainability layer (brief Section 8: "Use rule-based
explanations initially"). Distinct from the SHAP-based explainability
used for Track 1's traffic classifier -- this one explains individual
ABAC decisions in terms of which conditions failed and how much each
trust-score factor contributed, using TrustEngine.factor_breakdown().
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402
from attributes import AccessRequest  # noqa: E402
from policy_engine import Decision  # noqa: E402
from trust_engine import TrustEngine  # noqa: E402


class ExplainabilityAgent(BaseAgent):
    agent_id = "explainability_agent"
    name = "Explainability Agent"
    agent_kind = "service"   # formats per-decision explanations

    def __init__(self, trust_engine: TrustEngine):
        super().__init__()
        self.trust_engine = trust_engine

    def explain(self, req: AccessRequest, decision: Decision) -> dict:
        breakdown = self.trust_engine.factor_breakdown(req)
        top_factors = sorted(breakdown.items(), key=lambda kv: -abs(kv[1]))[:3]
        return {
            "request_id": decision.request_id,
            "decision": decision.decision,
            "trust_score": round(decision.trust_score, 4),
            "failed_conditions": decision.failed_conditions,
            "top_trust_factors": [{"factor": k, "contribution": round(v, 4)} for k, v in top_factors],
            "plain_language": decision.explanation,
        }

    def run(self, requests: list, decisions: list) -> AgentResult:
        self.status = "running"
        explanations = [self.explain(r, d) for r, d in zip(requests, decisions)]
        return self._result(
            output=explanations, confidence=1.0,
            reasoning_summary=f"Generated rule-based explanations for {len(explanations)} decisions "
                               f"(top-3 trust factors + failed ABAC conditions each).")
