"""
policy_engine.py (self_hardening module)
-------------------------------------------
ABAC Policy Decision Point. Evaluates an AccessRequest against the
current policy set + trust score, returns one of:
  ALLOW / DENY / STEP_UP_AUTH
(QUARANTINE deferred, per the scoped brief's Track A.)

Includes rule-based explainability: which specific condition(s)
caused the decision, in plain language -- no ML/SHAP needed here,
this is a separate, simpler explainability layer from the SHAP one
used for the traffic-classification trust model elsewhere in the
project.
"""

from dataclasses import dataclass, field
from typing import List, Optional

import yaml

from attributes import AccessRequest
from trust_engine import TrustEngine


@dataclass
class PolicyCondition:
    allowed_roles: List[str]
    min_trust_score: float
    min_device_integrity: float
    max_anomaly_score: float
    allowed_network_zones: List[str]
    require_step_up_if_zone_mismatch: bool = False


@dataclass
class Policy:
    policy_id: str
    resource: str
    action: str
    conditions: PolicyCondition
    version: int = 1


CRITICAL_INTEGRITY_THRESHOLD = 0.30   # below this, quarantine rather than just deny --
                                        # a single failed request isn't just "no access
                                        # this time", it signals the DEVICE itself may be
                                        # compromised and should stop being trusted at all


@dataclass
class Decision:
    request_id: str
    policy_id: Optional[str]
    decision: str               # ALLOW / DENY / STEP_UP_AUTH / QUARANTINE
    trust_score: float
    explanation: str
    failed_conditions: List[str] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, policies_path: str, trust_engine: TrustEngine):
        self.trust_engine = trust_engine
        self.policies = self._load(policies_path)

    def _load(self, path: str) -> List[Policy]:
        with open(path) as f:
            data = yaml.safe_load(f)
        out = []
        for p in data["policies"]:
            cond = PolicyCondition(**p["conditions"])
            out.append(Policy(policy_id=p["policy_id"], resource=p["resource"],
                               action=p["action"], conditions=cond))
        return out

    def find_policy(self, resource: str, action: str) -> Optional[Policy]:
        for p in self.policies:
            if p.resource == resource and p.action == action:
                return p
        return None

    def evaluate(self, req: AccessRequest) -> Decision:
        policy = self.find_policy(req.resource, req.action)
        if policy is None:
            return Decision(req.request_id, None, "DENY", 0.0,
                             "No matching policy for this resource/action -- default deny.")

        trust_score = self.trust_engine.score(req)
        c = policy.conditions
        failed = []

        if req.subject.role not in c.allowed_roles:
            failed.append(f"role '{req.subject.role}' not in allowed_roles {c.allowed_roles}")
        if trust_score < c.min_trust_score:
            failed.append(f"trust_score {trust_score:.2f} < min_trust_score {c.min_trust_score}")
        if req.device.device_integrity < c.min_device_integrity:
            failed.append(f"device_integrity {req.device.device_integrity:.2f} "
                           f"< min_device_integrity {c.min_device_integrity}")
        if req.context.anomaly_score > c.max_anomaly_score:
            failed.append(f"anomaly_score {req.context.anomaly_score:.2f} "
                           f"> max_anomaly_score {c.max_anomaly_score}")

        zone_mismatch = req.network.source_zone not in c.allowed_network_zones
        if zone_mismatch:
            failed.append(f"source_zone '{req.network.source_zone}' "
                           f"not in allowed_network_zones {c.allowed_network_zones}")

        if not failed:
            return Decision(req.request_id, policy.policy_id, "ALLOW", trust_score,
                             "All ABAC conditions satisfied.")

        # a critically low device-integrity reading means the DEVICE is the
        # problem, not just this one request -- quarantine rather than deny,
        # so future requests from it are flagged too (brief Section 7)
        if req.device.device_integrity < CRITICAL_INTEGRITY_THRESHOLD:
            return Decision(req.request_id, policy.policy_id, "QUARANTINE", trust_score,
                             f"Device integrity critically low "
                             f"({req.device.device_integrity:.2f} < {CRITICAL_INTEGRITY_THRESHOLD}) -- "
                             f"device quarantined pending manual firmware verification.",
                             failed_conditions=failed)

        # zone mismatch alone (everything else fine) -> STEP_UP_AUTH if policy allows it,
        # otherwise DENY. This gives the Blue Agent a real lever to pull later.
        only_zone_mismatch = failed == [failed[0]] and zone_mismatch
        if only_zone_mismatch and c.require_step_up_if_zone_mismatch:
            return Decision(req.request_id, policy.policy_id, "STEP_UP_AUTH", trust_score,
                             "Network zone mismatch detected; step-up authentication required.",
                             failed_conditions=failed)

        return Decision(req.request_id, policy.policy_id, "DENY", trust_score,
                         "Access denied: " + "; ".join(failed),
                         failed_conditions=failed)

    def save(self, path: str, version_bump: bool = True):
        """Persist current policy set back to YAML (used after Blue Agent updates)."""
        out = {"version": 2 if version_bump else 1, "policies": []}
        for p in self.policies:
            out["policies"].append({
                "policy_id": p.policy_id,
                "resource": p.resource,
                "action": p.action,
                "conditions": {
                    "allowed_roles": p.conditions.allowed_roles,
                    "min_trust_score": p.conditions.min_trust_score,
                    "min_device_integrity": p.conditions.min_device_integrity,
                    "max_anomaly_score": p.conditions.max_anomaly_score,
                    "allowed_network_zones": p.conditions.allowed_network_zones,
                    "require_step_up_if_zone_mismatch": p.conditions.require_step_up_if_zone_mismatch,
                },
                "decision_if_match": "ALLOW",
                "decision_if_no_match": "DENY",
            })
        with open(path, "w") as f:
            yaml.dump(out, f, sort_keys=False)
