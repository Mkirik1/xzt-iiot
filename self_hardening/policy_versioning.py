"""
policy_versioning.py
-----------------------
Brief Section 33: every policy update creates a new version with
diff/reason/validation_result/created_by/approved_by/deployment_time,
supports rollback. Section 11 state machine: PROPOSED / VALIDATED /
APPROVED / DEPLOYED / REJECTED.
"""

import copy
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

STATES = ["PROPOSED", "VALIDATED", "APPROVED", "DEPLOYED", "REJECTED"]


@dataclass
class PolicyVersion:
    version_id: int
    policy_snapshot: List[Dict[str, Any]]   # full serialized policy conditions
    diff: str
    reason: str
    source_threat: Optional[str]
    validation_result: Optional[Dict[str, Any]]
    state: str = "PROPOSED"
    created_by: str = "blue_agent"
    approved_by: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    deployed_at: Optional[float] = None


class PolicyVersionHistory:
    def __init__(self):
        self.versions: List[PolicyVersion] = []
        self._next_id = 1

    def _snapshot(self, policy_engine) -> List[Dict[str, Any]]:
        return [{
            "policy_id": p.policy_id, "min_trust_score": p.conditions.min_trust_score,
            "min_device_integrity": p.conditions.min_device_integrity,
            "max_anomaly_score": p.conditions.max_anomaly_score,
            "require_step_up_if_zone_mismatch": p.conditions.require_step_up_if_zone_mismatch,
        } for p in policy_engine.policies]

    def _diff(self, before: List[Dict], after: List[Dict]) -> str:
        lines = []
        for b, a in zip(before, after):
            changes = [f"{k}: {b[k]} -> {a[k]}" for k in b if b[k] != a[k]]
            if changes:
                lines.append(f"{b['policy_id']}: " + "; ".join(changes))
        return " | ".join(lines) if lines else "no change"

    def propose(self, policy_engine_before, policy_engine_after, reason: str,
                source_threat: Optional[str] = None,
                validation_result: Optional[Dict] = None) -> PolicyVersion:
        before = self._snapshot(policy_engine_before)
        after = self._snapshot(policy_engine_after)
        version = PolicyVersion(
            version_id=self._next_id, policy_snapshot=after,
            diff=self._diff(before, after), reason=reason,
            source_threat=source_threat, validation_result=validation_result)
        self._next_id += 1
        self.versions.append(version)
        return version

    def transition(self, version_id: int, new_state: str, approved_by: Optional[str] = None):
        assert new_state in STATES, f"invalid state {new_state}"
        v = self._get(version_id)
        v.state = new_state
        if new_state == "APPROVED":
            v.approved_by = approved_by or "auto_approved_semi_automatic_mode"
        if new_state == "DEPLOYED":
            v.deployed_at = time.time()

    def rollback_to(self, version_id: int, policy_engine):
        """Restore a policy_engine's conditions to a prior version's snapshot."""
        v = self._get(version_id)
        snap_by_id = {s["policy_id"]: s for s in v.policy_snapshot}
        for p in policy_engine.policies:
            s = snap_by_id.get(p.policy_id)
            if s:
                p.conditions.min_trust_score = s["min_trust_score"]
                p.conditions.min_device_integrity = s["min_device_integrity"]
                p.conditions.max_anomaly_score = s["max_anomaly_score"]
                p.conditions.require_step_up_if_zone_mismatch = s["require_step_up_if_zone_mismatch"]
        return v

    def _get(self, version_id: int) -> PolicyVersion:
        for v in self.versions:
            if v.version_id == version_id:
                return v
        raise KeyError(f"no version {version_id}")

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump([asdict(v) for v in self.versions], f, indent=2)
