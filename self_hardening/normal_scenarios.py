"""
normal_scenarios.py
----------------------
Legitimate IIoT operation scenarios, used to measure Normal Workflow
Success Rate (NWFSR) -- i.e. false positives. A hardening cycle that
raises Attack Success Rate protection but tanks NWFSR is not a good
mitigation; the Validation Agent scores both together.
"""

import random
from typing import List

from attributes import (AccessRequest, SubjectAttributes, DeviceAttributes,
                         NetworkAttributes, ContextAttributes)
from red_agent import RESOURCE_ACTION_PAIRS

# Roles actually permitted per resource by config/policies.yaml. Normal
# (legitimate) scenarios must draw a role from this set for their target
# resource, or they fail on a role mismatch that has nothing to do with
# trust/anomaly scoring -- an artifact of test-data generation, not a
# real finding about the policy's precision. (Caught by inspecting why
# NWFSR was suspiciously identical -- exactly 0.700 -- across every
# seed and cycle: PUMP_CONTROLLER doesn't allow the "maintenance" role,
# and the old i % 3 cycling assigned it anyway for 30% of requests.)
ALLOWED_ROLES_BY_RESOURCE = {
    "PLC_CONTROLLER": ["engineer", "maintenance"],
    "HMI_WORKSTATION": ["engineer", "operator", "maintenance"],
    "PUMP_CONTROLLER": ["operator", "engineer"],
}


def generate_normal_scenarios(n: int = 10, seed: int = 7) -> List[AccessRequest]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        resource, action, zone = RESOURCE_ACTION_PAIRS[i % len(RESOURCE_ACTION_PAIRS)]
        role = rng.choice(ALLOWED_ROLES_BY_RESOURCE[resource])
        req = AccessRequest(
            request_id=f"norm_{i:03d}",
            subject=SubjectAttributes(user_id=f"legit_user_{i}", role=role,
                                       identity_confidence=rng.uniform(0.82, 0.97),
                                       authentication_strength=rng.uniform(0.82, 0.97)),
            device=DeviceAttributes(device_id=f"legit_dev_{i}",
                                     device_integrity=rng.uniform(0.82, 0.98), patch_level=rng.uniform(0.8, 1.0)),
            network=NetworkAttributes(source_zone=zone, expected_zone=zone),
            context=ContextAttributes(behavioral_trust=rng.uniform(0.78, 0.96),
                                       anomaly_score=rng.uniform(0.03, 0.22), access_hour=rng.randint(8, 17)),
            resource=resource, action=action, label="normal",
        )
        out.append(req)
    return out
