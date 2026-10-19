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


BOUNDARY_KINDS = ["night_shift_maintenance", "aging_device", "unusual_but_legitimate"]


def generate_boundary_normal_scenarios(n: int = 50, seed: int = 11) -> List[AccessRequest]:
    """Legitimate work that sits near the policy's decision boundaries,
    where false positives actually happen (generalization_experiment.py,
    reviewer R4). Every request is genuinely legitimate (label "normal"):
      night_shift_maintenance  a maintenance engineer working at night;
                               ABAC-wise this looks like abnormal_access_time
      aging_device             an older but not compromised device:
                               integrity 0.62-0.75, lower patch level
      unusual_but_legitimate   a rare but authorised task: behaviour less
                               typical, anomaly 0.30-0.50
    Roles always match the target resource's allowed roles, and zones are
    correct, so a block here is a real false positive of the trust logic."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        kind = BOUNDARY_KINDS[i % len(BOUNDARY_KINDS)]
        # (i // kinds) so every boundary kind visits every resource, rather
        # than kind and resource advancing in lockstep
        resource, action, zone = RESOURCE_ACTION_PAIRS[(i // len(BOUNDARY_KINDS)) % len(RESOURCE_ACTION_PAIRS)]
        role = rng.choice(ALLOWED_ROLES_BY_RESOURCE[resource])
        integrity, patch = rng.uniform(0.82, 0.98), rng.uniform(0.8, 1.0)
        behaviour, anomaly, hour = rng.uniform(0.78, 0.96), rng.uniform(0.03, 0.22), rng.randint(8, 17)
        if kind == "night_shift_maintenance":
            if "maintenance" in ALLOWED_ROLES_BY_RESOURCE[resource]:
                role = "maintenance"
            hour = rng.choice([22, 23, 0, 1, 2, 3, 4, 5])
            anomaly = rng.uniform(0.15, 0.35)
        elif kind == "aging_device":
            integrity, patch = rng.uniform(0.62, 0.75), rng.uniform(0.4, 0.7)
        else:
            behaviour, anomaly = rng.uniform(0.6, 0.75), rng.uniform(0.3, 0.5)
        out.append(AccessRequest(
            request_id=f"edge_{i:03d}",
            subject=SubjectAttributes(user_id=f"legit_user_b{i}", role=role,
                                       identity_confidence=rng.uniform(0.82, 0.97),
                                       authentication_strength=rng.uniform(0.82, 0.97)),
            device=DeviceAttributes(device_id=f"legit_dev_b{i}", device_integrity=integrity,
                                     patch_level=patch),
            network=NetworkAttributes(source_zone=zone, expected_zone=zone),
            context=ContextAttributes(behavioral_trust=behaviour, anomaly_score=anomaly,
                                       access_hour=hour),
            resource=resource, action=action, label="normal",
            metadata={"boundary_kind": kind},
        ))
    return out
