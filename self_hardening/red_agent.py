"""
red_agent.py
--------------
SAFETY: This agent NEVER touches a network, a real host, or a real
credential. It only constructs Python dataclass instances representing
*abstract attribute combinations* that a real attacker's traffic might
exhibit (e.g. "high identity confidence but from the wrong network
zone"). There is no scanning, exploitation, credential theft, or
external connectivity of any kind here -- this satisfies the safety
constraints in the project brief by construction, not by a runtime
allowlist (there is nothing here that COULD reach an external target).

Generates the 5 abstract attack-scenario classes from the scoped
brief: stolen_credentials, compromised_device, network_zone_mismatch,
behavioral_anomaly, abnormal_access_time.
"""

import random
from typing import List

from attributes import (AccessRequest, SubjectAttributes, DeviceAttributes,
                         NetworkAttributes, ContextAttributes)

SCENARIOS = ["stolen_credentials", "compromised_device",
             "network_zone_mismatch", "behavioral_anomaly",
             "abnormal_access_time", "privilege_escalation_attempt",
             "replay_simulation", "firmware_integrity_failure"]

RESOURCE_ACTION_PAIRS = [
    ("PLC_CONTROLLER", "WRITE_SETPOINT", "engineering"),
    ("HMI_WORKSTATION", "READ_STATUS", "operations"),
    ("PUMP_CONTROLLER", "START_STOP", "operations"),
]


def _base_legit_request(rid: str, rng: random.Random) -> AccessRequest:
    resource, action, zone = rng.choice(RESOURCE_ACTION_PAIRS)
    return AccessRequest(
        request_id=rid,
        subject=SubjectAttributes(
            user_id=f"user_{rng.randint(1,20)}", role=rng.choice(["engineer", "operator", "maintenance"]),
            identity_confidence=rng.uniform(0.85, 0.98),
            authentication_strength=rng.uniform(0.85, 0.98)),
        device=DeviceAttributes(device_id=f"dev_{rng.randint(1,50)}",
                                 device_integrity=rng.uniform(0.85, 0.99), patch_level=rng.uniform(0.8, 1.0)),
        network=NetworkAttributes(source_zone=zone, expected_zone=zone),
        context=ContextAttributes(behavioral_trust=rng.uniform(0.8, 0.98),
                                   anomaly_score=rng.uniform(0.02, 0.2), access_hour=rng.randint(7, 18)),
        resource=resource, action=action, label="normal",
    )


def _apply_scenario(req: AccessRequest, scenario: str, rng: random.Random) -> AccessRequest:
    """Perturb a base (legitimate-looking) request into an attack scenario.

    Each scenario keeps SOME attributes attacker-favorable (e.g. valid
    stolen credentials still show high identity_confidence) -- that's
    exactly what makes these realistic policy-bypass tests rather than
    trivially-detectable noise.
    """
    if scenario == "stolen_credentials":
        req.context.behavioral_trust = rng.uniform(0.2, 0.4)
        req.context.anomaly_score = rng.uniform(0.5, 0.75)
    elif scenario == "compromised_device":
        req.device.device_integrity = rng.uniform(0.3, 0.55)
        req.context.anomaly_score = rng.uniform(0.4, 0.65)
    elif scenario == "network_zone_mismatch":
        req.network.source_zone = "unknown_external"
    elif scenario == "behavioral_anomaly":
        req.context.behavioral_trust = rng.uniform(0.1, 0.3)
        req.context.anomaly_score = rng.uniform(0.55, 0.8)
    elif scenario == "abnormal_access_time":
        req.context.access_hour = rng.choice([1, 2, 3, 4, 23])
        req.context.anomaly_score = rng.uniform(0.4, 0.6)
    elif scenario == "privilege_escalation_attempt":
        # legitimate initial identity/auth, but a sudden anomalous attempt
        # to act outside normal behavioral pattern (the classic
        # "valid session, unusual escalation" bypass shape)
        req.context.behavioral_trust = rng.uniform(0.15, 0.35)
        req.context.anomaly_score = rng.uniform(0.6, 0.85)
    elif scenario == "replay_simulation":
        # stale/replayed session metadata: auth strength degraded
        # (an old, reused token/session isn't as strong as a fresh one),
        # timing looks slightly off vs. normal behavior
        req.subject.authentication_strength = rng.uniform(0.4, 0.6)
        req.context.behavioral_trust = rng.uniform(0.3, 0.5)
        req.context.anomaly_score = rng.uniform(0.35, 0.55)
    elif scenario == "firmware_integrity_failure":
        # worse than compromised_device: integrity check outright fails
        req.device.device_integrity = rng.uniform(0.05, 0.3)
        req.device.patch_level = rng.uniform(0.0, 0.2)
    req.label = scenario
    req.metadata["attack_scenario"] = scenario
    return req


def generate_attack_scenarios(n_per_type: int = 8, seed: int = 42) -> List[AccessRequest]:
    """Test set: n_per_type instances of each of the 5 scenario classes.
    `seed` makes this reproducible AND lets the multi-seed runner draw
    independent scenario sets to test statistical robustness (RQ1)."""
    rng = random.Random(seed)
    out = []
    i = 0
    for scenario in SCENARIOS:
        for _ in range(n_per_type):
            req = _base_legit_request(f"atk_{i:03d}", rng)
            req = _apply_scenario(req, scenario, rng)
            out.append(req)
            i += 1
    return out


def generate_attack_scenarios_weighted(base_n_per_type: int, weights: dict,
                                        seed: int = 42) -> List[AccessRequest]:
    """Same as generate_attack_scenarios, but scales the count per
    scenario type by a priority weight (e.g. from ThreatIntelAgent's
    severity signal) instead of using a flat count for every type.
    weights not present for a scenario type default to 1.0 (no bias)."""
    rng = random.Random(seed)
    out = []
    i = 0
    for scenario in SCENARIOS:
        n = max(1, round(base_n_per_type * weights.get(scenario, 1.0)))
        for _ in range(n):
            req = _base_legit_request(f"atk_{i:03d}", rng)
            req = _apply_scenario(req, scenario, rng)
            out.append(req)
            i += 1
    return out
