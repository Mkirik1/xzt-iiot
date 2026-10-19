"""
blue_agent.py
----------------
Rule-based (no ML search yet -- that is Track B's Pareto optimization,
explicitly deferred) mitigation proposer. Looks at which attack
scenario TYPES bypassed the current policy set this cycle, and applies
bounded threshold tightening addressing those specific weaknesses.

Design choice to avoid the brief's "do not let security optimization
trivially become DENY EVERYTHING" trap: every step is small and
bounded (capped thresholds), and the loop measures NWFSR every cycle
so a policy that overcorrects and blocks legitimate traffic is visible
in the results, not hidden.
"""

from dataclasses import dataclass
from typing import List

from policy_engine import PolicyEngine
from trust_engine import TrustEngine
from validation_agent import ValidationResult

STEP = 0.05
MAX_TRUST_THRESHOLD = 0.90
MAX_INTEGRITY_THRESHOLD = 0.90
MIN_ANOMALY_CEILING = 0.15
MAX_ANOMALY_WEIGHT = 0.65
MAX_ML_RISK_WEIGHT = 0.65


@dataclass
class MitigationProposal:
    cycle: int
    bypassed_scenario_counts: dict
    changes: List[str]


def propose_and_apply(policy_engine: PolicyEngine, trust_engine: TrustEngine,
                       validation_result: ValidationResult, cycle: int) -> MitigationProposal:
    bypassed = validation_result.bypassed_scenarios
    counts = {s: bypassed.count(s) for s in set(bypassed)}
    changes = []

    if not bypassed:
        return MitigationProposal(cycle=cycle, bypassed_scenario_counts=counts,
                                   changes=["No bypasses this cycle -- no mitigation needed."])

    # network_zone_mismatch bypasses -> require step-up auth on zone mismatch
    if counts.get("network_zone_mismatch", 0) > 0:
        for p in policy_engine.policies:
            if not p.conditions.require_step_up_if_zone_mismatch:
                p.conditions.require_step_up_if_zone_mismatch = True
        changes.append("Enabled STEP_UP_AUTH requirement on network zone mismatch "
                        f"({counts['network_zone_mismatch']} bypasses observed).")

    # compromised_device bypasses -> raise min_device_integrity
    if counts.get("compromised_device", 0) > 0:
        for p in policy_engine.policies:
            p.conditions.min_device_integrity = min(
                MAX_INTEGRITY_THRESHOLD, p.conditions.min_device_integrity + STEP)
        changes.append("Raised min_device_integrity threshold by "
                        f"{STEP} across all policies ({counts['compromised_device']} bypasses).")

    # stolen_credentials / behavioral_anomaly / abnormal_access_time bypasses ->
    # tighten anomaly ceiling and increase the anomaly weight in the trust score
    anomaly_related = (counts.get("stolen_credentials", 0)
                        + counts.get("behavioral_anomaly", 0)
                        + counts.get("abnormal_access_time", 0))
    if anomaly_related > 0:
        for p in policy_engine.policies:
            p.conditions.max_anomaly_score = max(
                MIN_ANOMALY_CEILING, p.conditions.max_anomaly_score - STEP)
        trust_engine.weights.anomaly_risk = min(
            MAX_ANOMALY_WEIGHT, trust_engine.weights.anomaly_risk + STEP)
        changes.append(f"Lowered max_anomaly_score ceiling by {STEP} and raised trust-engine "
                        f"anomaly_risk weight by {STEP} ({anomaly_related} anomaly-related bypasses).")

    # BUG FOUND DURING THE TRACK1/TRACK2 INTEGRATION FIX: privilege_escalation_attempt,
    # replay_simulation and firmware_integrity_failure (3 of Red Agent's 8 scenario
    # classes -- added in a later revision than the original 5-scenario mitigation
    # rules above) had NO mitigation lever at all here. A bypass from any of these
    # three could never be reduced by a single hardening cycle, no matter how many
    # cycles ran -- their ASR contribution was structurally stuck. Now routed through
    # the one lever that genuinely responds to all three (each is, at its core, a
    # traffic/behavior-level compromise signature): raise the ml_risk weight so the
    # Track-1 model's P(malicious) output counts for more in the trust score.
    ml_related = (counts.get("privilege_escalation_attempt", 0)
                  + counts.get("replay_simulation", 0)
                  + counts.get("firmware_integrity_failure", 0))
    if ml_related > 0:
        trust_engine.weights.ml_risk = min(
            MAX_ML_RISK_WEIGHT, trust_engine.weights.ml_risk + STEP)
        changes.append(f"Raised trust-engine ml_risk weight by {STEP} "
                        f"({ml_related} bypasses from scenarios with no prior mitigation lever: "
                        "privilege_escalation_attempt / replay_simulation / firmware_integrity_failure).")

    return MitigationProposal(cycle=cycle, bypassed_scenario_counts=counts, changes=changes)
