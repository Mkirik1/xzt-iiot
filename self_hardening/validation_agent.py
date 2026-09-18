"""
validation_agent.py
----------------------
Runs the attack-scenario set and the normal-operation set against the
current policy engine, computes:
  - Attack Success Rate (ASR): fraction of attack scenarios that got ALLOW
    (a successful bypass -- STEP_UP_AUTH and DENY both count as blocked)
  - Normal Workflow Success Rate (NWFSR): fraction of legitimate
    scenarios that got ALLOW (STEP_UP_AUTH counts as partial friction,
    not full success, since it interrupts the operator)

No numbers are fabricated: every value here comes from actually
running PolicyEngine.evaluate() over the generated scenario sets.
"""

from dataclasses import dataclass
from typing import List

from attributes import AccessRequest
from policy_engine import PolicyEngine, Decision


@dataclass
class ValidationResult:
    asr: float
    nwfsr: float
    n_attacks: int
    n_normal: int
    attack_decisions: List[Decision]
    normal_decisions: List[Decision]
    bypassed_scenarios: List[str]   # scenario labels that got ALLOW


def validate(engine: PolicyEngine, attack_reqs: List[AccessRequest],
             normal_reqs: List[AccessRequest]) -> ValidationResult:
    attack_decisions = [engine.evaluate(r) for r in attack_reqs]
    normal_decisions = [engine.evaluate(r) for r in normal_reqs]

    bypassed = [r.label for r, d in zip(attack_reqs, attack_decisions) if d.decision == "ALLOW"]
    asr = len(bypassed) / len(attack_reqs) if attack_reqs else 0.0

    normal_success = sum(1 for d in normal_decisions if d.decision == "ALLOW")
    nwfsr = normal_success / len(normal_reqs) if normal_reqs else 0.0

    return ValidationResult(asr=asr, nwfsr=nwfsr, n_attacks=len(attack_reqs),
                             n_normal=len(normal_reqs), attack_decisions=attack_decisions,
                             normal_decisions=normal_decisions, bypassed_scenarios=bypassed)
