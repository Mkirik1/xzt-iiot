"""
objective_function.py
------------------------
Implements the brief's Section 13 self-hardening objective:

    J = alpha*S - beta*L - gamma*FPR - delta*O

where S = security effectiveness (1-ASR), L = normalized authorization
latency, FPR = false positive rate on normal traffic (1-NWFSR),
O = operational disruption (same as FPR here, since STEP_UP_AUTH
friction isn't separately modeled -- kept as a distinct term because
the brief specifies it).

The Blue Agent (objective mode, agents/blue_agent.py) perceives the
current policy, generates candidate mitigations, measures each one's
ASR/NWFSR on a TUNING scenario set that is separate from the scenarios
the cycle is evaluated on, and commits the candidate with the highest
J. A candidate that drives ASR to zero by denying legitimate work loses
on the FPR/O terms, so "DENY EVERYTHING" cannot win.

HISTORY: before the v4 revision this search existed and was unit-tested
but was never called by the hardening loop; the Blue Agent only applied
fixed if-bypassed-then-tighten rules. The paper's contribution statement
is built on J, so the loop now actually optimises it.

DETERMINISM: an earlier version measured wall-clock latency separately
for every candidate. Many candidates tie on ASR/NWFSR, so timer noise
decided which mitigation was applied, and two identical runs could
diverge. Thresholds do not change how much work a decision takes, so L
is now measured once per search and is the same for every candidate:
it is reported, but it cannot affect the choice. Ties go to the
earliest candidate in the grid, which is ordered from the smallest
change upward.
"""

import copy
import itertools
import time
from dataclasses import dataclass

from policy_engine import PolicyEngine
from validation_agent import validate

DEFAULT_WEIGHTS = {"alpha": 1.0, "beta": 0.05, "gamma": 1.0, "delta": 0.5}

# Candidate grid, each axis ordered smallest change first (tie-break order).
DELTA_OPTIONS = [0.0, 0.03, 0.06]
STEP_UP_OPTIONS = [False, True]
ML_WEIGHT_OPTIONS = [0.0, 0.05]
MAX_ML_RISK_WEIGHT = 0.65


def objective_J(asr: float, nwfsr: float, latency_ms: float,
                 weights: dict = DEFAULT_WEIGHTS) -> float:
    S = 1.0 - asr
    L = latency_ms / 10.0            # normalize; ABAC decisions are sub-ms, so this stays small
    FPR = 1.0 - nwfsr
    O = 1.0 - nwfsr                  # operational disruption proxy (see docstring)
    return (weights["alpha"] * S - weights["beta"] * L
            - weights["gamma"] * FPR - weights["delta"] * O)


@dataclass
class Candidate:
    delta_trust: float
    delta_integrity: float
    delta_anomaly: float
    enable_step_up: bool
    asr: float
    nwfsr: float
    latency_ms: float
    J: float
    delta_ml_weight: float = 0.0

    def describe(self) -> str:
        parts = []
        if self.delta_trust:
            parts.append(f"min_trust_score +{self.delta_trust}")
        if self.delta_integrity:
            parts.append(f"min_device_integrity +{self.delta_integrity}")
        if self.delta_anomaly:
            parts.append(f"max_anomaly_score -{self.delta_anomaly}")
        if self.enable_step_up:
            parts.append("STEP_UP_AUTH on zone mismatch")
        if self.delta_ml_weight:
            parts.append(f"ml_risk weight +{self.delta_ml_weight}")
        return ", ".join(parts) if parts else "no change"


def _clone_engine(policy_engine: PolicyEngine) -> PolicyEngine:
    """Deep-copy policies and trust weights, but SHARE the ML bridge:
    copying the trained model and its held-out split for every candidate
    would be slow and pointless (it is read-only)."""
    memo = {}
    bridge = getattr(policy_engine.trust_engine, "ml_bridge", None)
    if bridge is not None:
        memo[id(bridge)] = bridge
    return copy.deepcopy(policy_engine, memo)


def _apply_candidate(policy_engine: PolicyEngine, delta_trust, delta_integrity,
                      delta_anomaly, enable_step_up, delta_ml_weight=0.0):
    for p in policy_engine.policies:
        p.conditions.min_trust_score = min(0.95, max(0.1, p.conditions.min_trust_score + delta_trust))
        p.conditions.min_device_integrity = min(0.95, max(0.1, p.conditions.min_device_integrity + delta_integrity))
        p.conditions.max_anomaly_score = min(0.9, max(0.1, p.conditions.max_anomaly_score - delta_anomaly))
        if enable_step_up:
            p.conditions.require_step_up_if_zone_mismatch = True
    if delta_ml_weight:
        w = policy_engine.trust_engine.weights
        w.ml_risk = min(MAX_ML_RISK_WEIGHT, w.ml_risk + delta_ml_weight)


def apply_candidate(policy_engine: PolicyEngine, candidate: Candidate):
    """Commit a winning candidate to the actual (non-copy) engine --
    search_best_candidate only evaluates clones internally."""
    _apply_candidate(policy_engine, candidate.delta_trust, candidate.delta_integrity,
                      candidate.delta_anomaly, candidate.enable_step_up,
                      candidate.delta_ml_weight)


def search_best_candidate(policy_engine: PolicyEngine, attack_reqs: list, normal_reqs: list,
                           weights: dict = DEFAULT_WEIGHTS, return_all: bool = False):
    """Evaluate every candidate's REAL measured ASR/NWFSR on the given
    scenarios and return the highest-J one (ties: smallest change).
    The ML-weight axis is only searched when the trust engine actually
    consults the Track-1 model; otherwise it would have no effect."""
    uses_ml = getattr(policy_engine.trust_engine, "ml_bridge", None) is not None
    ml_options = ML_WEIGHT_OPTIONS if uses_ml else [0.0]

    t0 = time.perf_counter()
    validate(policy_engine, attack_reqs, normal_reqs)
    latency_ms = (time.perf_counter() - t0) / max(1, len(attack_reqs) + len(normal_reqs)) * 1000

    best, evaluated = None, []
    for dt, di, da, su, dm in itertools.product(DELTA_OPTIONS, DELTA_OPTIONS, DELTA_OPTIONS,
                                                STEP_UP_OPTIONS, ml_options):
        trial = _clone_engine(policy_engine)
        _apply_candidate(trial, dt, di, da, su, dm)
        result = validate(trial, attack_reqs, normal_reqs)
        J = objective_J(result.asr, result.nwfsr, latency_ms, weights)
        cand = Candidate(dt, di, da, su, result.asr, result.nwfsr, latency_ms, J, dm)
        evaluated.append(cand)
        if best is None or cand.J > best.J:
            best = cand

    return (best, evaluated) if return_all else best
