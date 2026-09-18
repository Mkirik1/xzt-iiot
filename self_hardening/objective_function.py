"""
objective_function.py
------------------------
Implements the brief's Section 13 self-hardening objective:

    J = alpha*S - beta*L - gamma*FPR - delta*O

where S = security effectiveness (1-ASR), L = normalized authorization
latency, FPR = false positive rate on normal traffic (1-NWFSR),
O = operational disruption (same as FPR here, since STEP_UP_AUTH
friction isn't separately modeled -- kept as a distinct term because
the brief specifies it, with a placeholder that can be extended, e.g.
STEP_UP_AUTH weighted as partial disruption).

The Blue Agent searches candidate policy adjustments (grid over
threshold deltas) and selects the one maximizing J, rather than always
applying a fixed-size step -- this is what makes it a real (if simple)
optimization search rather than a hardcoded rule, and it structurally
prevents "DENY EVERYTHING": a candidate that tanks NWFSR is penalized
by the FPR/O terms and will not win even if it drives ASR to zero.
"""

import copy
import itertools
import time
from dataclasses import dataclass

import yaml

from policy_engine import PolicyEngine
from trust_engine import TrustEngine
from validation_agent import validate

DEFAULT_WEIGHTS = {"alpha": 1.0, "beta": 0.05, "gamma": 1.0, "delta": 0.5}


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


def _apply_candidate(policy_engine: PolicyEngine, delta_trust, delta_integrity,
                      delta_anomaly, enable_step_up):
    for p in policy_engine.policies:
        p.conditions.min_trust_score = min(0.95, max(0.1, p.conditions.min_trust_score + delta_trust))
        p.conditions.min_device_integrity = min(0.95, max(0.1, p.conditions.min_device_integrity + delta_integrity))
        p.conditions.max_anomaly_score = min(0.9, max(0.1, p.conditions.max_anomaly_score - delta_anomaly))
        if enable_step_up:
            p.conditions.require_step_up_if_zone_mismatch = True


def apply_candidate(policy_engine: PolicyEngine, candidate: Candidate):
    """Apply a winning candidate's deltas to the actual (non-copy)
    policy engine -- search_best_candidate only evaluates deepcopies
    internally, so the caller must explicitly commit the winner."""
    _apply_candidate(policy_engine, candidate.delta_trust, candidate.delta_integrity,
                      candidate.delta_anomaly, candidate.enable_step_up)


def search_best_candidate(policy_engine: PolicyEngine, attack_reqs: list, normal_reqs: list,
                           weights: dict = DEFAULT_WEIGHTS) -> Candidate:
    """Grid search over small threshold deltas; evaluates each candidate's
    REAL measured ASR/NWFSR/latency (not estimated), picks the highest J.
    This is genuinely evaluating each candidate against the actual
    scenario suite -- a small but real Pareto-style search, not a
    single-rule heuristic."""
    delta_options = [0.0, 0.03, 0.06]
    step_up_options = [False, True]
    best: Candidate = None

    for dt, di, da, su in itertools.product(delta_options, delta_options, delta_options, step_up_options):
        trial_engine = copy.deepcopy(policy_engine)
        _apply_candidate(trial_engine, dt, di, da, su)

        t0 = time.perf_counter()
        result = validate(trial_engine, attack_reqs, normal_reqs)
        latency_ms = (time.perf_counter() - t0) / (len(attack_reqs) + len(normal_reqs)) * 1000

        J = objective_J(result.asr, result.nwfsr, latency_ms, weights)
        cand = Candidate(dt, di, da, su, result.asr, result.nwfsr, latency_ms, J)
        if best is None or cand.J > best.J:
            best = cand

    return best
