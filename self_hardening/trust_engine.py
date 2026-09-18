"""
trust_engine.py
------------------
Configurable weighted TrustScore, per the brief's formula:

  TrustScore = w1*IdentityConfidence + w2*DeviceIntegrity
             + w3*BehavioralTrust + w4*NetworkTrust
             + w5*AuthenticationStrength - w6*AnomalyRisk

Normalized to [0, 1]. Weights are loaded from config, never hardcoded,
so the Blue Agent can propose weight changes (e.g. raise w6, the
anomaly weight) as one class of mitigation.
"""

from dataclasses import dataclass

import yaml

from attributes import AccessRequest


@dataclass
class TrustWeights:
    identity_confidence: float
    device_integrity: float
    behavioral_trust: float
    network_trust: float
    authentication_strength: float
    anomaly_risk: float

    @classmethod
    def from_yaml(cls, path: str) -> "TrustWeights":
        with open(path) as f:
            data = yaml.safe_load(f)["weights"]
        return cls(**data)

    def max_possible_score(self) -> float:
        """Sum of the positive weights -- used to normalize into [0,1]."""
        return (self.identity_confidence + self.device_integrity +
                self.behavioral_trust + self.network_trust +
                self.authentication_strength)


class TrustEngine:
    def __init__(self, weights: TrustWeights):
        self.weights = weights

    def score(self, req: AccessRequest) -> float:
        w = self.weights
        raw = (
            w.identity_confidence * req.subject.identity_confidence
            + w.device_integrity * req.device.device_integrity
            + w.behavioral_trust * req.context.behavioral_trust
            + w.network_trust * req.network_trust
            + w.authentication_strength * req.subject.authentication_strength
            - w.anomaly_risk * req.context.anomaly_score
        )
        max_score = w.max_possible_score()
        normalized = raw / max_score if max_score > 0 else 0.0
        return max(0.0, min(1.0, normalized))

    def factor_breakdown(self, req: AccessRequest) -> dict:
        """Per-factor contribution, for rule-based explainability."""
        w = self.weights
        return {
            "identity_confidence": w.identity_confidence * req.subject.identity_confidence,
            "device_integrity": w.device_integrity * req.device.device_integrity,
            "behavioral_trust": w.behavioral_trust * req.context.behavioral_trust,
            "network_trust": w.network_trust * req.network_trust,
            "authentication_strength": w.authentication_strength * req.subject.authentication_strength,
            "anomaly_risk": -w.anomaly_risk * req.context.anomaly_score,
        }
