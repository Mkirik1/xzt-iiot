"""
trust_engine.py
------------------
Configurable weighted TrustScore, per the brief's formula, EXTENDED
with a 7th factor -- ml_risk -- that is the actual trained Track-1
XGBoost model's P(malicious) output, not another hand-set ABAC
attribute:

  TrustScore = w1*IdentityConfidence + w2*DeviceIntegrity
             + w3*BehavioralTrust + w4*NetworkTrust
             + w5*AuthenticationStrength - w6*AnomalyRisk
             - w7*MLModelRisk

Normalized to [0, 1]. Weights are loaded from config, never hardcoded,
so the Blue Agent can propose weight changes (e.g. raise w6/w7) as one
class of mitigation.

INTEGRATION FIX (responds directly to both rejection reviews' core
criticism): previously MLModelRisk did not exist and Track 1's trained
model was never consulted by this engine at all -- every ABAC decision
ran purely on hand-authored weighted attributes. Now, when a
MLTrustBridge is supplied, every single score() call also runs the
request's scenario through the ACTUAL trained XGBoost model (via
ml_trust_bridge.py) and folds its output in as its own weighted,
independently-visible factor. See ml_trust_bridge.py's docstring for
exactly how a request is turned into a traffic feature row and why
that mapping is honest rather than hand-waved.

If no bridge is supplied (ml_bridge=None, the default), the engine
falls back to the original ABAC-only formula unchanged -- this keeps
every existing caller and test backward compatible, and gives the
ablation study (ablation_experiment.py Experiment F) a clean "ML
integration OFF" baseline to compare against "ML integration ON".
"""

from dataclasses import dataclass
from typing import Optional

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
    ml_risk: float = 0.0   # weight on the Track-1 model's P(malicious); 0.0 = ML-disconnected baseline

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
    def __init__(self, weights: TrustWeights, ml_bridge: Optional[object] = None):
        self.weights = weights
        self.ml_bridge = ml_bridge  # ml_trust_bridge.MLTrustBridge instance, or None

    def _ml_risk_score(self, req: AccessRequest) -> float:
        if self.ml_bridge is None:
            return 0.0
        return self.ml_bridge.score_scenario(req.label, req.resource, req.request_id)

    def score(self, req: AccessRequest) -> float:
        w = self.weights
        ml_risk = self._ml_risk_score(req)
        raw = (
            w.identity_confidence * req.subject.identity_confidence
            + w.device_integrity * req.device.device_integrity
            + w.behavioral_trust * req.context.behavioral_trust
            + w.network_trust * req.network_trust
            + w.authentication_strength * req.subject.authentication_strength
            - w.anomaly_risk * req.context.anomaly_score
            - w.ml_risk * ml_risk
        )
        max_score = w.max_possible_score()
        normalized = raw / max_score if max_score > 0 else 0.0
        return max(0.0, min(1.0, normalized))

    def factor_breakdown(self, req: AccessRequest) -> dict:
        """Per-factor contribution, for rule-based explainability. Now
        includes ml_model_risk, so the explanation surface shows the
        trained model's contribution to the decision side-by-side with
        the ABAC attributes -- not as a separate, disconnected system."""
        w = self.weights
        ml_risk = self._ml_risk_score(req)
        return {
            "identity_confidence": w.identity_confidence * req.subject.identity_confidence,
            "device_integrity": w.device_integrity * req.device.device_integrity,
            "behavioral_trust": w.behavioral_trust * req.context.behavioral_trust,
            "network_trust": w.network_trust * req.network_trust,
            "authentication_strength": w.authentication_strength * req.subject.authentication_strength,
            "anomaly_risk": -w.anomaly_risk * req.context.anomaly_score,
            "ml_model_risk": -w.ml_risk * ml_risk,
        }
