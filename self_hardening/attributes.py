"""
attributes.py
--------------
Attribute data model for the ABAC Zero-Trust engine. Kept as plain
dataclasses (no FastAPI/Pydantic dependency needed for the research
prototype -- these are internal to the experiment runner, not exposed
over a network API).
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class SubjectAttributes:
    user_id: str
    role: str                      # engineer / operator / maintenance
    identity_confidence: float     # 0..1
    authentication_strength: float  # 0..1


@dataclass
class DeviceAttributes:
    device_id: str
    device_integrity: float        # 0..1
    patch_level: float             # 0..1 (not scored directly yet, kept for future use)


@dataclass
class NetworkAttributes:
    source_zone: str               # engineering / operations / maintenance / unknown
    expected_zone: str


@dataclass
class ContextAttributes:
    behavioral_trust: float        # 0..1, higher = more normal behavior
    anomaly_score: float           # 0..1, higher = more anomalous
    access_hour: int               # 0..23


@dataclass
class AccessRequest:
    request_id: str
    subject: SubjectAttributes
    device: DeviceAttributes
    network: NetworkAttributes
    context: ContextAttributes
    resource: str
    action: str
    label: str = "normal"          # "normal" or the attack scenario id, for evaluation only
                                    # (NOT visible to the policy engine's decision logic)
    metadata: Dict = field(default_factory=dict)

    @property
    def network_trust(self) -> float:
        return 1.0 if self.network.source_zone == self.network.expected_zone else 0.3
