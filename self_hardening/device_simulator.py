"""
device_simulator.py
----------------------
IIoT device simulator (brief Section 2A), scoped to what's honestly
achievable without a real MQTT broker (unavailable in this sandbox --
verified: apt-get install mosquitto fails, network-restricted). Devices
are real Python objects with the brief's full attribute set, and
`publish_telemetry()` generates real (simulated) readings in-process
on a schedule -- not a decorative dataclass, an actual small
simulation loop you can run and observe.
"""

import random
import time
from dataclasses import dataclass, field, asdict
from typing import List

DEVICE_TYPES = ["PLC", "temperature_sensor", "pressure_sensor", "industrial_robot",
                 "smart_valve", "pump_controller", "HMI_workstation",
                 "maintenance_laptop", "engineering_workstation", "edge_gateway"]

CRITICALITY_BY_TYPE = {
    "PLC": "critical", "industrial_robot": "critical", "pump_controller": "high",
    "smart_valve": "high", "edge_gateway": "high", "HMI_workstation": "medium",
    "engineering_workstation": "medium", "temperature_sensor": "low",
    "pressure_sensor": "low", "maintenance_laptop": "medium",
}


@dataclass
class IIoTDevice:
    device_id: str
    device_type: str
    owner: str
    firmware_version: str
    integrity_score: float          # 0..1
    security_patch_level: float     # 0..1
    trust_status: str = "unverified"  # unverified / trusted / degraded / quarantined
    network_zone: str = "engineering"
    certificate_status: str = "valid"
    behavioral_baseline: dict = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)
    criticality: str = "medium"

    def publish_telemetry(self, rng: random.Random) -> dict:
        """Generate one real (simulated) telemetry reading, tagged with
        this device's own attributes -- an in-process stand-in for an
        MQTT publish, since no broker is available in this environment."""
        self.last_seen = time.time()
        reading = {
            "device_id": self.device_id, "device_type": self.device_type,
            "timestamp": self.last_seen, "network_zone": self.network_zone,
            "integrity_score": round(self.integrity_score, 3),
        }
        if self.device_type in ("temperature_sensor",):
            reading["value_celsius"] = round(rng.uniform(18, 85), 2)
        elif self.device_type in ("pressure_sensor",):
            reading["value_bar"] = round(rng.uniform(1.0, 12.0), 2)
        elif self.device_type in ("PLC", "pump_controller", "smart_valve"):
            reading["operational_state"] = rng.choice(["RUNNING", "IDLE", "FAULT"])
        else:
            reading["heartbeat"] = True
        return reading


def build_fleet(n_devices: int = 20, seed: int = 1) -> List[IIoTDevice]:
    rng = random.Random(seed)
    fleet = []
    for i in range(n_devices):
        dtype = rng.choice(DEVICE_TYPES)
        fleet.append(IIoTDevice(
            device_id=f"dev_{i:04d}", device_type=dtype, owner=f"owner_{rng.randint(1, 6)}",
            firmware_version=f"{rng.randint(1,4)}.{rng.randint(0,9)}.{rng.randint(0,20)}",
            integrity_score=round(rng.uniform(0.6, 0.99), 3),
            security_patch_level=round(rng.uniform(0.5, 1.0), 3),
            network_zone=rng.choice(["engineering", "operations", "maintenance"]),
            criticality=CRITICALITY_BY_TYPE.get(dtype, "medium"),
        ))
    return fleet


def simulate_fleet_telemetry(fleet: List[IIoTDevice], n_rounds: int = 5, seed: int = 2) -> List[dict]:
    rng = random.Random(seed)
    readings = []
    for _ in range(n_rounds):
        for device in fleet:
            readings.append(device.publish_telemetry(rng))
    return readings


if __name__ == "__main__":
    fleet = build_fleet(n_devices=10)
    readings = simulate_fleet_telemetry(fleet, n_rounds=3)
    print(f"Simulated fleet of {len(fleet)} devices, {len(readings)} telemetry readings.")
    print("Sample device:", asdict(fleet[0]))
    print("Sample reading:", readings[0])
