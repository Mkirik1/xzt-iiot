"""
generate_dataset.py
--------------------
Synthetic Industrial IoT (IIoT) network traffic generator.

Mirrors the feature structure and attack taxonomy of Edge-IIoTset
(Ferrag et al., 2022) so that the downstream pipeline (trust model,
SHAP explainer, zero-trust policy engine) can be developed and
validated now, then pointed at the real dataset later by swapping
the CSV file (same column schema).

Attack categories (subset of Edge-IIoTset's 14 attacks, grouped
into the same 5 threat classes used in the original dataset):
  - DoS/DDoS:           DDoS_TCP_SYN, DDoS_UDP, DDoS_ICMP
  - Information gathering: Port_Scanning, Fingerprinting
  - Man-in-the-Middle:  MITM
  - Injection:          SQL_Injection, XSS
  - Malware:            Backdoor, Ransomware, Password (brute force)

Devices simulated: PLC, HMI, SCADA_server, temperature_sensor,
pressure_sensor, actuator, edge_gateway  (industrial testbed roles)
"""

import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)

DEVICES = ["PLC", "HMI", "SCADA_server", "temperature_sensor",
           "pressure_sensor", "actuator", "edge_gateway"]

PROTOCOLS = ["Modbus_TCP", "MQTT", "HTTP", "TCP", "UDP", "ICMP"]

ATTACK_TYPES = {
    "Normal": 0.85,
    "DDoS_TCP_SYN": 0.025,
    "DDoS_UDP": 0.02,
    "DDoS_ICMP": 0.015,
    "Port_Scanning": 0.02,
    "Fingerprinting": 0.01,
    "MITM": 0.015,
    "SQL_Injection": 0.01,
    "XSS": 0.01,
    "Backdoor": 0.01,
    "Ransomware": 0.01,
    "Password": 0.015,
}


def _base_row(n, device, protocol):
    """Generate benign-like baseline feature distributions for n rows."""
    return pd.DataFrame({
        "device_type": device,
        "protocol": protocol,
        "frame_len": RNG.normal(180, 40, n).clip(40, 1500),
        "flow_duration_ms": RNG.exponential(300, n).clip(1, 5000),
        "pkt_rate": RNG.normal(8, 3, n).clip(0.1, 50),
        "byte_rate": RNG.normal(1200, 400, n).clip(50, 8000),
        "inter_arrival_ms": RNG.exponential(120, n).clip(1, 2000),
        "tcp_syn_count": RNG.poisson(1, n),
        "tcp_ack_count": RNG.poisson(3, n),
        "tcp_rst_count": RNG.poisson(0.1, n),
        "distinct_dst_ports": RNG.poisson(1, n).clip(1, None),
        "payload_entropy": RNG.normal(3.2, 0.6, n).clip(0, 8),
        "modbus_func_code": RNG.integers(1, 6, n),
        "auth_fail_count": RNG.poisson(0.05, n),
    })


def _apply_attack_signature(df, attack):
    """Perturb features to encode a realistic attack signature."""
    n = len(df)
    if attack == "DDoS_TCP_SYN":
        df["pkt_rate"] = RNG.normal(400, 80, n).clip(100, None)
        df["tcp_syn_count"] = RNG.poisson(40, n)
        df["tcp_ack_count"] = RNG.poisson(0.5, n)
        df["inter_arrival_ms"] = RNG.exponential(2, n)
    elif attack == "DDoS_UDP":
        df["pkt_rate"] = RNG.normal(350, 70, n).clip(100, None)
        df["protocol"] = "UDP"
        df["byte_rate"] = RNG.normal(9000, 1500, n)
    elif attack == "DDoS_ICMP":
        df["pkt_rate"] = RNG.normal(300, 60, n).clip(80, None)
        df["protocol"] = "ICMP"
        df["payload_entropy"] = RNG.normal(0.5, 0.2, n).clip(0, None)
    elif attack == "Port_Scanning":
        df["distinct_dst_ports"] = RNG.integers(20, 200, n)
        df["flow_duration_ms"] = RNG.exponential(5, n)
        df["tcp_syn_count"] = RNG.poisson(1, n)
        df["tcp_rst_count"] = RNG.poisson(3, n)
    elif attack == "Fingerprinting":
        df["distinct_dst_ports"] = RNG.integers(5, 30, n)
        df["payload_entropy"] = RNG.normal(5.5, 0.5, n).clip(0, 8)
    elif attack == "MITM":
        df["inter_arrival_ms"] = RNG.exponential(400, n)
        df["tcp_rst_count"] = RNG.poisson(2, n)
        df["modbus_func_code"] = RNG.integers(80, 100, n)  # illegal func codes
    elif attack == "SQL_Injection":
        df["protocol"] = "HTTP"
        df["payload_entropy"] = RNG.normal(6.0, 0.4, n).clip(0, 8)
        df["frame_len"] = RNG.normal(600, 150, n).clip(100, 1500)
    elif attack == "XSS":
        df["protocol"] = "HTTP"
        df["payload_entropy"] = RNG.normal(5.8, 0.5, n).clip(0, 8)
    elif attack == "Backdoor":
        df["distinct_dst_ports"] = RNG.integers(1, 3, n)
        df["byte_rate"] = RNG.normal(50, 20, n).clip(1, None)
        df["inter_arrival_ms"] = RNG.exponential(800, n)
    elif attack == "Ransomware":
        df["byte_rate"] = RNG.normal(15000, 3000, n)
        df["payload_entropy"] = RNG.normal(7.5, 0.3, n).clip(0, 8)
    elif attack == "Password":
        df["auth_fail_count"] = RNG.poisson(15, n)
        df["pkt_rate"] = RNG.normal(20, 5, n)
    df["label_attack_type"] = attack
    df["label_binary"] = 0 if attack == "Normal" else 1
    return df


def generate(n_rows: int = 20000) -> pd.DataFrame:
    frames = []
    for attack, frac in ATTACK_TYPES.items():
        n = int(n_rows * frac)
        device = RNG.choice(DEVICES, n)
        protocol = RNG.choice(PROTOCOLS, n)
        df = _base_row(n, device, protocol)
        df = _apply_attack_signature(df, attack)
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    full = full.sample(frac=1, random_state=42).reset_index(drop=True)
    full["device_id"] = ["dev_%04d" % i for i in RNG.integers(0, 500, len(full))]
    return full


if __name__ == "__main__":
    df = generate(20000)
    out_path = "./data/iiot_traffic.csv"
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} rows -> {out_path}")
    print(df["label_attack_type"].value_counts())
