"""
metrics.py
------------
Brief Section 27: p50/p95/p99 authorization latency, throughput
(requests/sec). Measured on the real PolicyEngine.evaluate() call,
not estimated.
"""

import json
import time

import numpy as np

from normal_scenarios import generate_normal_scenarios
from policy_engine import PolicyEngine
from red_agent import generate_attack_scenarios
from trust_engine import TrustEngine, TrustWeights


def measure_latency_and_throughput(policy_engine: PolicyEngine, requests: list) -> dict:
    per_request_ms = []
    t_start = time.perf_counter()
    for r in requests:
        t0 = time.perf_counter()
        policy_engine.evaluate(r)
        per_request_ms.append((time.perf_counter() - t0) * 1000)
    total_s = time.perf_counter() - t_start

    arr = np.array(per_request_ms)
    return {
        "n_requests": len(requests),
        "p50_ms": round(float(np.percentile(arr, 50)), 5),
        "p95_ms": round(float(np.percentile(arr, 95)), 5),
        "p99_ms": round(float(np.percentile(arr, 99)), 5),
        "mean_ms": round(float(arr.mean()), 5),
        "throughput_req_per_sec": round(len(requests) / total_s, 1),
    }


if __name__ == "__main__":
    trust_engine = TrustEngine(TrustWeights.from_yaml("./config/trust_weights.yaml"))
    policy_engine = PolicyEngine("./config/policies.yaml", trust_engine)
    attack = generate_attack_scenarios(n_per_type=100, seed=1)
    normal = generate_normal_scenarios(n=200, seed=2)
    requests = attack + normal

    metrics = measure_latency_and_throughput(policy_engine, requests)
    print(json.dumps(metrics, indent=2))

    with open("./results/latency_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("\nSaved -> ./results/latency_metrics.json")
