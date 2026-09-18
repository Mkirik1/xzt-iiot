"""
run_agentic_multiseed.py
----------------------------
The canonical, most complete experiment runner: drives the full
8-agent architecture (ThreatIntelAgent through CoordinatorAgent)
across N_SEEDS independent seeds, for a statistically robust ASR/NWFSR
result. Supersedes run_multiseed.py (which used the procedural
hardening_loop.run() directly) -- kept for comparison/backward
compatibility, but THIS script is what the paper's reported numbers
and figure should come from, since it exercises every named agent.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import numpy as np

from agents.coordinator_agent import CoordinatorAgent, N_CYCLES

RESULTS = Path(__file__).parent / "results"
N_SEEDS = 5
SEEDS = [42, 101, 202, 303, 404]


def main():
    all_asr = np.zeros((N_SEEDS, N_CYCLES))
    all_nwfsr = np.zeros((N_SEEDS, N_CYCLES))
    audit_report = []

    for i, seed in enumerate(SEEDS):
        print(f"\n=== Agentic run {i+1}/{N_SEEDS} (seed={seed}) ===")
        coord = CoordinatorAgent()
        result = coord.run_experiment(seed=seed, write_explanations=(i == 0), verbose=True)
        cycle_results = result.output["cycle_results"]
        for c, r in enumerate(cycle_results):
            all_asr[i, c] = r["asr"]
            all_nwfsr[i, c] = r["nwfsr"]
        audit_report.append({"seed": seed, "audit_valid": result.output["audit_valid"],
                              "audit_blocks": result.output["audit_blocks"]})
        if i == 0:
            with open(RESULTS / "sample_explanations.json", "w") as f:
                json.dump(result.output["sample_explanations"], f, indent=2)

    asr_mean, asr_std = all_asr.mean(axis=0), all_asr.std(axis=0)
    nwfsr_mean, nwfsr_std = all_nwfsr.mean(axis=0), all_nwfsr.std(axis=0)

    summary = {
        "n_seeds": N_SEEDS, "seeds": SEEDS, "n_cycles": N_CYCLES,
        "architecture": "8-agent (ThreatIntel, Red, Blue, Validation, Policy, "
                         "Explainability, Audit, Coordinator)",
        "asr_mean_by_cycle": asr_mean.round(4).tolist(),
        "asr_std_by_cycle": asr_std.round(4).tolist(),
        "nwfsr_mean_by_cycle": nwfsr_mean.round(4).tolist(),
        "nwfsr_std_by_cycle": nwfsr_std.round(4).tolist(),
        "asr_raw_by_seed": all_asr.round(4).tolist(),
        "nwfsr_raw_by_seed": all_nwfsr.round(4).tolist(),
        "asr_reduction_absolute": round(float(asr_mean[0] - asr_mean[-1]), 4),
        "asr_reduction_relative_pct": round(
            float((asr_mean[0] - asr_mean[-1]) / asr_mean[0] * 100), 1) if asr_mean[0] > 0 else None,
        "audit_reports_by_seed": audit_report,
    }

    print("\n" + "=" * 60)
    print(f"ASR   mean by cycle: {[f'{m:.3f}±{s:.3f}' for m, s in zip(asr_mean, asr_std)]}")
    print(f"NWFSR mean by cycle: {[f'{m:.3f}±{s:.3f}' for m, s in zip(nwfsr_mean, nwfsr_std)]}")
    print(f"ASR reduction: {summary['asr_reduction_absolute']:.3f} absolute "
          f"({summary['asr_reduction_relative_pct']}% relative), across {N_SEEDS} seeds")
    print(f"Audit chains valid across all seeds: {all(r['audit_valid'] for r in audit_report)}")

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "hardening_multiseed_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {RESULTS / 'hardening_multiseed_summary.json'}")


if __name__ == "__main__":
    main()
