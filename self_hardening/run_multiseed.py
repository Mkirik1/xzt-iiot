"""
run_multiseed.py
-------------------
Repeats the full 5-cycle self-hardening experiment across N_SEEDS
independent random draws of the attack/normal scenario sets, and
reports mean +/- std ASR/NWFSR per cycle. This is the defensible
version of the result for the paper -- a single-seed run (what
hardening_loop.py's __main__ does) is kept only as a quick smoke test /
demo with a full audit-chain trace, not as the reported evaluation number.

Every number here is computed, not simulated: N_SEEDS full runs of the
real Red/Blue/Validation loop, nothing pre-baked.
"""

import json
from pathlib import Path

import numpy as np

from hardening_loop import run, N_CYCLES

RESULTS = Path(__file__).parent / "results"
N_SEEDS = 10
SEEDS = [42, 101, 202, 303, 404, 505, 606, 707, 808, 909]


def main():
    all_asr = np.zeros((N_SEEDS, N_CYCLES))
    all_nwfsr = np.zeros((N_SEEDS, N_CYCLES))

    for i, seed in enumerate(SEEDS):
        print(f"\n=== Run {i+1}/{N_SEEDS} (seed={seed}) ===")
        # only write the full audit-chain trace for the first seed, to
        # keep this fast -- the audit mechanism itself is already
        # demonstrated exhaustively by the single-seed run and by the
        # traffic-classification module's audit chain.
        cycle_results = run(seed=seed, write_audit=(i == 0), verbose=True)
        for c, r in enumerate(cycle_results):
            all_asr[i, c] = r["asr"]
            all_nwfsr[i, c] = r["nwfsr"]

    asr_mean = all_asr.mean(axis=0)
    asr_std = all_asr.std(axis=0)
    nwfsr_mean = all_nwfsr.mean(axis=0)
    nwfsr_std = all_nwfsr.std(axis=0)

    summary = {
        "n_seeds": N_SEEDS,
        "seeds": SEEDS,
        "n_cycles": N_CYCLES,
        "asr_mean_by_cycle": asr_mean.round(4).tolist(),
        "asr_std_by_cycle": asr_std.round(4).tolist(),
        "nwfsr_mean_by_cycle": nwfsr_mean.round(4).tolist(),
        "nwfsr_std_by_cycle": nwfsr_std.round(4).tolist(),
        "asr_raw_by_seed": all_asr.round(4).tolist(),
        "nwfsr_raw_by_seed": all_nwfsr.round(4).tolist(),
        "asr_reduction_absolute": round(float(asr_mean[0] - asr_mean[-1]), 4),
        "asr_reduction_relative_pct": round(
            float((asr_mean[0] - asr_mean[-1]) / asr_mean[0] * 100), 1) if asr_mean[0] > 0 else None,
    }

    print("\n" + "=" * 60)
    print(f"ASR   mean by cycle: {[f'{m:.3f}±{s:.3f}' for m, s in zip(asr_mean, asr_std)]}")
    print(f"NWFSR mean by cycle: {[f'{m:.3f}±{s:.3f}' for m, s in zip(nwfsr_mean, nwfsr_std)]}")
    print(f"ASR reduction: {summary['asr_reduction_absolute']:.3f} absolute "
          f"({summary['asr_reduction_relative_pct']}% relative), across {N_SEEDS} seeds")

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "hardening_multiseed_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved -> {RESULTS / 'hardening_multiseed_summary.json'}")


if __name__ == "__main__":
    main()
