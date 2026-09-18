import json

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 11, "figure.dpi": 150, "savefig.dpi": 300, "savefig.bbox": "tight"})

R = "./results"
F = "./figures"

summary = json.load(open(f"{R}/hardening_multiseed_summary.json"))
cycles = list(range(summary["n_cycles"]))
asr_mean = np.array(summary["asr_mean_by_cycle"])
asr_std = np.array(summary["asr_std_by_cycle"])
nwfsr_mean = np.array(summary["nwfsr_mean_by_cycle"])
nwfsr_std = np.array(summary["nwfsr_std_by_cycle"])

fig, ax = plt.subplots(figsize=(6.2, 4.6))
ax.plot(cycles, asr_mean, marker="o", linewidth=2.2, label="Attack Success Rate (ASR)", color="#C44E52")
ax.fill_between(cycles, asr_mean - asr_std, asr_mean + asr_std, color="#C44E52", alpha=0.18)
ax.plot(cycles, nwfsr_mean, marker="s", linewidth=2.2, label="Normal Workflow Success Rate (NWFSR)", color="#4C72B0")
ax.fill_between(cycles, nwfsr_mean - nwfsr_std, nwfsr_mean + nwfsr_std, color="#4C72B0", alpha=0.18)
ax.set_xlabel("Hardening Cycle")
ax.set_ylabel("Rate")
ax.set_ylim(0, 1.05)
ax.set_xticks(cycles)
ax.set_title(f"Autonomous Zero-Trust Policy Self-Hardening\n"
             f"(mean ± std over {summary['n_seeds']} independent runs)")
ax.legend(loc="center right")
ax.grid(alpha=0.3)
for x, y in zip(cycles, asr_mean):
    ax.annotate(f"{y:.0%}", (x, y), textcoords="offset points", xytext=(0, -16), ha="center", fontsize=9)
fig.tight_layout()
fig.savefig(f"{F}/fig5_hardening_cycles.png")
print(f"Saved fig5_hardening_cycles.png  "
      f"(ASR: {asr_mean[0]:.1%} -> {asr_mean[-1]:.1%}, "
      f"NWFSR: {nwfsr_mean[0]:.1%} -> {nwfsr_mean[-1]:.1%})")
