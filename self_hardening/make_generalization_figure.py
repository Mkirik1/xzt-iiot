"""Figure 12: does self-hardening generalize? (generalization_experiment.py,
reviewer R4). Left: attack success by group. Right: legitimate workflows
allowed, standard and boundary-case. Gray = Cycle-0 policy; blue/orange =
after 5 cycles hardened on the five SEEN classes only."""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 10, "figure.dpi": 150, "savefig.dpi": 300})
BASE = Path(__file__).parent
d = json.load(open(BASE / "results" / "generalization.json"))
S = d["summary"]
policies = [("initial", "Cycle-0 policy", "#9ca3af"),
            ("objective", "Hardened, J-driven defender", "#2a78d6"),
            ("rule", "Hardened, fixed-rule defender", "#eb6834")]

panels = [
    ("Attack success on unseen evaluation draws (lower is better)",
     [("asr_seen", "Seen classes\n(new draws)"), ("asr_held_out", "Held-out\nclasses"),
      ("asr_class_insider_flood", "New: insider\nflood"), ("asr_class_low_and_slow", "New: low\nand slow")],
     "Attacks allowed (%)"),
    ("Legitimate workflows allowed (higher is better)",
     [("nwfsr_normal", f"Standard\n(n={d['n_normal_eval']})"),
      ("nwfsr_boundary_night_shift_maintenance", "Boundary:\nnight shift"),
      ("nwfsr_boundary_aging_device", "Boundary:\naging device"),
      ("nwfsr_boundary_unusual_but_legitimate", "Boundary:\nunusual task")],
     "Workflows allowed (%)"),
]

fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
w = 0.26
for ax, (title, metrics, ylabel) in zip(axes, panels):
    x = np.arange(len(metrics))
    for j, (key, label, color) in enumerate(policies):
        m = [S[key][k]["mean"] * 100 for k, _ in metrics]
        sd = [S[key][k]["std"] * 100 for k, _ in metrics]
        bars = ax.bar(x + (j - 1) * (w + 0.015), m, w, color=color, label=label, yerr=sd,
                      capsize=3, error_kw={"elinewidth": 1, "ecolor": "#374151"})
        for b, v, s in zip(bars, m, sd):
            ax.text(b.get_x() + b.get_width() / 2, v + s + 1.5, f"{v:.0f}", ha="center",
                    va="bottom", fontsize=7.5, color="#374151")
    ax.set_xticks(x, [lbl for _, lbl in metrics])
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, 115)
    ax.set_title(title, fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, color="#e5e7eb", linewidth=0.8)
    ax.set_axisbelow(True)

handles, labels = axes[0].get_legend_handles_labels()
fig.legend(handles, labels, loc="lower center", ncol=3, frameon=False, fontsize=9,
           bbox_to_anchor=(0.5, -0.04))
fig.suptitle(f"Generalization of self-hardening (hardened on 5 classes; mean ± std over "
             f"{len(d['seeds'])} seeds)", fontsize=11)
fig.tight_layout(rect=(0, 0.06, 1, 1))
out = BASE / "figures" / "fig12_generalization.png"
fig.savefig(out, bbox_inches="tight")
print(f"Saved {out.name}")
