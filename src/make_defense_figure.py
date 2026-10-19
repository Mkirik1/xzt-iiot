"""Figure 9: adversarial training, evaluated on the same held-out attacks
for both models under the permissive and strict threat models
(adversarial_training_defense.py)."""

import json

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 10.5, "figure.dpi": 150, "savefig.dpi": 300})

d = json.load(open("./results/adversarial_training_defense.json"))
ev = d["evasion"]
tiers = [("permissive", "Permissive\n(all features)"), ("strict", "Strict\n(protocol fields +\nTCP flags frozen)")]
models = [("original", "Original model", "#dc2626"), ("defended", "+ Adversarial training", "#16a34a")]

fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6), gridspec_kw={"width_ratios": [1.15, 1]})

ax = axes[0]
x = np.arange(len(tiers))
w = 0.36
for j, (m, mlabel, color) in enumerate(models):
    means = [ev[m][t]["evasion_rate_mean"] * 100 for t, _ in tiers]
    stds = [ev[m][t]["evasion_rate_std"] * 100 for t, _ in tiers]
    best = [ev[m][t]["evasion_rate_best_known"] * 100 for t, _ in tiers]
    offs = (j - 0.5) * (w + 0.02)
    bars = ax.bar(x + offs, means, w, color=color, label=mlabel, yerr=stds, capsize=4,
                  error_kw={"elinewidth": 1.1, "ecolor": "#374151"})
    for b, v, s, bk in zip(bars, means, stds, best):
        ax.text(b.get_x() + b.get_width() / 2, v + s + 1.5, f"{v:.1f}%", ha="center",
                va="bottom", fontsize=10, color="#111827", fontweight="bold")
        ax.text(b.get_x() + b.get_width() / 2, v + s + 8, f"best {bk:.0f}%", ha="center",
                va="bottom", fontsize=8, color="#4b5563")
ax.set_xticks(x, [lbl for _, lbl in tiers])
ax.set_ylabel("Blocked attacks evaded to ALLOW (%)")
ax.set_ylim(0, 118)
n_seeds = len(d["search_seeds"])
ax.set_title("Evasion before and after adversarial training\n"
             f"(same 200 held-out attacks; bars = single run, mean ± std over {n_seeds} seeds;\n"
             "\"best\" = pooled over all valid searches)", fontsize=10)
ax.spines[["top", "right"]].set_visible(False)
ax.yaxis.grid(True, color="#e5e7eb", linewidth=0.8)
ax.set_axisbelow(True)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2, frameon=False, fontsize=9)

ax = axes[1]
metrics = ["accuracy", "f1", "precision", "recall", "roc_auc"]
orig_vals = [d["clean_metrics_original_model"][m] for m in metrics]
def_vals = [d["clean_metrics_defended_model"][m] for m in metrics]
xm = np.arange(len(metrics))
ax.bar(xm - 0.18, orig_vals, width=0.35, label="Original model", color="#9ca3af")
ax.bar(xm + 0.18, def_vals, width=0.35, label="+ Adversarial training", color="#16a34a")
ax.set_xticks(xm, metrics, rotation=20)
ax.set_ylim(0.9, 1.02)
ax.set_title("Clean-data performance on the held-out test split", fontsize=10)
ax.spines[["top", "right"]].set_visible(False)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2, frameon=False, fontsize=9)

fig.tight_layout()
fig.savefig("./figures/fig9_adversarial_defense.png", bbox_inches="tight")
print("Saved fig9_adversarial_defense.png")
