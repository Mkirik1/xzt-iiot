"""Figure 11: evasion success under the three threat models of
adversarial_evasion_constrained.py (reviewer criticism R3).

Red = best known evasion rate (pooled over every search whose threat
model is at least as strict; a valid, monotone lower bound on the
attacker). Gray = one search run, mean ± std over search seeds, shown
to make the search variance visible."""

import json

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 10.5, "figure.dpi": 150, "savefig.dpi": 300})

data = json.load(open("./results/adversarial_evasion_constrained.json"))["threat_models"]
order = [("permissive", "Permissive\n(all features)"),
         ("protocol_constrained", "Protocol-constrained\n(protocol/capture\nfields frozen)"),
         ("strict", "Strict\n(+ TCP control\nflags frozen)")]

best = [data[k]["evasion_rate_best_known"] * 100 for k, _ in order]
mean = [data[k]["evasion_rate_mean"] * 100 for k, _ in order]
std = [data[k]["evasion_rate_std"] * 100 for k, _ in order]
n_frozen = [len(data[k]["frozen_features"]) for k, _ in order]
n_seeds = len(data["permissive"]["search_seeds"])

x = np.arange(len(order))
w = 0.36
fig, ax = plt.subplots(figsize=(7.6, 4.9))
b1 = ax.bar(x - w / 2 - 0.01, best, w, color="#dc2626",
            label="Best known (all searches valid for this tier)")
b2 = ax.bar(x + w / 2 + 0.01, mean, w, color="#9ca3af", yerr=std, capsize=4,
            error_kw={"elinewidth": 1.1, "ecolor": "#374151"},
            label=f"Single search run (mean ± std, {n_seeds} seeds)")

for b, v in zip(b1, best):
    ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.1f}%", ha="center",
            va="bottom", fontsize=10, color="#111827", fontweight="bold")
for b, v, s in zip(b2, mean, std):
    ax.text(b.get_x() + b.get_width() / 2, v + s + 1.5, f"{v:.1f}%", ha="center",
            va="bottom", fontsize=9, color="#374151")
ax.set_xticks(x, [f"{lbl}\n[{f} frozen]" for (_, lbl), f in zip(order, n_frozen)])
ax.set_ylabel("Blocked attacks evaded to ALLOW (%)")
ax.set_ylim(0, 108)
ax.set_title("Evasion success by attacker capability\n"
             "(same 200 held-out attacks, same per-run search budget)")
ax.spines[["top", "right"]].set_visible(False)
ax.yaxis.grid(True, color="#e5e7eb", linewidth=0.8)
ax.set_axisbelow(True)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.30), ncol=2, frameon=False, fontsize=9)

fig.tight_layout()
fig.savefig("./figures/fig11_constrained_evasion.png", bbox_inches="tight")
print("Saved fig11_constrained_evasion.png")
