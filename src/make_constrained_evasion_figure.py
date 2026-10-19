"""Figure 11: evasion success under the three threat models of
adversarial_evasion_constrained.py (reviewer criticism R3)."""

import json

import matplotlib.pyplot as plt

plt.rcParams.update({"font.size": 10.5, "figure.dpi": 150, "savefig.dpi": 300})

data = json.load(open("./results/adversarial_evasion_constrained.json"))["threat_models"]
order = [("permissive", "Permissive\n(all features)"),
         ("protocol_constrained", "Protocol-constrained\n(protocol/capture\nfields frozen)"),
         ("strict", "Strict\n(+ TCP control\nflags frozen)")]

labels = [lbl for _, lbl in order]
rates = [data[k]["evasion_rate_mean"] * 100 for k, _ in order]
stds = [data[k]["evasion_rate_std"] * 100 for k, _ in order]
n_seeds = len(data["permissive"]["search_seeds"])
n_frozen = [len(data[k]["frozen_features"]) for k, _ in order]

fig, ax = plt.subplots(figsize=(7.2, 4.2))
bars = ax.bar(labels, rates, width=0.55, color="#dc2626",
              yerr=stds, capsize=5, error_kw={"elinewidth": 1.2, "ecolor": "#374151"})
for b, r, sd, f in zip(bars, rates, stds, n_frozen):
    ax.text(b.get_x() + b.get_width() / 2, r + sd + 2, f"{r:.1f}% ± {sd:.1f}",
            ha="center", va="bottom", fontsize=10, color="#111827")
    ax.text(b.get_x() + b.get_width() / 2, 2, f"{f} frozen", ha="center", va="bottom",
            fontsize=8.5, color="white")

ax.set_ylabel("Blocked attacks evaded to ALLOW (%)")
ax.set_ylim(0, 115)
ax.set_title("Evasion success by attacker capability\n"
             f"(same 200 held-out attacks and search budget, mean ± std over {n_seeds} search seeds)")
ax.spines[["top", "right"]].set_visible(False)
ax.yaxis.grid(True, color="#e5e7eb", linewidth=0.8)
ax.set_axisbelow(True)

fig.tight_layout()
fig.savefig("./figures/fig11_constrained_evasion.png", bbox_inches="tight")
print("Saved fig11_constrained_evasion.png")
