import json

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 10.5, "figure.dpi": 150, "savefig.dpi": 300})

data = json.load(open("./results/adversarial_evasion.json"))
summary = data["summary"]
per_sample = data["per_sample"]
top_feats = data["top_perturbed_features_overall"]

fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))

# Left: success rate bar
ax = axes[0]
labels = ["Blocked\n(original)", "Evaded to ALLOW\n(after attack)"]
vals = [summary["n_originally_blocked"] - summary["n_successfully_evaded_to_allow"],
        summary["n_successfully_evaded_to_allow"]]
colors = ["#16a34a", "#dc2626"]
bars = ax.bar(labels, vals, color=colors)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 3, f"{v}\n({v/summary['n_samples_tested']:.0%})",
            ha="center", fontsize=10)
ax.set_ylabel("Number of attack samples (n=200)")
ax.set_title(f"Adversarial Evasion of the Trust Model\n{summary['evasion_success_rate_overall']:.1%} success rate")
ax.set_ylim(0, summary["n_samples_tested"] * 1.15)

# Right: most-perturbed features (attack surface)
ax = axes[1]
feats = [f[0] for f in top_feats][::-1]
counts = [f[1] for f in top_feats][::-1]
ax.barh(feats, counts, color="#7c3aed")
ax.set_xlabel(f"Appearances among successful evasions (n={summary['n_successfully_evaded_to_allow']})")
ax.set_title("Which features the attack exploits\n(same features SHAP ranks as most important)")

fig.tight_layout()
fig.savefig("./figures/fig8_adversarial_evasion.png", bbox_inches="tight")
print("Saved fig8_adversarial_evasion.png")
