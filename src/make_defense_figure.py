import json
import matplotlib.pyplot as plt

plt.rcParams.update({"font.size": 10.5, "figure.dpi": 150, "savefig.dpi": 300})

d = json.load(open("./results/adversarial_training_defense.json"))

fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))

# Left: evasion rate before/after defense
ax = axes[0]
labels = ["Original\nmodel", "+ Adversarial\ntraining"]
vals = [d["evasion_success_rate_original_model"] * 100, d["evasion_success_rate_defended_model"] * 100]
bars = ax.bar(labels, vals, color=["#dc2626", "#16a34a"])
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.1f}%", ha="center", fontsize=11)
ax.set_ylabel("Evasion success rate (%)")
ax.set_ylim(0, 100)
ax.set_title(f"Adversarial Training Defense\n{d['relative_evasion_reduction_pct']:.1f}% relative reduction "
             f"(+{d['n_adversarial_training_examples_added']} examples)")

# Right: clean-data metrics, no trade-off
ax = axes[1]
metrics = ["accuracy", "f1", "precision", "recall", "roc_auc"]
orig_vals = [d["clean_metrics_original_model"][m] for m in metrics]
def_vals = [d["clean_metrics_defended_model"][m] for m in metrics]
x = range(len(metrics))
w = 0.35
ax.bar([i - w/2 for i in x], orig_vals, width=w, label="Original", color="#94a3b8")
ax.bar([i + w/2 for i in x], def_vals, width=w, label="+ Adversarial training", color="#16a34a")
ax.set_xticks(list(x))
ax.set_xticklabels(metrics, rotation=20)
ax.set_ylim(0.9, 1.02)
ax.set_title("Clean-Data Performance\n(no trade-off from the defense)")
ax.legend(fontsize=8.5, loc="lower right")

fig.tight_layout()
fig.savefig("./figures/fig9_adversarial_defense.png", bbox_inches="tight")
print("Saved fig9_adversarial_defense.png")
