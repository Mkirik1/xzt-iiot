import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.size": 10.5, "figure.dpi": 150, "savefig.dpi": 300})

df = pd.read_csv("./results/policy_decisions.csv")
print(f"Loaded {len(df):,} real decisions")

fig, axes = plt.subplots(2, 2, figsize=(12, 9))

# --- 1. Trust score distribution, real answers, split by true label ---
ax = axes[0, 0]
benign = df[df.label_binary == 0]["trust_score"]
attack = df[df.label_binary == 1]["trust_score"]
ax.hist(benign, bins=50, alpha=0.65, label=f"Benign (n={len(benign):,})", color="#16a34a")
ax.hist(attack, bins=50, alpha=0.65, label=f"Attack (n={len(attack):,})", color="#dc2626")
ax.set_xlabel("Trust score (real model output, 0-1)")
ax.set_ylabel("Number of real test samples")
ax.set_title("Distribution of Real Trust Scores\n(all 38,295 real Edge-IIoTset test samples)")
ax.legend(fontsize=9)
ax.set_yscale("log")

# --- 2. Decision breakdown, real counts ---
ax = axes[0, 1]
decision_counts = df["decision"].value_counts()
colors_map = {"ALLOW": "#16a34a", "RESTRICT": "#d97706", "DENY": "#dc2626"}
colors = [colors_map.get(d, "#6b7280") for d in decision_counts.index]
bars = ax.bar(decision_counts.index, decision_counts.values, color=colors)
for b, v in zip(bars, decision_counts.values):
    ax.text(b.get_x() + b.get_width() / 2, v + 200, f"{v:,}\n({v/len(df):.1%})", ha="center", fontsize=9)
ax.set_ylabel("Number of real decisions")
ax.set_title("Real Decisions Made\n(all 38,295 real test requests)")

# --- 3. Trust score by real attack type (boxplot-style: mean + spread) ---
ax = axes[1, 0]
attack_types = df[df.label_binary == 1].groupby("attack_type")["trust_score"].agg(["mean", "std", "count"])
attack_types = attack_types.sort_values("mean")
ax.barh(attack_types.index, attack_types["mean"], xerr=attack_types["std"].fillna(0),
        color="#7c3aed", alpha=0.85, error_kw=dict(elinewidth=1, capsize=2))
ax.set_xlabel("Mean real trust score ± std (lower = more confidently flagged)")
ax.set_title("Real Trust Score by Attack Type\n(mean over all real samples of that type)")
ax.axvline(0.4, color="gray", ls="--", lw=1, label="RESTRICT threshold")
ax.axvline(0.8, color="gray", ls=":", lw=1, label="ALLOW threshold")
ax.legend(fontsize=8, loc="lower right")

# --- 4. Confusion between decision and ground truth, real counts ---
ax = axes[1, 1]
ct = pd.crosstab(df["label_binary"].map({0: "Benign", 1: "Attack"}), df["decision"])
ct = ct.reindex(columns=[c for c in ["ALLOW", "RESTRICT", "DENY"] if c in ct.columns])
im = ax.imshow(ct.values, cmap="Blues", aspect="auto")
ax.set_xticks(range(len(ct.columns)))
ax.set_xticklabels(ct.columns)
ax.set_yticks(range(len(ct.index)))
ax.set_yticklabels(ct.index)
for i in range(len(ct.index)):
    for j in range(len(ct.columns)):
        v = ct.values[i, j]
        ax.text(j, i, f"{v:,}", ha="center", va="center",
                color="white" if v > ct.values.max() / 2 else "black", fontsize=10)
ax.set_title("Real Ground Truth vs. Real Decision\n(every one of 38,295 real test samples)")
fig.colorbar(im, ax=ax, fraction=0.046)

fig.tight_layout()
fig.savefig("./figures/fig10_real_responses.png", bbox_inches="tight")
print("Saved fig10_real_responses.png")
