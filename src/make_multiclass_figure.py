import json

import matplotlib.pyplot as plt

plt.rcParams.update({"font.size": 10, "figure.dpi": 150, "savefig.dpi": 300, "savefig.bbox": "tight"})

data = json.load(open("./results/multiclass_report.json"))
per_class = data["per_class"]
class_names = [k for k in per_class if k not in ("accuracy", "macro avg", "weighted avg")]
f1s = [per_class[c]["f1-score"] for c in class_names]
order = sorted(range(len(class_names)), key=lambda i: f1s[i])
class_names = [class_names[i] for i in order]
f1s = [f1s[i] for i in order]

colors = ["#C44E52" if f < 0.8 else "#DD8452" if f < 0.95 else "#55A868" for f in f1s]

fig, ax = plt.subplots(figsize=(6.5, 5))
ax.barh(class_names, f1s, color=colors)
ax.set_xlabel("F1-score")
ax.set_xlim(0, 1.05)
ax.set_title(f"Per-Attack-Type F1 (XGBoost, 15-class, real Edge-IIoTset)\n"
             f"Overall accuracy={data['overall']['accuracy']:.1%}, macro-F1={data['overall']['macro_f1']:.3f}")
for i, v in enumerate(f1s):
    ax.text(v + 0.01, i, f"{v:.2f}", va="center", fontsize=8)
fig.tight_layout()
fig.savefig("./figures/fig6_multiclass_f1.png")
print("Saved fig6_multiclass_f1.png")
