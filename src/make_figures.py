"""
make_figures.py
------------------
Generates the figures needed for the paper's Results section,
from the already-computed JSON/CSV outputs in results/.
Saves 300-dpi PNGs to figures/, ready to embed in a Word/LaTeX draft.
"""

import json

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

plt.rcParams.update({
    "font.size": 11,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

R = "./results"
F = "./figures"


def fig_confusion_matrix():
    metrics = json.load(open(f"{R}/baseline_metrics.json"))
    cm = np.array(metrics["confusion_matrix"])
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    im = ax.imshow(cm, cmap="Blues")
    labels = ["Benign", "Attack"]
    ax.set_xticks([0, 1]); ax.set_xticklabels(labels)
    ax.set_yticks([0, 1]); ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title("Trust Model Confusion Matrix\n(Real Edge-IIoTset)")
    for i in range(2):
        for j in range(2):
            color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", color=color, fontsize=12)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(f"{F}/fig1_confusion_matrix.png")
    plt.close(fig)


def fig_shap_global_importance():
    data = json.load(open(f"{R}/shap_global_importance.json"))
    top = data[:10][::-1]  # top-10, reversed for horizontal bar (largest on top)
    names = [d[0].replace("_enc", "") for d in top]
    vals = [d[1] for d in top]
    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.barh(names, vals, color="#4C72B0")
    ax.set_xlabel("Mean |SHAP value|  (impact on trust score)")
    ax.set_title("Global Feature Importance\n(SHAP, Real Edge-IIoTset)")
    fig.tight_layout()
    fig.savefig(f"{F}/fig2_shap_global_importance.png")
    plt.close(fig)


def fig_robustness_curve():
    data = json.load(open(f"{R}/robustness.json"))
    fracs = [5, 10, 20, 30]
    throughput = [data[f"malicious_{f}pct"]["sustained_allow_throughput"] for f in fracs]
    containment = [data[f"malicious_{f}pct"]["attack_containment_rate"] for f in fracs]

    fig, ax = plt.subplots(figsize=(5.5, 4))
    ax.plot(fracs, throughput, marker="o", label="Sustained ALLOW throughput", linewidth=2)
    ax.plot(fracs, containment, marker="s", label="Attack containment rate", linewidth=2)
    ax.set_xlabel("Malicious devices in network (%)")
    ax.set_ylabel("Fraction")
    ax.set_ylim(0, 1.05)
    ax.set_title("Robustness under Increasing Malicious-Device Fraction")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(f"{F}/fig3_robustness_curve.png")
    plt.close(fig)


def fig_shap_overhead():
    data = json.load(open(f"{R}/shap_overhead.json"))
    labels = ["Plain inference", "SHAP-explained inference"]
    vals = [data["plain_inference_ms_per_sample"], data["shap_explained_ms_per_sample"]]
    fig, ax = plt.subplots(figsize=(4.5, 4))
    bars = ax.bar(labels, vals, color=["#55A868", "#C44E52"])
    ax.set_ylabel("Latency per sample (ms)")
    ax.set_title("Cost of Explainability")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.2f} ms",
                 ha="center", va="bottom", fontsize=10)
    fig.tight_layout()
    fig.savefig(f"{F}/fig4_shap_overhead.png")
    plt.close(fig)


def table_comparison_csv():
    """Comparison table vs. related work, saved as CSV (paste into Word table)."""
    baseline = json.load(open(f"{R}/baseline_metrics.json"))
    overhead = json.load(open(f"{R}/shap_overhead.json"))
    robustness = json.load(open(f"{R}/robustness.json"))

    rows = [
        {"Framework": "ZT-BlocIoT (2025)", "Accuracy/F1": "N/R", "Latency": "42 ms (full cycle)",
         "Explainable?": "No", "Throughput @20% malicious": "85%"},
        {"Framework": "XDLTDS / Trust-my-IDS (2024)", "Accuracy/F1": "N/R", "Latency": "N/R",
         "Explainable?": "Yes (SHAP, detection only)", "Throughput @20% malicious": "N/A (no policy layer)"},
        {"Framework": "XZT-IIoT (ours)",
         "Accuracy/F1": f"{baseline['accuracy']:.3f} / {baseline['f1']:.3f}",
         "Latency": f"{overhead['shap_explained_ms_per_sample']:.2f} ms (explained)",
         "Explainable?": "Yes (SHAP, integrated in policy engine)",
         "Throughput @20% malicious": f"{robustness['malicious_20pct']['sustained_allow_throughput']*100:.1f}%"},
    ]
    df = pd.DataFrame(rows)
    df.to_csv(f"{R}/comparison_table.csv", index=False)
    print(df.to_string(index=False))


if __name__ == "__main__":
    fig_confusion_matrix()
    fig_shap_global_importance()
    fig_robustness_curve()
    fig_shap_overhead()
    table_comparison_csv()
    print("\nAll figures saved to figures/, comparison table saved to results/comparison_table.csv")
