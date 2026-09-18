"""
make_security_architecture_diagram.py (v2 — cleaner layout)
----------------------------------------------------------------
Full-picture security architecture diagram for the paper. Redesigned
for readability: more spacing between elements, bigger fonts, no
overlapping text/blocks, blockchain visual clearly separated from
its label text.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams.update({"font.family": "DejaVu Sans"})

fig, ax = plt.subplots(figsize=(15, 17.5))
ax.set_xlim(-2, 118)
ax.set_ylim(0, 152)
ax.axis("off")

COLOR_INPUT = "#6b7280"
COLOR_BARRIER = "#2563eb"
COLOR_ALLOW = "#16a34a"
COLOR_DENY = "#dc2626"
COLOR_STEPUP = "#d97706"
COLOR_QUARANTINE = "#7f1d1d"
COLOR_EXPLAIN = "#0891b2"
COLOR_AUDIT = "#334155"
COLOR_LOOP = "#be123c"
COLOR_BLOCK = "#fbbf24"


def box(x, y, w, h, text, color, fontsize=11.5, text_color="white", weight="normal"):
    b = FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                        boxstyle="round,pad=0.35,rounding_size=3",
                        linewidth=0, facecolor=color, zorder=3)
    ax.add_patch(b)
    ax.text(x, y, text, ha="center", va="center", fontsize=fontsize,
            color=text_color, zorder=4, linespacing=1.55, fontweight=weight)


def arrow(p1, p2, color="#1f2937", lw=2.1, ls="solid", curve=0.0, style="-|>"):
    a = FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=16,
                         linewidth=lw, color=color, linestyle=ls,
                         connectionstyle=f"arc3,rad={curve}", zorder=2)
    ax.add_patch(a)


def label(x, y, text, color, fontsize=10, weight="bold"):
    ax.text(x, y, text, ha="center", va="center", fontsize=fontsize, color=color,
            fontweight=weight, zorder=6,
            bbox=dict(boxstyle="round,pad=0.25", fc="white", ec=color, lw=1))


# ================= MAIN PIPELINE (left column) =================
CX = 28
LW = 48  # standard left-column box width

box(CX, 141, LW, 8, "Access Request / Device Traffic\n(user, device, network sample)",
    COLOR_INPUT, fontsize=12)

box(CX, 126, LW, 11,
    "BARRIER 1 — Context Collection\nidentity · device integrity · network zone\nbehavioral signals · historical pattern",
    COLOR_BARRIER)
arrow((CX, 137), (CX, 131.5))

box(CX, 109, LW, 13,
    "BARRIER 2 — Trust Engine\nXGBoost classifier (real traffic) +\nweighted formula (ABAC attributes)\n→ Trust Score [0,1] + SHAP factors",
    COLOR_BARRIER)
arrow((CX, 120.5), (CX, 115.5))

box(CX, 92, LW, 11,
    "BARRIER 3 — Policy Decision Point\nABAC rules: role, resource, zone,\nmin_trust / min_integrity / max_anomaly",
    COLOR_BARRIER)
arrow((CX, 102.5), (CX, 97.5))

# Decision outcomes
dy = 76
label(CX, 84.3, "4 possible outcomes", "#555", fontsize=10, weight="normal")
box(6, dy, 13.5, 8, "ALLOW", COLOR_ALLOW, fontsize=12.5)
box(22.3, dy, 13.5, 8, "STEP_UP\nAUTH", COLOR_STEPUP, fontsize=11)
box(38.7, dy, 13.5, 8, "DENY", COLOR_DENY, fontsize=12.5)
box(55, dy, 13.5, 8, "QUARANTINE", COLOR_QUARANTINE, fontsize=10.5)
for x in (6, 22.3, 38.7, 55):
    arrow((CX, 86.5), (x, dy + 4.2), curve=(0.0 if x == CX else (0.18 if x < CX else -0.18)))

box(CX, 62, LW, 11,
    "LAYER 4 — Explainability (non-gating)\nSHAP (traffic model) / rule-based (ABAC):\nWHY this decision — does NOT alter it",
    COLOR_EXPLAIN)
for x in (6, 22.3, 38.7, 55):
    arrow((x, dy - 4.2), (CX + (x - CX) * 0.35, 67.5))

# Barrier 5 — sized generously so title text and blockchain visual never touch
box(CX, 34, LW, 24, "", COLOR_AUDIT)
ax.text(CX, 43.3, "LAYER 5 (non-gating) — Lightweight Blockchain-\nStyle Audit Ledger (SHA-256 hash-chain)",
        ha="center", va="center", fontsize=11.5, color="white", fontweight="normal",
        linespacing=1.5, zorder=4)
arrow((CX, 56.5), (CX, 46.5))

# Blockchain visual: 5 clearly separated gold blocks, own row, well below the title
chain_y = 31
chain_xs = [8.5, 18.5, 28.5, 38.5, 48.5]
for i, cxb in enumerate(chain_xs):
    blk = FancyBboxPatch((cxb - 4, chain_y - 2.4), 8, 4.8,
                          boxstyle="round,pad=0.2,rounding_size=1",
                          linewidth=1.8, edgecolor="#1e293b", facecolor=COLOR_BLOCK, zorder=6)
    ax.add_patch(blk)
    ax.text(cxb, chain_y, f"Block {i}", ha="center", va="center", fontsize=8.3,
            color="#1e293b", fontweight="bold", zorder=7)
    if i > 0:
        arrow((chain_xs[i - 1] + 4, chain_y), (cxb - 4, chain_y), color=COLOR_BLOCK, lw=2.4)
ax.text(CX, 24.5, "each block stores hash(previous block) → editing one block breaks every\nhash after it. Single-node ledger: detects tampering, does NOT by itself\nprevent someone with file access from rewriting the whole chain consistently",
        fontsize=8.3, style="italic", ha="center", color="white", linespacing=1.4, zorder=4)

arrow((CX, 22), (CX, 17.5))
box(CX, 11, LW, 8, "Action Permitted / Blocked\n+ Full Audit Trail", COLOR_INPUT, fontsize=11.5)


# ================= SELF-HARDENING LOOP (right column) =================
RX = 92
RW = 36

box(RX, 147, RW, 9,
    "CoordinatorAgent\norchestrates every agent below,\neach cycle — scheduled or on-demand",
    "#881337", fontsize=10)
arrow((RX, 142.5), (RX, 131.5))

box(RX, 126, RW, 11,
    "ThreatIntelAgent\nlocal feed OR live NVD (real CVEs)\n→ category + severity weights",
    COLOR_LOOP)

box(RX, 109, RW, 11,
    "RedAgent / EvolutionaryRedAgent\nsafe simulated attack scenarios,\nevolves worst-case within bounds",
    COLOR_LOOP)
arrow((RX, 120.5), (RX, 114.5))

box(RX, 92, RW, 11,
    "ValidationAgent\nmeasures Attack Success Rate (ASR)\n& Normal Workflow Success Rate (NWFSR)",
    COLOR_LOOP)
arrow((RX, 103.5), (RX, 97.5))

box(RX, 62, RW, 11,
    "BlueAgent\nproposes threshold tightening\nJ = \u03b1S \u2212 \u03b2L \u2212 \u03b3FPR \u2212 \u03b4O search",
    COLOR_LOOP)
arrow((RX, 86.5), (RX, 67.5))  # ValidationAgent -> BlueAgent (was missing)

box(RX, 45, RW, 11,
    "PolicyVersionHistory\nPROPOSED → VALIDATED →\nAPPROVED → DEPLOYED (+ rollback)",
    COLOR_LOOP)
arrow((RX, 56.5), (RX, 50.5))

box(RX, 28, RW, 9,
    "Cycle repeats:\nAttack Success Rate measurably\ndecreases cycle over cycle",
    COLOR_LOOP, fontsize=10.5)
arrow((RX, 39.5), (RX, 32.5))

# ---- Cross-column connections (kept simple: one clear diagonal each) ----
# 1. RedAgent probes Barrier 2/3
arrow((RX - RW / 2, 109), (CX + LW / 2, 100), color=COLOR_LOOP, ls="dashed", lw=1.8, curve=-0.15)
label(70, 104.5, "probes", COLOR_LOOP, fontsize=9.5)

# 2. Decision outcomes -> ValidationAgent
arrow((55, dy + 4.2), (RX - RW / 2, 92), color=COLOR_LOOP, ls="dashed", lw=1.8, curve=0.25)
label(70, 84, "measures", COLOR_LOOP, fontsize=9.5)

# 3. BlueAgent -> Barrier 3 (feedback: tightens rules)
arrow((RX - RW / 2, 62), (CX + LW / 2, 92), color=COLOR_LOOP, lw=2.6, curve=0.22)
label(70, 70, "updates\npolicy", COLOR_LOOP, fontsize=9.5)

# 4. PolicyVersionHistory -> Audit ledger
arrow((RX - RW / 2, 45), (CX + LW / 2, 40), color=COLOR_AUDIT, lw=1.8, ls="dashed", curve=0.15)
label(70, 44.5, "logs version", COLOR_AUDIT, fontsize=9.5)

ax.text(59, 150.5, "XZT-IIoT — Full Security Architecture: Barriers, Layers, and Feedback Loop",
        ha="center", fontsize=16, fontweight="bold")

legend_items = [
    mpatches.Patch(color=COLOR_INPUT, label="Input / Output"),
    mpatches.Patch(color=COLOR_BARRIER, label="Core decision barrier (gates ALLOW/DENY)"),
    mpatches.Patch(color=COLOR_EXPLAIN, label="Explainability layer (non-gating)"),
    mpatches.Patch(color=COLOR_AUDIT, label="Audit / blockchain layer (non-gating)"),
    mpatches.Patch(color=COLOR_LOOP, label="Self-hardening agents (background loop)"),
    mpatches.Patch(color="#881337", label="CoordinatorAgent"),
    mpatches.Patch(color=COLOR_BLOCK, label="Individual audit block"),
]
ax.legend(handles=legend_items, loc="lower center", bbox_to_anchor=(0.5, -0.045),
          ncol=3, fontsize=10.5, frameon=False)

fig.tight_layout()
fig.savefig("./figures/fig7_security_architecture.png", bbox_inches="tight", facecolor="white")
print("Saved fig7_security_architecture.png")
