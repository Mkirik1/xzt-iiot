"""
run_all.py
------------
Runs the entire XZT-IIoT project end-to-end, in the correct dependency
order, with one command. Stops immediately and prints a clear message
if any step fails (order matters -- later steps depend on earlier
ones' output files).

Usage:   python run_all.py
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent

STEPS = [
    ("Track 1 — train trust model (XGBoost)", ["python", "src/train_trust_model.py"]),
    ("Track 1 — SHAP explainability", ["python", "src/explain_shap.py"]),
    ("Track 1 — policy engine + robustness", ["python", "src/policy_engine.py"]),
    ("Track 1 — model comparison (RF/XGBoost/LogReg)", ["python", "src/model_comparison.py"]),
    ("Track 1 — multiclass (15-way) classification", ["python", "src/multiclass_classification.py"]),
    ("Track 1 — figures 1-4", ["python", "src/make_figures.py"]),
    ("Track 1 — multiclass figure", ["python", "src/make_multiclass_figure.py"]),
    ("Track 1.5 — adversarial evasion attack", ["python", "src/adversarial_evasion.py"]),
    ("Track 1.5 — adversarial training defense", ["python", "src/adversarial_training_defense.py"]),
    ("Track 1.5 — evasion figure", ["python", "src/make_evasion_figure.py"]),
    ("Track 1.5 — defense figure", ["python", "src/make_defense_figure.py"]),
    ("Track 1.5 — protocol-constrained evasion (reviewer R3)",
     ["python", "src/adversarial_evasion_constrained.py"]),
    ("Track 1.5 — constrained evasion figure", ["python", "src/make_constrained_evasion_figure.py"]),
    ("Architecture diagram", ["python", "src/make_security_architecture_diagram.py"]),
    ("Track 1/1.5 tests", ["python", "-m", "pytest", "src/test_adversarial_evasion.py", "-v"]),
    ("Track 2 — self-hardening, J-driven Blue Agent (10 seeds)",
     ["python", "run_agentic_multiseed.py"], "self_hardening"),
    ("Track 2 — self-hardening, fixed-rule Blue Agent baseline (10 seeds)",
     ["python", "run_agentic_multiseed.py", "--blue-mode", "rule"], "self_hardening"),
    ("Track 2 — ablation study (Experiments A-F)",
     ["python", "ablation_experiment.py"], "self_hardening"),
    ("Track 2 — hardening cycle figure", ["python", "make_figure.py"], "self_hardening"),
    ("Track 2 — generalization to unseen attacks and boundary workflows (reviewer R4)",
     ["python", "generalization_experiment.py"], "self_hardening"),
    ("Track 2 — generalization figure", ["python", "make_generalization_figure.py"], "self_hardening"),
    ("Track 2 — tests", ["python", "-m", "pytest", "tests/", "-v"], "self_hardening"),
]


def run_step(name, cmd, cwd=None):
    print("\n" + "=" * 70)
    print(f"  {name}")
    print("=" * 70)
    t0 = time.time()
    result = subprocess.run(cmd, cwd=str(ROOT / cwd) if cwd else str(ROOT))
    elapsed = time.time() - t0
    if result.returncode != 0:
        print(f"\n[FAILED] '{name}' exited with code {result.returncode} after {elapsed:.1f}s.")
        print("Stopping here -- later steps depend on this one's output.")
        print("Fix the error above and re-run: python run_all.py")
        sys.exit(1)
    print(f"[OK] {name} ({elapsed:.1f}s)")


def ensure_directories():
    """The individual scripts assume results/figures folders already
    exist and don't create them -- if they're missing (fresh clone,
    accidental deletion), scripts crash on the first file write.
    Create everything needed up front so run_all.py works from a
    truly clean checkout, not just a partially-populated one."""
    for d in ("results", "figures", "self_hardening/results", "self_hardening/figures"):
        (ROOT / d).mkdir(parents=True, exist_ok=True)


def main():
    ensure_directories()
    t_start = time.time()
    for step in STEPS:
        name, cmd = step[0], step[1]
        cwd = step[2] if len(step) > 2 else None
        run_step(name, cmd, cwd)

    total = time.time() - t_start
    print("\n" + "=" * 70)
    print(f"  ALL STEPS COMPLETE ({total/60:.1f} minutes)")
    print("=" * 70)
    print("\nResults:  results/*.json, self_hardening/results/*.json")
    print("Figures:  figures/*.png, self_hardening/figures/*.png")
    print("\nTo launch the live dashboard now, run separately:")
    print("  cd self_hardening")
    print("  python -m uvicorn api.app:app --reload")
    print("  then open http://127.0.0.1:8000/")


if __name__ == "__main__":
    main()
