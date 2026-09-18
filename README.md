# XZT-IIoT

**Explainable Zero-Trust Access Control with Autonomous Adversarial Validation
and Lightweight Blockchain Audit for Industrial IoT**

Research prototype accompanying a submission to BSS 2026 (5th International
Workshop on Blockchain Security and Scalability, IEEE Cybermatics Congress).

Two independent, measured contributions:

1. **Explainable trust scoring** for IIoT network traffic (XGBoost + SHAP),
   validated on the real [Edge-IIoTset](https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot)
   benchmark — including a black-box adversarial evasion study and an
   adversarial-training defense.
2. **An 8-agent autonomous Zero-Trust ABAC self-hardening platform**
   (ThreatIntel / Red / Blue / Validation / Policy / Explainability / Audit /
   Coordinator agents), with a full ablation study isolating each
   component's measured contribution.

## Key results

| | |
|---|---|
| Trust model | XGBoost, F1 = 0.985, ROC-AUC = 0.993 on real Edge-IIoTset |
| Adversarial evasion (black-box) | 91.5% success rate against the undefended model |
| + Adversarial training defense | Evasion drops to 28.0%, with no measured loss in clean-data F1 |
| Self-hardening (5 seeds, 5 cycles) | Attack Success Rate 38.8% → 15.3% (60.5% relative reduction), Normal Workflow Success Rate held at 100% throughout |

All figures in `figures/` and `self_hardening/figures/` are generated
directly from the code in this repository — nothing is hand-edited.

## Repository structure

```
src/                    Track 1: trust scoring, SHAP, adversarial evasion/defense, figures
self_hardening/          Track 2: 8-agent architecture, API + dashboard, tests
  agents/                 Individual agent implementations
  api/                     FastAPI backend + web dashboard
  tests/                   pytest suite (28 tests)
data/                    Dataset location (not included — see below)
results/, figures/       Generated outputs (not tracked in git — reproducible)
HANDOFF.md               Full mapping of every reported number to its source file
run_all.py                Runs the entire pipeline end-to-end
```

## Reproducing the results

1. Download the real Edge-IIoTset dataset (`ML-EdgeIIoT-dataset.csv`) from
   [Kaggle](https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot)
   (free account required — not redistributed here due to dataset license).
2. Place it at `data/edge_iiotset_raw.csv`.
3. Install dependencies:
   ```bash
   pip install pyyaml numpy shap scikit-learn xgboost matplotlib pytest fastapi uvicorn apscheduler requests
   ```
4. Run everything:
   ```bash
   python src/prepare_real_data.py
   python run_all.py
   ```
5. (Optional) Launch the live dashboard:
   ```bash
   cd self_hardening
   python -m uvicorn api.app:app --reload
   # open http://127.0.0.1:8000/
   ```

## Safety note

All adversarial testing (Red Agent, evolutionary search, adversarial
evasion) runs exclusively against local, abstract, simulated scenarios.
Nothing in this repository scans, exploits, or connects to any real
external system. See `HANDOFF.md` for the full threat-model and
limitations discussion.

## Citation

Paper under review at BSS 2026. Citation details will be added upon
acceptance.
