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
2. **A closed-loop Zero-Trust ABAC self-hardening platform** (two goal-based agents, a reflex threat-intelligence agent and five services; see HANDOFF.md 2.1)
   (components: ThreatIntel / Red / Blue / Validation / Policy / Explainability /
   Audit / Coordinator), with a full ablation study isolating each
   component's measured contribution.

## Key results

| | |
|---|---|
| Trust model | XGBoost, F1 = 0.985, ROC-AUC = 0.993 on real Edge-IIoTset |
| Model ↔ policy integration | Same scenarios and policy, ABAC-only vs. ABAC + the trained model: attack success 34.4% → 9.4%, normal workflows unaffected |
| Adversarial evasion (black-box, 200 held-out attacks) | Undefended model: 90.3% single-run evasion; with 3 restarts, all 200 evaded, even when 14 protocol fields are frozen |
| + Adversarial training defense | Best-known evasion 100% → 55.0% (permissive) and 100% → 26.5% (strict tier: protocol fields and TCP flags frozen); no clean-data F1 decrease observed |
| Self-hardening (10 seeds, 5 cycles, fixed-rule defender) | Attack success 11.6% → 7.7%, normal workflow success 97.5% → 93.5% |
| Self-hardening, J-driven defender | Attack success 11.6% → 10.6%, normal workflow success 97.5% → 95.5%; neither defender improves J on held-out scenarios (see HANDOFF.md 2.2) |

See `HANDOFF.md` for how each number was produced and what it does not show.

All figures in `figures/` and `self_hardening/figures/` are generated
directly from the code in this repository — nothing is hand-edited.

## Repository structure

```
src/                    Track 1: trust scoring, SHAP, adversarial evasion/defense, figures
self_hardening/          Track 2: self-hardening loop, API + dashboard, tests
  agents/                 Individual agent implementations
  api/                     FastAPI backend + web dashboard
  tests/                   pytest suite (41 tests)
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
