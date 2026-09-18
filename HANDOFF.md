# XZT-IIoT — Handoff to Paper Author (v3, FINAL)

Everything measured and tested. No fabricated numbers anywhere in this
document — every figure below came from an actual run, reproducible
via the commands listed.

Paper title: **XZT-IIoT: Explainable Zero-Trust Access Control with
Autonomous Adversarial Validation and Lightweight Blockchain Audit for
Industrial IoT**
Target venue: BSS 2026, submission deadline 20 Sept 2026, 6-page IEEE
format, double-anonymous review.

**Two independent, measured contributions, sharing one audit mechanism:**
- **Track 1** — Explainable trust scoring for IIoT network traffic
  (XGBoost + SHAP), validated on the real Edge-IIoTset benchmark.
- **Track 2** — Autonomous Zero-Trust ABAC policy self-hardening
  platform: an 8-agent architecture with an evolutionary adversarial
  search, a real objective-function-driven mitigation search, policy
  versioning/rollback, scheduled + event-triggered continuous
  operation, and an optional live CVE feed.

---

## TRACK 1 — Explainable Trust Scoring (unchanged from prior handoff — see there for full detail)

Quick reference (full detail was already handed off and is stable, not
touched in this session):
- XGBoost, F1=0.985, ROC-AUC=0.993 on real Edge-IIoTset (153,180 rows)
- SHAP overhead ~18x (0.020ms → 0.372ms/sample; multiplier is machine-dependent, 4-19x observed across runs — cite absolute ms as the stable number)
- **Classifier FPR (0.5 threshold) = 15.3%; deployed policy DENY rate (TAU_RESTRICT=0.40) on benign = 14.9%; RESTRICT rate = 0.5% — these are three distinct numbers, do not conflate (see paper-writing prompt for full explanation, an earlier draft mixed these up)**
- Multiclass (15-way): 88.7% accuracy, macro-F1=0.883
- Model comparison table justifies XGBoost over RF/LogReg empirically
- Figures: `figures/fig1-fig4, fig6`. Results: `results/*.json`

---

## TRACK 1.5 — Adversarial Evasion + Defense (NEW — the paper's strongest single finding)

**This should be a prominent subsection, possibly the headline result
of the Discussion.** It answers a question the base F1/accuracy
numbers cannot: does high offline accuracy mean the model resists a
motivated attacker? Answer: no, and we measured exactly how much, then
fixed most of it.

### Attack: black-box feature-space evasion

`src/adversarial_evasion.py` — a query-only (no model-internals
access) hill-climbing search that perturbs a real attack sample's
features, bounded to the range of values actually observed in real
Edge-IIoTset traffic (an attacker cannot set a feature outside what
real traffic ever showed). Success criterion is the REAL deployed
decision threshold (`TAU_ALLOW=0.80` in `policy_engine.py`), not just
flipping the raw 0.5 classifier boundary.

**Result: 91.5% of blocked attack samples (183/200) could be perturbed
into getting a real ALLOW decision.** State the threat model
explicitly and honestly in the paper: this is a permissive,
feature-space threat model (standard in adversarial ML research) that
assumes the attacker can freely set ANY feature within its observed
range — including some protocol-state fields (tcp.seq, tcp.ack) a real
attacker has less than full control over. Report this as a pessimistic
upper bound, not a claim that this exact attack is fully practical
against a real deployed system as-is.

**Striking, citable detail:** the features the attack exploits most
(tcp.ack_raw, tcp.ack, tcp.checksum, mqtt.hdrflags, tcp.seq) are almost
exactly the same features SHAP ranks as most important globally (see
Track 1's fig2) — the features that give the model its explanatory
power are also its biggest attack surface. This is a genuinely
interesting, defensible observation, not just a coincidence to gloss
over.

Figure: `figures/fig8_adversarial_evasion.png` (success rate bar +
most-exploited-features bar, side by side).

### Defense: adversarial training

`src/adversarial_training_defense.py` — generated 300 evasive examples
against the TRAINING set only (test set held out, zero leakage),
added them to training data as additional "attack" examples, retrained
XGBoost, then re-ran the IDENTICAL evasion search against the hardened
model on the SAME 200 held-out test attacks.

| | Original model | + Adversarial training |
|---|---|---|
| Evasion success rate | 91.5% | **28.0%** |
| Clean-data F1 | 0.9855 | 0.9856 |
| Clean-data accuracy | 0.9751 | 0.9754 |

**69.4% relative reduction in evasion success, with ZERO measurable
cost to clean-data performance** (F1/accuracy essentially unchanged —
state this explicitly, it's the key "no free lunch was needed" result
reviewers look for). Honestly disclose the residual: 28% still evade
even after defense — adversarial training reduces but does not
eliminate the vulnerability; frame this as a genuine open problem,
not a solved one.

Figure: `figures/fig9_adversarial_defense.png` (before/after evasion
rate + side-by-side clean metrics showing no trade-off).

**Suggested framing for the paper:** this whole Track 1.5 result is
arguably the paper's strongest contribution to lead the Discussion
section with — it demonstrates genuine security-research depth (attack
+ defense + honest residual risk), not just a classification benchmark.
Consider referencing it from the Abstract/Introduction as well.

### Limitation to add to the cumulative list

The adversarial evasion threat model is a permissive, feature-space
abstraction (see above) — it establishes an upper bound on
vulnerability under an idealized attacker, not a proof that this exact
attack is trivially executable by crafting real packets on real
industrial hardware.  Real-world evasion feasibility (whether an
attacker can actually manipulate protocol-state fields like tcp.seq
freely) is future work.

---

## TRACK 2 — Autonomous Zero-Trust Self-Hardening Platform

### 2.1 Eight-agent architecture

| Agent | File | What it actually does |
|---|---|---|
| **ThreatIntelAgent** | `agents/threat_intel_agent.py` | Can pull REAL current CVEs from the public NVD database (`try_live=True`), categorizes them into our safe abstract scenario types via keyword matching, weights by CVSS severity. Falls back to local `config/threat_feed.json` if network unavailable — **never crashes**. |
| **RedAgent** | `agents/red_agent.py` | Generates SAFE abstract attack scenarios, weighted by ThreatIntelAgent's priorities. Static/random sampling mode. |
| **EvolutionaryRedAgent** | `evolutionary_red_agent.py` | (1+λ) evolutionary search: finds the worst-case parameter combination within each attack category's declared bounds, re-searching fresh every cycle against the CURRENT policy. Genuinely adaptive, not scripted replay. |
| **PolicyAgent** | `agents/policy_agent.py` | ABAC Decision Point — ALLOW / DENY / STEP_UP_AUTH / **QUARANTINE** |
| **ValidationAgent** | `agents/validation_agent.py` | Computes ASR and NWFSR |
| **BlueAgent** | `agents/blue_agent.py` | Rule-based mitigation (legacy mode) |
| **ExplainabilityAgent** | `agents/explainability_agent.py` | Rule-based per-decision explanation: failed conditions + top-3 trust factors |
| **AuditAgent** | `agents/audit_agent.py` | Hash-chained ledger, structurally append-only |
| **CoordinatorAgent** | `agents/coordinator_agent.py` | Orchestrates all of the above across N cycles |

Canonical entry point: `self_hardening/run_agentic_multiseed.py` for
the paper's reported numbers (5 seeds, static Red Agent, matches the
numbers table below). For the evolutionary/live-threat variant, use
`CoordinatorAgent.run_experiment(use_evolutionary_red=True,
try_live_threat_intel=True)` directly, or the API/dashboard.

### 2.2 Reported numbers (5 seeds, 5 cycles, threat-weighted 8-scenario Red Agent — the CURRENT, authoritative run fig5 was generated from)

**CORRECTED — a prior version of this file had a stale table (41.7%→17.2%)
left over from before the Red Agent's scenario set was expanded from 5
to 8 types. An external review caught that it no longer matched
fig5_hardening_cycles.png. The table below is the current, verified
match — re-check against the JSON source before ever citing a number
from this section, since this exact class of error already happened
once.**

| Cycle | ASR (mean ± std) | NWFSR (mean ± std) |
|---|---|---|
| 0 | 38.8% ± 2.4% | 100.0% ± 0.0% |
| 1 | 30.2% ± 2.1% | 100.0% ± 0.0% |
| 2 | 26.0% ± 1.5% | 100.0% ± 0.0% |
| 3 | 20.1% ± 2.0% | 100.0% ± 0.0% |
| 4 | 15.3% ± 1.8% | 100.0% ± 0.0% |

**60.5% relative ASR reduction.** Source: `self_hardening/results/hardening_multiseed_summary.json`.
Figure: `self_hardening/figures/fig5_hardening_cycles.png`.

**Use this table for the paper.** The evolutionary/live-CVE mode is a
real, tested, working *extension* (great for a demo, a "future
directions realized" paragraph, or a follow-up paper) but was run with
different, non-standardized parameters during development — don't mix
its ad-hoc numbers into the reported table without re-running it
cleanly across the same 5 seeds first.

### 2.3 Ablation study — Experiments A–E (CORRECTED to match the current 8-scenario run)

| Experiment | Zero-Trust | Explainability | Blockchain | Adaptive AI | ASR | NWFSR |
|---|---|---|---|---|---|---|
| A. Baseline ABAC | No | No | No | No | 70.0% | 100% |
| B. Zero-Trust ABAC | Yes | No | No | No | 34.4% | 100% |
| C. ZT + Explainability | Yes | Yes | No | No | 34.4% | 100% |
| D. ZT + Blockchain | Yes | No | Yes | No | 34.4% | 100% |
| E. Full XZT-IIoT | Yes | Yes | Yes | Yes | 15.3% ± 1.8% | 100% |

Source: `self_hardening/results/ablation_table.json` / `.csv`.

### 2.4 New capabilities added this session (real, tested, extending beyond the paper's minimum claim)

**Objective function search (`objective_function.py`)** — implements
`J = αS − βL − γFPR − δO`, grid-searches threshold candidates, applies
the highest-J winner. Tested: `apply_candidate` correctly commits the
winning candidate; DENY-everything is structurally penalized (unit
test `test_deny_everything_is_penalized`).

**Policy versioning + rollback (`policy_versioning.py`)** — full
PROPOSED→VALIDATED→APPROVED→DEPLOYED state machine, diff between
versions, `rollback_to()` restores prior thresholds exactly. Tested.

**QUARANTINE decision** — `policy_engine.py`, triggers when
`device_integrity < 0.30` regardless of other factors (a compromised
DEVICE, not just one bad request). Tested: fires on all 10/10
`firmware_integrity_failure` scenarios in a spot check.

**8 attack scenario types** (was 5): added `privilege_escalation_attempt`,
`replay_simulation`, `firmware_integrity_failure`.

**Device Simulator (`device_simulator.py`)** — 10 device types with the
brief's full attribute set (firmware_version, integrity_score, etc.),
generates in-process telemetry (no real MQTT broker — verified
unavailable in this sandbox, see 2.6).

**Latency/throughput metrics (`metrics.py`)** — real p50/p95/p99 and
req/s on the ABAC decision point: p50≈0.002ms, throughput≈400K req/s
(pure in-process Python, no network hop — cite as decision-logic
latency only, not end-to-end system latency).

**27 pytest tests, all passing** (`tests/test_xzt_iiot.py`) — trust
scoring, ABAC decisions incl. QUARANTINE/STEP_UP_AUTH, Red Agent scope
(asserts no networking imports present — a structural safety check,
not just a policy statement), evolutionary search monotonicity,
scheduler, real-CVE parsing (mocked), audit tamper detection.

**Evolutionary Red Agent (`evolutionary_red_agent.py`)** — (1+λ)
evolutionary search within declared per-category bounds
(`GENE_BOUNDS`), re-run fresh each cycle against the CURRENT (possibly
already-hardened) policy. Confirmed: fitness is non-decreasing within
a run (selection never loses the best found); different seeds find
different worst-case parameter values (not a replayed script).

**Scheduler (`scheduler.py`)** — cron-based (`config/schedule.yaml`,
default `0 2 * * *`) automatic re-runs, plus event triggers
(`NEW_THREAT`, `POLICY_CHANGE`, `SCHEDULED`) callable via API. Runs
persist to `results/scheduled_run_history.json`, building a real trend
over time rather than a single snapshot.

**Real-CVE-aware ThreatIntelAgent** — can call the public NVD API
(`services.nvd.nist.gov`) for current CVEs, extracts ONLY category +
CVSS severity (never exploit mechanics), maps to the same 8 safe
abstract scenario types. Could not be tested end-to-end from the dev
sandbox (network restricted to package registries; confirmed via a
live attempt that correctly failed with 403 and fell back gracefully),
but **was confirmed working live by the student** on their own machine
via `/experiments/history`: repeated triggers show a real mix of
`"threat_intel_source":"LIVE_NVD"` and `"local_static_feed"` entries —
the alternation is expected, since NVD's public API without an API key
enforces a ~5-requests-per-30-seconds rate limit, and the agent
correctly and gracefully falls back whenever a request is throttled
rather than erroring. This is a genuinely stronger result than a
single successful call: it demonstrates the fallback logic working
under real, uncontrolled network conditions, not just in a mocked
test. Cite this as "implemented and validated live (including observed
graceful degradation under NVD's rate limit), tested by the student."

**FastAPI + SQLite + web dashboard** (`api/app.py`,
`api/static/index.html`) — 11 real REST endpoints (see `/docs` for
interactive testing), SQLite-backed decision log, live dashboard with:
access-decision tester, policy table, self-hardening trigger with a
live ASR/NWFSR chart (Chart.js), latency measurement, device fleet
viewer, and a **trend-over-time chart** reading the scheduler history.
No Docker/Postgres/MQTT — confirmed unavailable in this dev sandbox
(2.6), SQLite + in-process agents is the maximum honestly achievable
and fully tested here.

### 2.5 What to say about the evolutionary/live-CVE/scheduler work in the paper

Frame this honestly as depth beyond the minimum viable claim, not as
inflating the headline numbers:
- The core reported result (2.2) stays the static-scenario, 5-seed table.
- Mention the evolutionary search and real-CVE integration as a
  **"strengthened validation methodology"** subsection or as
  **future-work-already-realized** — e.g. "we additionally implemented
  and tested an evolutionary worst-case search and a live-CVE-informed
  threat prioritization mechanism; see supplementary code." This is
  honest, adds real credibility, and doesn't require re-deriving the
  paper's headline claim from noisier ad-hoc runs.
- If you DO want to report evolutionary/live numbers as a second
  result table, re-run `run_agentic_multiseed.py`-equivalent with
  `use_evolutionary_red=True` across the same 5 fixed seeds first, so
  it's a fair, clean, reproducible comparison — don't hand-pick numbers
  from exploratory runs during development.

### 2.6 Environment constraints (verified by direct testing, not assumed)

- Docker: not installed, cannot be installed (`apt-get install docker.io` fails — network-restricted package mirror).
- PostgreSQL, Mosquitto (MQTT broker): same — confirmed un-installable.
- `services.nvd.nist.gov`: unreachable from this sandbox (403 via egress proxy) — confirmed by a live attempt, not assumed.
- Everything else in this handoff (FastAPI, SQLite, APScheduler, XGBoost, SHAP, pytest) — pip-installable and fully tested here.

### 2.7 Known limitations to disclose (cumulative — do not omit any)

1. Rule-based/evolutionary Red/Blue agents, not deep-learning-based — explicit safety-scoped choice.
2. NWFSR=100% partly reflects generous legitimate-scenario parameter ranges (see prior handoff note — unchanged).
3. Small policy/resource set (3 policies, 3 resource types).
4. Single-node, offline-by-default simulation; live CVE path exists but is network-dependent and untested-by-the-AI-assistant end-to-end.
5. BlueAgent mitigations auto-apply without a human-approval UI step (state machine exists in `policy_versioning.py` but isn't wired to a manual-approval gate in the API yet).
6. Evolutionary search operates only within pre-declared per-category numeric bounds — it cannot discover a genuinely new attack CATEGORY, only the worst case within an already-authorized one (this is a deliberate safety boundary, not an oversight — state it as such).
7. Scheduler requires the FastAPI process to stay running continuously; there is no persistence/resume if the process restarts mid-schedule (APScheduler's in-memory job store, not a durable one).

---

## How to run everything (for the author, or for a live demo)

```bash
cd self_hardening
pip install -r <manually: pyyaml numpy shap scikit-learn xgboost matplotlib pytest fastapi uvicorn apscheduler requests>

# Paper's headline Track 2 result:
python run_agentic_multiseed.py

# Ablation table:
python ablation_experiment.py

# Full test suite:
python -m pytest tests/ -v

# Live dashboard (also starts the cron scheduler automatically):
python -m uvicorn api.app:app --reload
# open http://127.0.0.1:8000/  (dashboard)  and  /docs  (API explorer)
```

Track 1 commands unchanged from the prior handoff (`src/train_trust_model.py` etc.).

---

## Related Work — citation list (unchanged from prior handoff)

- AU-ZTAC (Electronics, 2023) — https://doi.org/10.3390/electronics12234825
- UB-ZTDAC (ACM ICCSIS, 2024) — https://dl.acm.org/doi/10.1145/3703187.3703255
- Explainable AI-based IDS for Industry 5.0 (arXiv, 2024) — https://arxiv.org/html/2408.03335v1
- Autonomous federated defense for zero-day threats in IIoT (Frontiers Comm. Netw., 2026) — closest prior work, cite prominently
- RvB: Iterative Red-Blue Games for AI system hardening (arXiv, 2026)
- Blockchain Ledgers for AI Decisions in IoT (MDPI, 2025)
- ZT-BlocIoT (2025), TbDd (2024), XDLTDS/Trust-my-IDS (2024), SHAP+LIME on WUSTL-IIoT-2021 (2025)

---

## Suggested paper structure (6 pages, IEEE, double-anonymous) — unchanged

1. Abstract + Introduction
2. Related Work (4 clusters)
3. Methodology — 3a: XGBoost+SHAP trust scoring; 3b: 8-agent self-hardening loop (mention evolutionary/live-CVE as implemented extensions); 3c: shared audit mechanism
4. Results — Track 1 (fig1-4,6), Track 2 (fig5, ablation table)
5. Discussion — precision/recall trade-off, cost of explainability, ASR/NWFSR philosophy
6. Limitations — full cumulative list (Track 1 + 2.7 above)
7. Conclusion + Future Work
