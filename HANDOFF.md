# XZT-IIoT — Handoff to Paper Author (v4, post-rejection revision)

Everything measured and tested. No fabricated numbers anywhere in this
document — every figure below came from an actual run on the real
Edge-IIoTset data, reproducible via the commands listed.

Paper title: **XZT-IIoT: Explainable Zero-Trust Access Control with
Autonomous Adversarial Validation and Lightweight Blockchain Audit for
Industrial IoT**
Status: rejected at IEEE-Blockchain 2026 (paper #1571356711, reviews 3/5
"Accept if Room" and 1/5 "Strong Reject"). This revision addresses the
reviews and is the basis for resubmission and for the author's diploma
thesis («Разработка и реализация объяснимого шлюза контроля доступа
Zero-Trust для периферийных устройств промышленного интернета вещей»).

**Contributions, now one integrated pipeline sharing one audit mechanism:**
- **Track 1** — Explainable trust scoring for IIoT network traffic
  (XGBoost + SHAP), validated on the real Edge-IIoTset benchmark.
- **Track 2** — Autonomous Zero-Trust ABAC policy self-hardening
  platform: an 8-agent architecture with an evolutionary adversarial
  search, a real objective-function-driven mitigation search, policy
  versioning/rollback, scheduled + event-triggered continuous
  operation, and an optional live CVE feed.
- **Integration (new in v4)** — every Track-2 access decision now
  consults the trained Track-1 model. Before v4 the two tracks ran side
  by side and never exchanged data; see the next section.

---

## WHAT CHANGED IN v4 — response to the rejection's core criticism

Both reviewers independently made the same central point: the trained
XGBoost model (Track 1) and the ABAC self-hardening loop (Track 2) were
not connected. The policy simulator scored trust with its own weighted
formula over hand-sampled ABAC attributes; Track 1's model was never
called. That criticism was correct.

**Fix (`self_hardening/ml_trust_bridge.py`, `trust_engine.py`):**
- The trust score gains a 7th weighted factor, `ml_risk` (weight 0.30,
  `config/trust_weights.yaml`), equal to the trained model's
  P(malicious).
- For each access request, the bridge maps the request's scenario onto
  an Edge-IIoTset traffic class, draws one **real record of that class
  from Track 1's held-out test split** (`results/test_split.csv`, never
  seen in training, so no leakage), deterministically per request ID,
  and uses the model's actual output for that record.
- The model's real errors carry through: a benign record the
  classifier misjudges lowers that legitimate request's trust, and
  NWFSR shows it. This is why NWFSR is no longer 100% (see 2.2).

| Track-2 scenario | Edge-IIoTset traffic class | Rationale |
|---|---|---|
| normal | Normal | legitimate traffic |
| stolen_credentials | Password | credential abuse looks like brute-force traffic |
| compromised_device | Backdoor | covert channel from a compromised device |
| network_zone_mismatch | Port_Scanning | access from an unexpected zone resembles reconnaissance |
| behavioral_anomaly | Fingerprinting | irregular probing behaviour |
| abnormal_access_time | Normal | time of day is an ABAC/context signal, not visible in packets |
| privilege_escalation_attempt | SQL_injection | abuse of elevated access, injection-like payload |
| replay_simulation | MITM | replayed/stale session, interception-adjacent |
| firmware_integrity_failure | Ransomware | severe device compromise |

The `abnormal_access_time → Normal` row is deliberate: claiming packet
statistics reveal *when* someone logs in would overclaim. It shows the
two signal sources are complementary — the ML model cannot see this
scenario, the ABAC context attributes can.

**Two bugs found and fixed along the way (disclose, they show the
validation process works):**
1. `blue_agent.py` had no mitigation rule at all for 3 of the 8 attack
   scenarios (`privilege_escalation_attempt`, `replay_simulation`,
   `firmware_integrity_failure`), so their bypasses could never be
   reduced by hardening. They now raise the `ml_risk` weight.
2. The first bridge version synthesized traffic rows from the synthetic
   generator's schema. On the real dataset (43 raw packet fields such
   as `tcp.ack`, `mqtt.hdrflags`) none of those columns existed, every
   feature was zero-filled, and the model returned one constant
   probability (0.963) for every request. A unit test caught it on the
   first real-data run. The bridge now samples real held-out rows and
   refuses to start on a feature mismatch instead of zero-filling; two
   regression tests guard this. **Any Track-2 numbers from that single
   run (ASR 4.7% → 0.7%, NWFSR 50.5%) are invalid and must not be
   used.**

**Headline evidence (Experiment F, section 2.3):** with scenarios,
policy and seed held fixed, wiring in the model cuts ASR from 34.4% to
9.4% at unchanged 100% NWFSR. That single controlled comparison is the
direct answer to the reviewers.

---

## TRACK 1 — Explainable Trust Scoring (unchanged from prior handoff — see there for full detail)

Quick reference (full detail was already handed off and is stable, not
touched in this session):
- XGBoost, F1=0.985, ROC-AUC=0.993 on real Edge-IIoTset (153,180 rows)
- SHAP explanation latency 0.17 ms/sample vs 0.038 ms plain inference (~4.4x) in the latest real-data run; earlier runs on other hardware measured 0.37 ms. The multiplier is machine-dependent (4–19x observed); cite absolute ms and name the machine
- **Classifier FPR (0.5 threshold) = 15.3%; deployed policy DENY rate (TAU_RESTRICT=0.40) on benign = 14.9%; RESTRICT rate = 0.5% — these are three distinct numbers, do not conflate (see paper-writing prompt for full explanation, an earlier draft mixed these up)**
- Multiclass (15-way): 88.7% accuracy, macro-F1=0.883
- Model comparison table justifies XGBoost over RF/LogReg empirically
- Figures: `figures/fig1-fig4, fig6`. Results: `results/*.json`

---

## TRACK 1.5 — Adversarial Evasion + Defense (NEW — the paper's strongest single finding)

**This should be a prominent subsection, possibly the headline result
of the Discussion.** It answers a question the base F1/accuracy
numbers cannot: does high offline accuracy mean the model resists a
motivated attacker? Answer: no. We measure how much, under three threat
models, and test the standard defense against the same attacks.

### Evaluation sample (fixed in v4 — all Track 1.5 numbers must be re-measured)

**Bug found during the R3 work:** `adversarial_evasion.py` drew its 200
attack samples from the WHOLE dataset (training rows included), while
`adversarial_training_defense.py` attacked 200 samples from the
held-out test split and then hard-coded the original model's rate
(0.915) from the first script. The published "91.5% → 28.0%" therefore
compared two different attack sets, and the 91.5% was not held-out.
`fig11` and the R3 text also called the first set "held-out", which was
wrong.

Fix: one shared sampler, `held_out_attack_sample()`, gives every
experiment the same 200 attacks from the held-out test split (unit-
tested). The defense script now attacks both models itself, on those
samples, with the same seeds, under the permissive and strict tiers.
Nothing is copied between scripts.

**Every number in this Track 1.5 section that predates this fix is
superseded.** Old values are kept below only so the change is
traceable; do not cite them.

### Attack: black-box feature-space evasion

`src/adversarial_evasion.py` — a query-only (no model-internals
access) hill-climbing search that perturbs a real attack sample's
features, bounded to the range of values actually observed in real
Edge-IIoTset traffic. Success criterion is the REAL deployed decision
threshold (`TAU_ALLOW=0.80` in `policy_engine.py`), not the raw 0.5
classifier boundary.

| | Value |
|---|---|
| Evasion, permissive, seed 42, held-out sample | **NOT MEASURED** (rerun pending) |
| Superseded (mixed train/test sample) | 91.5% (183/200) |

State the threat model explicitly: permissive feature space, the
attacker may set ANY feature within its observed range, including
protocol-state fields such as `tcp.seq` / `tcp.ack`. Report it as the
rate measured under this threat model, not as an upper bound and not
as a practical attack. The constrained tiers below address this.

**Citable detail (check it still holds after the rerun):** in the
superseded run the most-exploited features (`tcp.ack_raw`, `tcp.ack`,
`tcp.checksum`, `mqtt.hdrflags`, `tcp.seq`) were almost exactly the
ones SHAP ranks most important globally (fig2): the features that give
the model its explanatory power are also its main attack surface.

Figure: `figures/fig8_adversarial_evasion.png`.

### Protocol-constrained evasion (response to reviewer R3)

`src/adversarial_evasion_constrained.py` re-runs the identical search
on the same 200 held-out attacks with the identical budget, under three
threat models:

| Tier | What the attacker may change | Frozen fields (each has a written reason in the code) |
|---|---|---|
| permissive | every feature | none |
| protocol_constrained | everything the sender actually chooses | checksums (`tcp.checksum`, `icmp.checksum`), TCP sequence state (`tcp.seq`, `tcp.ack`, `tcp.ack_raw`), Wireshark-assigned indices (`udp.stream`, `tcp.stream`, `dns.retransmit_request_in`), `arp.hw.size` |
| strict | as above, minus TCP control flags | + `tcp.flags`, `tcp.flags.ack`, `tcp.connection.{syn,synack,fin,rst}` |

On the real data, 8 of 43 features are frozen in protocol_constrained
(`tcp.stream` is not a dataset feature) and 14 of 43 in strict.

Each tier is searched with 3 seeds (42, 43, 44). Two numbers per tier:

- **Single search run, mean ± std.** Shows search variance. It mixes
  the threat model with search efficiency: with fewer mutable features
  each random step concentrates on the rest, so a fixed-budget search
  can score a stricter tier higher (it did in the superseded run).
- **Best known (headline).** Fraction of blocked attacks evaded by any
  search whose threat model is at least as strict as this tier. An
  evasion found under stricter constraints is legal under looser ones,
  so this is a valid lower bound on the attacker in that tier and is
  monotone by construction (unit-tested).

Seed 42 of the permissive tier reproduces `adversarial_evasion.py`
exactly (printed as a sanity check). Figure:
`figures/fig11_constrained_evasion.png` (red = best known, gray =
single run).

| Tier | Single run (mean ± std) | Best known | Superseded run (mixed sample): single / best |
|---|---|---|---|
| permissive | NOT MEASURED | NOT MEASURED | 89.5% ± 1.5 / 100% |
| protocol_constrained | NOT MEASURED | NOT MEASURED | 78.2% ± 2.1 / 100% |
| strict | NOT MEASURED | NOT MEASURED | 83.0% ± 1.5 / 100% |

The superseded run already showed the qualitative answer to the
reviewer: with three restarts, a strict-tier attacker evaded every
blocked attack, so the vulnerability is not an artifact of the
permissive threat model. Confirm it on the held-out sample before
writing it. If the best-known bound saturates at 100% again, it cannot
rank the tiers; say so, and do not present single-run differences as
a constraint effect.

### Defense: adversarial training

`src/adversarial_training_defense.py` — generates 300 evasive examples
against the TRAINING set only (permissive attacker), adds them as
additional "attack" examples, retrains XGBoost, then attacks BOTH the
original and the defended model on the same 200 held-out attacks, with
the same seeds, under the permissive and strict tiers. Clean-data
metrics on the untouched test split for both models.

| | Original model | + Adversarial training |
|---|---|---|
| Evasion, permissive (single run / best known) | NOT MEASURED | NOT MEASURED |
| Evasion, strict (single run / best known) | NOT MEASURED | NOT MEASURED |
| Clean-data F1 / accuracy | 0.9855 / 0.9751 (superseded run) | 0.9856 / 0.9754 (superseded run) |
| Superseded headline (different samples, see above) | 91.5% | 28.0% |

The clean-data metrics did not depend on the sampling bug, so they
should reproduce; the evasion rows must be re-measured. When writing:
- The defense was trained on permissive-attacker examples only. If it
  helps much less against the strict attacker, report that plainly; it
  is a real finding about adversarial training, not a failure to hide.
- No clean-data decrease observed is "in this experiment", not "zero
  cost". Whatever residual evasion remains after defense is an open
  problem, not a solved one.

Figure: `figures/fig9_adversarial_defense.png` (left: evasion by tier,
original vs defended; right: clean-data metrics).

**Framing:** Track 1.5 is still a strong Discussion section (attack +
realistic constraints + defense + honest residual risk), but its
numbers come from the rerun, not from the superseded values.

Still not modelled, even in the strict tier: whether the perturbed
traffic still achieves the attack's purpose, and consistency between
mutable fields (e.g. `tcp.len` vs the actual payload). So the
best-known rates are lower bounds within each feature-space threat
model, but may over-estimate what a real attacker on the wire achieves.
State both directions.

### Limitation to add to the cumulative list

The adversarial evasion threat model is a permissive, feature-space
abstraction (see above) — it measures vulnerability under an idealized
attacker, not a proof that this exact attack is trivially executable by
crafting real packets on real industrial hardware. Real-world evasion
feasibility (whether an
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
| **BlueAgent** | `agents/blue_agent.py` | Rule-based mitigation: tightens thresholds and raises the `anomaly_risk` / `ml_risk` weights in response to the scenario types that bypassed this cycle (all 8 now have a lever — see v4 bug #1) |
| **ExplainabilityAgent** | `agents/explainability_agent.py` | Rule-based per-decision explanation: failed conditions + top-3 trust factors |
| **AuditAgent** | `agents/audit_agent.py` | Hash-chained ledger, structurally append-only |
| **CoordinatorAgent** | `agents/coordinator_agent.py` | Orchestrates all of the above across N cycles |

Canonical entry point: `self_hardening/run_agentic_multiseed.py` for
the paper's reported numbers (10 seeds, threat-weighted Red Agent, matches the
numbers table below). For the evolutionary/live-threat variant, use
`CoordinatorAgent.run_experiment(use_evolutionary_red=True,
try_live_threat_intel=True)` directly, or the API/dashboard.

### 2.2 Reported numbers (10 seeds, 5 cycles, threat-weighted 8-scenario Red Agent, ML-integrated trust — the CURRENT, authoritative run fig5 was generated from)

| Cycle | ASR (mean ± std) | NWFSR (mean ± std) |
|---|---|---|
| 0 | 11.6% ± 1.0% | 97.5% ± 2.5% |
| 1 | 11.7% ± 1.7% | 96.5% ± 2.3% |
| 2 | 11.1% ± 1.1% | 95.0% ± 3.2% |
| 3 | 9.6% ± 1.6% | 94.5% ± 2.7% |
| 4 | 7.7% ± 1.4% | 93.5% ± 3.9% |

**33.5% relative ASR reduction across cycles (3.9 points absolute),
at a cost of 4.0 points of NWFSR.** Source:
`self_hardening/results/hardening_multiseed_summary.json`. Figure:
`self_hardening/figures/fig5_hardening_cycles.png`.

How to read this honestly:
- The hardening loop now starts from a much lower ASR (11.6%) because
  the integrated model already blocks most attacks at cycle 0. The
  loop's own contribution is the further 11.6% → 7.7%.
- **The loop now trades availability for security.** NWFSR falls from
  97.5% to 93.5% because the Blue Agent raises the `ml_risk` weight and
  the classifier's real benign-traffic errors (~15% FPR, Track 1) then
  weigh more. Report this trade-off openly; it is exactly the
  security/availability tension the J objective is meant to manage.
  The old 100%-NWFSR table had no such tension only because the model
  was not in the loop.
- Cycle 1 ASR is not lower than cycle 0 (11.7% vs 11.6%): the decline
  is not monotonic per cycle, and the Red Agent re-samples scenarios
  every cycle. Do not describe it as "steadily decreasing".

**Superseded (pre-integration, do NOT use as the headline):** the
rejected submission reported 37.2% ± 2.6% → 15.3% ± 2.1% with 100%
NWFSR. That run never consulted the trained model. It can be cited only
as the "ABAC-only" comparison point, clearly labelled.

**Use this table for the paper.** The evolutionary/live-CVE mode is a
real, tested, working *extension* (great for a demo, a "future
directions realized" paragraph, or a follow-up paper) but was run with
different, non-standardized parameters during development — don't mix
its ad-hoc numbers into the reported table without re-running it
cleanly across the same 10 seeds first.

### 2.3 Ablation study — Experiments A–F

| Experiment | Zero-Trust | ML model | Explainability | Audit | Adaptive | ASR | NWFSR |
|---|---|---|---|---|---|---|---|
| A. Baseline ABAC | No | No | No | No | No | 70.0% | 100% |
| B. Zero-Trust ABAC | Yes | No | No | No | No | 34.4% | 100% |
| C. ZT + Explainability | Yes | No | Yes | No | No | 34.4% | 100% |
| D. ZT + Audit | Yes | No | No | Yes | No | 34.4% | 100% |
| **F. ZT + Track-1 model** | Yes | **Yes** | No | No | No | **9.4%** | **100%** |
| E. Full XZT-IIoT | Yes | Yes | Yes | Yes | Yes | 7.7% ± 1.4% | 93.5% |

Source: `self_hardening/results/ablation_table.json` / `.csv`.

- **B vs F is the controlled integration test:** same seed (42), same
  scenarios, same Cycle-0 policy; the only difference is whether the
  trust engine consults the model. ASR 34.4% → 9.4% (−73% relative),
  NWFSR unchanged at 100%.
- A–D and F are single-seed (42) static evaluations; E is the 10-seed
  mean after 5 cycles. Say so in the table caption.
- C and D intentionally match B: explainability and audit are
  observability layers, they do not change decisions. Their cost is
  latency (C: 0.005 ms/decision, D: 0.013 ms/decision in the latest run).

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

**33 pytest tests, all passing on real Edge-IIoTset** (`tests/test_xzt_iiot.py`) — trust
scoring, ML-bridge integration (scores differ by scenario, are not
constant, and a schema mismatch fails loudly), ABAC decisions incl. QUARANTINE/STEP_UP_AUTH, Red Agent scope
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
- The core reported result (2.2) stays the static-scenario, 10-seed table.
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
  from exploratory runs during development. (Use the same 10 seeds.)

### 2.6 Environment constraints (verified by direct testing, not assumed)

- Docker: not installed, cannot be installed (`apt-get install docker.io` fails — network-restricted package mirror).
- PostgreSQL, Mosquitto (MQTT broker): same — confirmed un-installable.
- `services.nvd.nist.gov`: unreachable from this sandbox (403 via egress proxy) — confirmed by a live attempt, not assumed.
- Everything else in this handoff (FastAPI, SQLite, APScheduler, XGBoost, SHAP, pytest) — pip-installable and fully tested here.

### 2.7 Known limitations to disclose (cumulative — do not omit any)

1. Rule-based/evolutionary Red/Blue agents, not deep-learning-based — explicit safety-scoped choice.
2. Legitimate-scenario ABAC attribute ranges are generous, which favours NWFSR; the ML factor now adds real classifier errors on top, so NWFSR is no longer trivially 100%.
3. Small policy/resource set (3 policies, 3 resource types).
4. Single-node, offline-by-default simulation; live CVE path exists but is network-dependent and untested-by-the-AI-assistant end-to-end.
5. BlueAgent mitigations auto-apply without a human-approval UI step (state machine exists in `policy_versioning.py` but isn't wired to a manual-approval gate in the API yet).
6. Evolutionary search operates only within pre-declared per-category numeric bounds — it cannot discover a genuinely new attack CATEGORY, only the worst case within an already-authorized one (this is a deliberate safety boundary, not an oversight — state it as such).
7. Scheduler requires the FastAPI process to stay running continuously; there is no persistence/resume if the process restarts mid-schedule (APScheduler's in-memory job store, not a durable one).
8. **ML/ABAC pairing is a modelling assumption.** Each simulated ABAC request is paired with a real held-out Edge-IIoTset record of the class its scenario maps to (table in "What changed in v4"). The traffic and the identity/device attributes therefore do not come from one physical session. The mapping is documented and fixed, not tuned, but a reviewer may question individual rows. The planned hardware testbed (below) removes this assumption.
9. `abnormal_access_time` is invisible to the ML factor by design; its bypasses can only be closed by ABAC context rules.
10. The audit ledger is a single-node SHA-256 hash chain: tamper-evident, not a distributed blockchain (no consensus, replication or external anchoring). Say "hash-chained audit log" in the paper; do not claim blockchain-level guarantees.

### 2.8 Reviewer criticisms — status

| # | Criticism (IEEE-Blockchain 2026 reviews) | Status |
|---|---|---|
| R1 | Track 1 and Track 2 not integrated; policy loop ignores the trained model | **Fixed in v4** — ML bridge + Experiment F (34.4% → 9.4% ASR, controlled) |
| R2 | Single-node hash chain overclaimed as blockchain | Limitation 10 stated; wording in paper must follow it. Open option: periodic anchoring of the chain head to an external timestamping service |
| R3 | Feature-space evasion may perturb fields an attacker cannot control | **Implemented** — three threat-model tiers (`src/adversarial_evasion_constrained.py`) and the defense evaluated under permissive and strict. A first real-data run showed a strict attacker with 3 restarts evading all 200 blocked attacks, but it used a mixed train/test sample (bug fixed in v4); held-out numbers NOT MEASURED until rerun |
| R4 | Only one scenario family; no out-of-distribution attacks or boundary cases | Open. Planned: hold out some attack classes from Red Agent generation and test hardened policies against them; add borderline legitimate workflows |
| R5 | "Agent" undefined; components look like scripted modules | Open. Planned: an explicit definition (perceive → decide → act with state and a goal) and honest relabelling of components that do not meet it |

### 2.9 Hardware testbed (diploma prototype, planned)

Raspberry Pi 4 as the gateway (MQTT broker + this policy engine + the
model + audit log + dashboard), three ESP32 nodes (temperature sensor,
relay-driven pump, attacker node with button-triggered test scenarios),
OLED/LED/buzzer for decision feedback, RC522 RFID for STEP_UP_AUTH.
Isolated Wi-Fi network only. It turns the simulated ABAC attributes
into measured ones (firmware hash → `device_integrity`, message rate →
`behavioral_trust`, source subnet → `network_zone`, live `tshark`
fields → `ml_risk`) and lets the Edge-IIoTset-trained model be
evaluated on live traffic (domain shift), which also addresses
limitation 8 and partially R3. **No hardware results exist yet; report
none until measured.**

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
3. Methodology — 3a: XGBoost+SHAP trust scoring; 3b: integration of the model into the ABAC trust score (`ml_risk`, held-out record sampling, scenario→class table); 3c: 8-agent self-hardening loop (mention evolutionary/live-CVE as implemented extensions); 3d: shared hash-chained audit log
4. Results — Track 1 (fig1-4,6), Track 1.5 (fig8-9), Track 2 (fig5, ablation table A–F with B vs F as the integration result)
5. Discussion — precision/recall trade-off, cost of explainability, the security/availability trade-off now visible in NWFSR, ML-blind scenarios (abnormal_access_time)
6. Limitations — full cumulative list (Track 1 + 2.7 above)
7. Conclusion + Future Work
