"""
ml_trust_bridge.py
---------------------
THE INTEGRATION FIX. Both rejection reviews converge on one core
criticism: Track 1 (the trained XGBoost traffic classifier) and
Track 2 (the ABAC self-hardening loop) are not actually connected --
the policy simulator scores trust with its own separate weighted
formula, never touching the trained model's output. This module is
the bridge that removes that disconnect.

HOW A REQUEST GETS AN ML SCORE
Track 1's model consumes network-traffic features; Track 2's ABAC
engine reasons over identity/device/context attributes. A real
Zero-Trust gateway sees both for the same session: the identity and
device claims, AND the traffic that session generates. So for every
access request the self-hardening loop evaluates, this bridge:

  1. maps the request's scenario label onto an Edge-IIoTset traffic
     class (table below),
  2. draws one REAL traffic record of that class from Track 1's
     held-out test split (results/test_split.csv -- rows the model
     never saw during training, so there is no train/test leakage),
     deterministically per request_id,
  3. returns the trained model's actual P(malicious) for that record.

The model's real errors carry through honestly: a Normal record the
classifier misjudges (Track 1 has a ~15% false-positive rate on benign
traffic) will push that legitimate request's trust down, and the
NWFSR metric will show it. Nothing is smoothed over.

WHY REAL HELD-OUT ROWS AND NOT SYNTHESIZED ONES
An earlier version of this module synthesized a traffic row per
request with src/generate_dataset.py. That only works when the model
was trained on the synthetic generator's schema. On the real
Edge-IIoTset (43 raw packet-field features such as tcp.ack, tcp.seq,
mqtt.hdrflags) none of the synthesized columns existed, every feature
was silently zero-filled, and the model returned the SAME constant
probability for every request -- normal and attack alike. That bug was
caught by test_bridge_scores_attack_scenarios_higher_than_normal on
the first run against real data. Sampling real held-out rows works for
any schema by construction, and the bridge now refuses to start (with
a clear error) if the test split does not contain every feature the
model expects, instead of zero-filling.

SCENARIO -> TRAFFIC CLASS MAPPING (documented, not hand-waved)
One scenario (abnormal_access_time) is deliberately mapped to Normal
traffic: accessing at 3am is an ABAC/context-level signal, not
something visible in packet statistics, and pretending otherwise would
overclaim what traffic classification can see. That is itself a
finding: ABAC context attributes and the ML traffic model are
complementary signals, not redundant ones.
"""

import random
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
# train_trust_model.py runs with cwd=<repo root> (see run_all.py) and writes
# relative to it, so both artifacts land in <repo root>/results/.
MODEL_PATH = REPO_ROOT / "results" / "trust_model.joblib"
TEST_SPLIT_PATH = REPO_ROOT / "results" / "test_split.csv"

# Track-2 ABAC scenario label -> Edge-IIoTset traffic class. Labels are
# matched case-insensitively, because the real dataset spells one class
# "SQL_injection" while the synthetic generator spells it "SQL_Injection".
SCENARIO_TO_ATTACK_TYPE = {
    "normal": "Normal",
    "stolen_credentials": "Password",              # credential abuse -> brute-force-like traffic
    "compromised_device": "Backdoor",               # device-level compromise -> covert channel
    "network_zone_mismatch": "Port_Scanning",        # unexpected-zone access -> reconnaissance
    "behavioral_anomaly": "Fingerprinting",          # irregular probing behavior
    "abnormal_access_time": "Normal",                # time of day is an ABAC/context signal, not a traffic one
    "privilege_escalation_attempt": "SQL_Injection",  # abuse of elevated access -> injection payload
    "replay_simulation": "MITM",                     # replayed/stale session -> interception-adjacent
    "firmware_integrity_failure": "Ransomware",      # severe device compromise -> high-severity malware
    # out-of-distribution classes, used only by generalization_experiment.py
    "insider_flood": "DDoS_UDP",                     # legitimate-looking device flooding the target
    "low_and_slow": "Normal",                        # ABAC-boundary probe with ordinary traffic
}

NON_FEATURE_COLUMNS = {"label_binary", "device_id", "attack_type"}


class MLTrustBridge:
    """Loads the trained Track-1 model and its held-out test split once,
    precomputes P(malicious) for every held-out record, and serves a
    real, deterministic per-request score for Track-2 access requests."""

    def __init__(self, model_path: Path = MODEL_PATH, test_split_path: Path = TEST_SPLIT_PATH):
        for p in (model_path, test_split_path):
            if not p.exists():
                raise FileNotFoundError(
                    f"{p.name} not found at {p}. Run `python src/train_trust_model.py` "
                    "from the repo root first (or `python run_all.py`). The self-hardening "
                    "loop needs the ACTUAL trained Track-1 model and its held-out test "
                    "split, not a placeholder."
                )
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.feature_cols: List[str] = list(bundle["feature_cols"])

        split = pd.read_csv(test_split_path)
        missing = [c for c in self.feature_cols if c not in split.columns]
        if missing:
            # Refuse rather than zero-fill: zero-filling is exactly the bug
            # that made every request score identically on real data.
            raise ValueError(
                f"test_split.csv is missing {len(missing)} of the model's "
                f"{len(self.feature_cols)} features (e.g. {missing[:5]}). The model and "
                "test split come from different training runs -- re-run "
                "`python src/train_trust_model.py`."
            )
        if "attack_type" not in split.columns:
            raise ValueError("test_split.csv has no attack_type column -- re-run train_trust_model.py.")

        # One batched prediction over the whole held-out set; per-request
        # scoring is then a lookup (the loop scores thousands of requests).
        self.p_malicious = self.model.predict_proba(split[self.feature_cols])[:, 1]
        self.attack_type = split["attack_type"].astype(str).to_numpy()

        self.rows_by_class: Dict[str, np.ndarray] = {}
        for cls in np.unique(self.attack_type):
            self.rows_by_class[cls.lower()] = np.flatnonzero(self.attack_type == cls)

        unavailable = sorted({t for t in SCENARIO_TO_ATTACK_TYPE.values()
                              if t.lower() not in self.rows_by_class})
        if unavailable:
            raise ValueError(
                f"Held-out test split has no records of traffic class(es) {unavailable}, "
                f"needed by SCENARIO_TO_ATTACK_TYPE. Classes present: "
                f"{sorted(self.attack_type_names())}."
            )

    def attack_type_names(self) -> List[str]:
        return sorted(set(self.attack_type.tolist()))

    def _pick_row(self, scenario_label: str, request_id: str) -> int:
        attack_type = SCENARIO_TO_ATTACK_TYPE.get(scenario_label, "Normal")
        candidates = self.rows_by_class[attack_type.lower()]
        rng = random.Random(f"{request_id}:{scenario_label}")
        return int(candidates[rng.randrange(len(candidates))])

    def score_scenario(self, scenario_label: str, resource: str, request_id: str) -> float:
        """P(malicious) in [0,1] from the ACTUAL trained Track-1 model, for
        one real held-out traffic record of the class this request's
        scenario maps to. Deterministic per (request_id, scenario_label),
        so runs with the same scenario seed are reproducible. `resource`
        is accepted for interface stability; record choice does not
        depend on it."""
        return float(self.p_malicious[self._pick_row(scenario_label, request_id)])

    def describe_scenario(self, scenario_label: str, request_id: str) -> dict:
        """Which real record backed a score -- for explanations and audits."""
        idx = self._pick_row(scenario_label, request_id)
        return {"test_split_row": idx, "traffic_class": str(self.attack_type[idx]),
                "p_malicious": float(self.p_malicious[idx])}


_singleton: Optional[MLTrustBridge] = None
_singleton_failed = False


def get_bridge(model_path: Path = MODEL_PATH,
               test_split_path: Path = TEST_SPLIT_PATH) -> Optional[MLTrustBridge]:
    """Process-wide singleton. Returns None (with a printed warning, not
    an exception) only when Track 1 has not been trained yet, so the
    self-hardening module can still run standalone on the ABAC-only
    formula. Schema mismatches DO raise: they mean the artifacts are
    inconsistent, and silently degrading there is what hid the
    zero-fill bug."""
    global _singleton, _singleton_failed
    if _singleton is not None:
        return _singleton
    if _singleton_failed:
        return None
    try:
        _singleton = MLTrustBridge(model_path, test_split_path)
        return _singleton
    except FileNotFoundError as e:
        print(f"[ml_trust_bridge] WARNING: {e}")
        print("[ml_trust_bridge] Falling back to ABAC-only trust scoring "
              "(Track 1/Track 2 integration DISABLED for this run).")
        _singleton_failed = True
        return None
