"""
ml_trust_bridge.py
---------------------
THE INTEGRATION FIX. Both rejection reviews converge on one core
criticism: Track 1 (the trained XGBoost traffic classifier) and
Track 2 (the ABAC self-hardening loop) are not actually connected --
the policy simulator scores trust with its own separate weighted
formula, never touching the trained model's output. This module is
the bridge that removes that disconnect.

WHY THIS ISN'T A TRIVIAL "JUST CALL .PREDICT()":
Track 1's XGBoost model consumes network-traffic-flow features
(pkt_rate, byte_rate, tcp_syn_count, payload_entropy, ...). Track 2's
ABAC engine reasons over identity/device/context attributes
(identity_confidence, device_integrity, behavioral_trust, ...). These
are genuinely different feature spaces -- a real Zero-Trust gateway
sits between both layers in practice (it sees the identity/device
claims AND the traffic the session generates). So the honest
integration is: for every access request the self-hardening loop
evaluates, synthesize the network-traffic signature that request's
scenario would plausibly produce, run the ACTUAL trained model on
it, and feed its P(malicious) output into the trust score as a
first-class, separately-weighted factor (ml_risk) -- not a fabricated
number, and not hidden inside an unrelated field.

SCENARIO -> TRAFFIC-SIGNATURE MAPPING (documented, not hand-waved):
Track 2's 8 abstract ABAC attack classes are mapped onto one of Track
1's Edge-IIoTset-aligned traffic attack types each, chosen by what a
real attacker producing that ABAC-level symptom would plausibly look
like on the wire. One scenario (abnormal_access_time) is deliberately
mapped to "Normal" traffic -- accessing at 3am is an ABAC/context-level
signal, not something that shows up in packet statistics, and pretending
otherwise would overclaim what traffic classification can see. That is
itself evidence for the paper: ABAC context attributes and the ML
traffic model are complementary signals, not redundant ones.
"""

import hashlib
import importlib.util
import random
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd

REPO_ROOT = Path(__file__).parent.parent
SRC = REPO_ROOT / "src"
# train_trust_model.py is run with cwd=<repo root> (see run_all.py), and its
# MODEL_PATH is relative ("./results/trust_model.joblib") -- so the trained
# model actually lands at <repo root>/results/, not src/results/.
MODEL_PATH = REPO_ROOT / "results" / "trust_model.joblib"


def _load_module(name: str, path: Path):
    """Load a src/ script as a module by explicit file path -- avoids
    putting src/ on sys.path, which would shadow self_hardening/'s own
    policy_engine.py / trust_engine.py (same filenames, different
    content). Same pattern already used by hardening_loop.py for
    audit_chain.py."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_gen_dataset = _load_module("generate_dataset_reused", SRC / "generate_dataset.py")

# Maps each Track-2 ABAC scenario label onto one Track-1 attack-type key
# from generate_dataset.ATTACK_TYPES (see module docstring for rationale).
SCENARIO_TO_ATTACK_TYPE = {
    "normal": "Normal",
    "stolen_credentials": "Password",              # credential/auth abuse -> brute-force-like signature
    "compromised_device": "Backdoor",               # device-level compromise -> covert channel signature
    "network_zone_mismatch": "Port_Scanning",        # unexpected-zone access -> reconnaissance signature
    "behavioral_anomaly": "Fingerprinting",          # irregular probing behavior
    "abnormal_access_time": "Normal",                # time-of-day is an ABAC/context signal, not a traffic one
    "privilege_escalation_attempt": "SQL_Injection",  # abuse of elevated access -> injection-like payload signature
    "replay_simulation": "MITM",                     # replayed/stale session -> interception-adjacent signature
    "firmware_integrity_failure": "Ransomware",      # severe device compromise -> high-severity malware signature
}

# Resource -> plausible device_type for the synthesized traffic row
# (generate_dataset.DEVICES is a different, coarser taxonomy than
# device_simulator.DEVICE_TYPES; this maps Track 2's three resources
# onto it).
RESOURCE_TO_DEVICE_TYPE = {
    "PLC_CONTROLLER": "PLC",
    "HMI_WORKSTATION": "HMI",
    "PUMP_CONTROLLER": "actuator",
}


class MLTrustBridge:
    """Loads the trained Track-1 model once and scores Track-2 access
    requests against it by synthesizing a consistent traffic row for
    each request's scenario label."""

    def __init__(self, model_path: Path = MODEL_PATH):
        if not model_path.exists():
            raise FileNotFoundError(
                f"Trained trust model not found at {model_path}. "
                "Run `python src/train_trust_model.py` first (or `python run_all.py` "
                "from the repo root) -- the self-hardening loop needs the ACTUAL "
                "trained Track-1 model to score requests against, not a placeholder."
            )
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.feature_cols = bundle["feature_cols"]
        self.encoders = bundle["encoders"]

    def _encode_row(self, df: pd.DataFrame) -> pd.DataFrame:
        """Mirror train_trust_model.load_and_encode's categorical encoding
        for a single synthesized row, using the SAME fitted encoders the
        model was trained with (never re-fit on the fly -- that would
        silently change what the labels mean)."""
        for col, le in self.encoders.items():
            if col not in df.columns:
                continue
            raw = df[col].astype(str)
            known = set(le.classes_)
            # An unseen category (shouldn't happen -- generate_dataset only
            # emits values the encoder was fit on -- but fail safe rather
            # than crash the whole hardening loop over one row).
            safe = raw.where(raw.isin(known), le.classes_[0])
            df[col + "_enc"] = le.transform(safe)
        for col in self.feature_cols:
            if col not in df.columns:
                df[col] = 0
        return df[self.feature_cols]

    def score_scenario(self, scenario_label: str, resource: str, request_id: str) -> float:
        """Returns P(malicious) in [0,1] from the ACTUAL trained Track-1
        model, for one synthesized traffic row representing this
        request's scenario. Deterministic per request_id (same request
        always yields the same synthesized row + score), so results are
        reproducible across runs with the same scenario seed."""
        attack_type = SCENARIO_TO_ATTACK_TYPE.get(scenario_label, "Normal")
        device_type = RESOURCE_TO_DEVICE_TYPE.get(resource, "PLC")
        local_rng = random.Random(f"{request_id}:{scenario_label}")
        protocol = local_rng.choice(_gen_dataset.PROTOCOLS)

        df = _gen_dataset._base_row(1, [device_type], [protocol])
        df = _gen_dataset._apply_attack_signature(df, attack_type)
        X = self._encode_row(df)
        p_malicious = float(self.model.predict_proba(X)[:, 1][0])
        return p_malicious


_singleton: Optional[MLTrustBridge] = None
_singleton_failed = False


def get_bridge(model_path: Path = MODEL_PATH) -> Optional[MLTrustBridge]:
    """Process-wide singleton (avoid re-loading the joblib model on every
    single request -- it's called once per AccessRequest per cycle).
    Returns None (not an exception) if the model isn't trained yet, so
    callers can fall back to the ABAC-only trust formula with a clear
    warning instead of crashing -- useful for running the self-hardening
    module standalone/in tests without first training Track 1."""
    global _singleton, _singleton_failed
    if _singleton is not None:
        return _singleton
    if _singleton_failed:
        return None
    try:
        _singleton = MLTrustBridge(model_path)
        return _singleton
    except FileNotFoundError as e:
        print(f"[ml_trust_bridge] WARNING: {e}")
        print("[ml_trust_bridge] Falling back to ABAC-only trust scoring "
              "(Track 1/Track 2 integration DISABLED for this run).")
        _singleton_failed = True
        return None
