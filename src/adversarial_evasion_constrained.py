"""
adversarial_evasion_constrained.py
-------------------------------------
Answers reviewer criticism R3 of the rejected submission: the original
evasion attack (adversarial_evasion.py) lets the attacker change ANY
feature, including fields a real sender cannot set freely. Here the
SAME black-box search, on the SAME 200 held-out attack samples, with
the SAME search budget, is re-run under three threat models:

  permissive            every feature may change (original result,
                        reproduced here as a sanity check)
  protocol_constrained  fields computed by the protocol stack or created
                        by the capture tool are frozen (see FROZEN_PROTOCOL)
  strict                additionally freezes TCP control flags, because an
                        attacker who needs a working TCP session cannot
                        flip them at will (see FROZEN_STRICT_EXTRA)

Every frozen field has a written reason below. Edge-IIoTset features
are Wireshark field names, so the rules match by exact name; a field
the rules do not name stays mutable (the conservative choice: it can
only make the attacker stronger, never weaker).

WHAT THIS STILL DOES NOT MODEL: whether a perturbed attack would still
achieve its goal (functionality preservation), and inter-feature
consistency beyond the frozen set (e.g. tcp.len vs the real payload).
Both make the constrained results an over-estimate of a real attacker,
not an under-estimate. Say so in the paper.
"""

import json
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from adversarial_evasion import (compute_feature_bounds, evasion_search,  # noqa: E402
                                  load_model, predict_p_malicious, N_SAMPLES)
from policy_engine import decide, TAU_ALLOW  # noqa: E402
from train_trust_model import load_and_encode, DATA_PATH  # noqa: E402

RESULTS_PATH = "./results/adversarial_evasion_constrained.json"
# The search is random, so one run per tier mixes the effect of the
# threat model with search noise (a single run can even rank strict
# above protocol_constrained). Each tier is searched with these seeds;
# report mean +/- std. Seed 42 alone reproduces adversarial_evasion.py
# exactly for the permissive tier -- a built-in sanity check.
SEARCH_SEEDS = [42, 43, 44]

# Fields the sender cannot choose independently of the rest of the
# packet or of the connection state.
FROZEN_PROTOCOL = {
    "tcp.checksum": "computed by the sender's stack from header+payload; a wrong value gets the packet dropped",
    "icmp.checksum": "computed from the ICMP message; a wrong value gets the packet dropped",
    "tcp.seq": "relative sequence number, fixed by bytes already sent on the connection",
    "tcp.ack": "relative acknowledgement number, fixed by bytes received from the peer",
    "tcp.ack_raw": "absolute acknowledgement number, fixed by the peer's sequence space",
    "udp.stream": "stream index assigned by Wireshark at capture time, not a packet field",
    "tcp.stream": "stream index assigned by Wireshark at capture time, not a packet field",
    "dns.retransmit_request_in": "frame reference computed by Wireshark's analysis, not a packet field",
    "arp.hw.size": "hardware address length, fixed by the link layer (6 on Ethernet)",
}

# Extra fields frozen only in the strict tier.
FROZEN_STRICT_EXTRA = {
    "tcp.flags": "a working session needs the flag sequence the TCP state machine expects",
    "tcp.flags.ack": "ACK must be set on every segment after the handshake",
    "tcp.connection.syn": "derived from the flags of a valid handshake",
    "tcp.connection.synack": "derived from the flags of a valid handshake",
    "tcp.connection.fin": "derived from the flags of a valid teardown",
    "tcp.connection.rst": "derived from the flags of a valid teardown",
}

TIERS = {
    "permissive": set(),
    "protocol_constrained": set(FROZEN_PROTOCOL),
    "strict": set(FROZEN_PROTOCOL) | set(FROZEN_STRICT_EXTRA),
}


def split_features(feature_cols, frozen_names):
    """Return (mutable, frozen_present) for one tier."""
    frozen_present = [c for c in feature_cols if c in frozen_names]
    mutable = [c for c in feature_cols if c not in frozen_names]
    return mutable, frozen_present


def run_tier(model, feature_cols, bounds, attack_rows, mutable, seed):
    """One search pass over all samples with a fresh RNG, so every tier
    gets an identical random budget for a given seed."""
    rng = np.random.default_rng(seed)
    n_blocked = n_evaded = 0
    iters = []
    for orig in attack_rows:
        orig_p = predict_p_malicious(model, feature_cols, orig)
        orig_decision = decide(1 - orig_p)
        adv, adv_p, history = evasion_search(model, feature_cols, bounds, orig, rng,
                                              mutable_cols=mutable)
        adv_decision = decide(1 - adv_p)
        if orig_decision != "ALLOW":
            n_blocked += 1
            if adv_decision == "ALLOW":
                n_evaded += 1
        iters.append(len(history) - 1)
    return {
        "n_samples_tested": len(attack_rows),
        "n_originally_blocked": n_blocked,
        "n_successfully_evaded_to_allow": n_evaded,
        "evasion_success_rate_of_blocked": round(n_evaded / n_blocked, 4) if n_blocked else None,
        "avg_search_iterations": round(float(np.mean(iters)), 1),
    }


def main():
    print("Loading model and real Edge-IIoTset attack samples...")
    model, feature_cols = load_model()
    df, _, _ = load_and_encode(DATA_PATH)
    attack_df = df[df.label_binary == 1].sample(n=N_SAMPLES, random_state=42)
    bounds = compute_feature_bounds(df, feature_cols)
    attack_rows = [row[feature_cols].to_dict() for _, row in attack_df.iterrows()]

    out = {"threat_models": {}, "success_criterion":
           f"adversarial trust_score >= TAU_ALLOW ({TAU_ALLOW}), i.e. a real ALLOW decision",
           "frozen_field_reasons": {**FROZEN_PROTOCOL, **FROZEN_STRICT_EXTRA}}

    for tier, frozen_names in TIERS.items():
        mutable, frozen_present = split_features(feature_cols, frozen_names)
        missing = sorted(frozen_names - set(frozen_present))
        print(f"\n[{tier}] frozen {len(frozen_present)} of {len(feature_cols)} features: {frozen_present}")
        if missing:
            print(f"  (rules name {len(missing)} field(s) not in this dataset's features: {missing})")
        t0 = time.perf_counter()
        runs = []
        for seed in SEARCH_SEEDS:
            r = run_tier(model, feature_cols, bounds, attack_rows, mutable, seed)
            r["seed"] = seed
            runs.append(r)
            print(f"  seed {seed}: {r['n_successfully_evaded_to_allow']}/{r['n_originally_blocked']} "
                  f"= {r['evasion_success_rate_of_blocked']}")
        rates = np.array([r["evasion_success_rate_of_blocked"] for r in runs], dtype=float)
        out["threat_models"][tier] = {
            "evasion_rate_mean": round(float(rates.mean()), 4),
            "evasion_rate_std": round(float(rates.std()), 4),
            "search_seeds": SEARCH_SEEDS,
            "per_seed": runs,
            "frozen_features": frozen_present,
            "n_mutable_features": len(mutable),
            "wall_time_s": round(time.perf_counter() - t0, 1),
        }

    if not out["threat_models"]["protocol_constrained"]["frozen_features"]:
        print("\nWARNING: no protocol-derived fields exist in this dataset's features "
              "(e.g. the synthetic generator), so the tiers cannot differ. "
              "Run on the real Edge-IIoTset for a meaningful comparison.")

    print("\n" + "=" * 60)
    for tier, res in out["threat_models"].items():
        print(f"{tier:22s} evasion = {res['evasion_rate_mean']:.3f} ± {res['evasion_rate_std']:.3f} "
              f"({len(res['frozen_features'])} frozen, {len(SEARCH_SEEDS)} search seeds)")
    seed42 = out["threat_models"]["permissive"]["per_seed"][0]["evasion_success_rate_of_blocked"]
    print(f"Sanity check: permissive, seed 42 = {seed42} "
          "(should equal evasion_success_rate_of_blocked in adversarial_evasion.json)")

    with open(RESULTS_PATH, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
