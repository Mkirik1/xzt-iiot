"""
test_adversarial_evasion.py
-------------------------------
Sanity checks for the evasion search: perturbed features never exceed
the bounds actually observed in real data (the stated threat model),
and the search never decreases confidence by accident (hill-climbing
correctness).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import numpy as np
import pytest

from adversarial_evasion import (compute_feature_bounds, evasion_search,
                                  load_model, predict_p_malicious)
from train_trust_model import load_and_encode, DATA_PATH


@pytest.fixture(scope="module")
def setup():
    model, feature_cols = load_model()
    df, _, _ = load_and_encode(DATA_PATH)
    bounds = compute_feature_bounds(df, feature_cols)
    return model, feature_cols, df, bounds


def test_perturbed_features_stay_within_observed_bounds(setup):
    model, feature_cols, df, bounds = setup
    rng = np.random.default_rng(123)
    row = df[df.label_binary == 1].iloc[0][feature_cols].to_dict()
    adv, _, _ = evasion_search(model, feature_cols, bounds, row, rng, max_iters=30)
    for f in feature_cols:
        lo, hi, _ = bounds[f]
        assert lo - 1e-6 <= adv[f] <= hi + 1e-6, f"{f} escaped observed bounds: {adv[f]} not in [{lo},{hi}]"


def test_hill_climbing_never_gets_worse(setup):
    model, feature_cols, df, bounds = setup
    rng = np.random.default_rng(5)
    row = df[df.label_binary == 1].iloc[10][feature_cols].to_dict()
    orig_p = predict_p_malicious(model, feature_cols, row)
    adv, adv_p, history = evasion_search(model, feature_cols, bounds, row, rng, max_iters=40)
    assert adv_p <= orig_p + 1e-9
    # history should be non-increasing (we only ever keep improvements)
    assert all(history[i] >= history[i + 1] - 1e-9 for i in range(len(history) - 1))


def test_constrained_search_never_touches_frozen_features(setup):
    """R3 threat model: features outside mutable_cols must come back
    exactly as they went in, whatever the schema."""
    model, feature_cols, df, bounds = setup
    mutable = feature_cols[: len(feature_cols) // 2]
    frozen = [f for f in feature_cols if f not in mutable]
    rng = np.random.default_rng(7)
    row = df[df.label_binary == 1].iloc[3][feature_cols].to_dict()
    adv, _, _ = evasion_search(model, feature_cols, bounds, row, rng,
                               max_iters=40, mutable_cols=mutable)
    for f in frozen:
        assert adv[f] == row[f], f"frozen feature {f} was changed"


def test_no_mutable_features_means_no_change(setup):
    model, feature_cols, df, bounds = setup
    row = df[df.label_binary == 1].iloc[4][feature_cols].to_dict()
    adv, adv_p, history = evasion_search(model, feature_cols, bounds, row,
                                         np.random.default_rng(1), mutable_cols=[])
    assert adv == row and len(history) == 1


def test_tier_split_freezes_named_protocol_fields():
    from adversarial_evasion_constrained import TIERS, split_features
    cols = ["tcp.seq", "tcp.ack", "tcp.checksum", "tcp.flags", "tcp.len", "mqtt.hdrflags"]
    mutable, frozen = split_features(cols, TIERS["protocol_constrained"])
    assert set(frozen) == {"tcp.seq", "tcp.ack", "tcp.checksum"}
    assert "tcp.flags" in mutable and "tcp.len" in mutable
    _, frozen_strict = split_features(cols, TIERS["strict"])
    assert "tcp.flags" in frozen_strict
    assert split_features(cols, TIERS["permissive"]) == (cols, [])


def test_best_known_is_monotone_even_when_single_runs_are_not():
    """Reproduces the real-data situation: a single strict run evades more
    than a protocol_constrained run. The pooled lower bound must still
    rank permissive >= protocol_constrained >= strict."""
    from adversarial_evasion_constrained import add_best_known
    run = lambda idx: {"n_originally_blocked": 10, "evaded_sample_idx": idx}
    tm = {
        "permissive": {"frozen_features": [], "per_seed": [run([0, 1, 2])]},
        "protocol_constrained": {"frozen_features": ["tcp.seq"], "per_seed": [run([0, 1])]},
        "strict": {"frozen_features": ["tcp.seq", "tcp.flags"], "per_seed": [run([5, 6, 7, 8])]},
    }
    add_best_known(tm)
    rates = [tm[t]["evasion_rate_best_known"] for t in ("permissive", "protocol_constrained", "strict")]
    assert rates == [0.7, 0.6, 0.4]
    assert rates == sorted(rates, reverse=True)
    assert tm["strict"]["best_known_pooled_from_tiers"] == ["strict"]


def test_evaluation_attacks_come_only_from_held_out_split(setup):
    """Every evasion experiment must attack the same held-out samples;
    an earlier version sampled from the whole dataset, training rows
    included, so before/after defense numbers used different attacks."""
    from sklearn.model_selection import train_test_split
    from adversarial_evasion import held_out_attack_sample
    model, feature_cols, df, bounds = setup
    a = held_out_attack_sample(df, feature_cols)
    b = held_out_attack_sample(df, feature_cols)
    assert list(a.index) == list(b.index)
    assert (a["label_binary"] == 1).all()
    _, X_test = train_test_split(df[feature_cols], test_size=0.25, random_state=42,
                                 stratify=df["label_binary"])
    assert set(a.index) <= set(X_test.index)
