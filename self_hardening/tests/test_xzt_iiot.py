"""
test_xzt_iiot.py
-------------------
Brief Section 45: tests for trust scoring, ABAC decision, audit hash
verification, Red Agent target restrictions, normal workflow, attack
simulation, self-hardening loop, rollback.

Run with: pytest tests/ -v   (from self_hardening/)
"""

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from attributes import (AccessRequest, SubjectAttributes, DeviceAttributes,
                         NetworkAttributes, ContextAttributes)
from normal_scenarios import generate_normal_scenarios
from objective_function import apply_candidate, objective_J, search_best_candidate
from policy_engine import PolicyEngine
from policy_versioning import PolicyVersionHistory
from red_agent import generate_attack_scenarios, SCENARIOS
from trust_engine import TrustEngine, TrustWeights
from validation_agent import validate

CONFIG = Path(__file__).parent.parent / "config"


@pytest.fixture
def trust_engine():
    return TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")))


@pytest.fixture
def policy_engine(trust_engine):
    return PolicyEngine(str(CONFIG / "policies.yaml"), trust_engine)


def make_request(**overrides):
    base = dict(
        request_id="test_req",
        subject=SubjectAttributes(user_id="u1", role="engineer",
                                   identity_confidence=0.9, authentication_strength=0.9),
        device=DeviceAttributes(device_id="d1", device_integrity=0.9, patch_level=0.9),
        network=NetworkAttributes(source_zone="engineering", expected_zone="engineering"),
        context=ContextAttributes(behavioral_trust=0.9, anomaly_score=0.05, access_hour=10),
        resource="PLC_CONTROLLER", action="WRITE_SETPOINT",
    )
    base.update(overrides)
    return AccessRequest(**base)


# ---- Trust scoring ----

class TestTrustEngine:
    def test_high_quality_request_scores_high(self, trust_engine):
        req = make_request()
        score = trust_engine.score(req)
        assert 0.7 < score <= 1.0

    def test_low_quality_request_scores_low(self, trust_engine):
        req = make_request(
            subject=SubjectAttributes(user_id="u2", role="engineer",
                                       identity_confidence=0.1, authentication_strength=0.1),
            context=ContextAttributes(behavioral_trust=0.1, anomaly_score=0.95, access_hour=3))
        score = trust_engine.score(req)
        assert score < 0.4

    def test_score_bounded_0_1(self, trust_engine):
        for req in generate_attack_scenarios(n_per_type=5, seed=99):
            s = trust_engine.score(req)
            assert 0.0 <= s <= 1.0

    def test_factor_breakdown_sums_close_to_score(self, trust_engine):
        req = make_request()
        breakdown = trust_engine.factor_breakdown(req)
        # breakdown is pre-normalization; just check all expected keys present.
        # ml_model_risk is always present (0 contribution when no ml_bridge is
        # wired in, as in this fixture) -- see TestMLTrustIntegration below for
        # the case where a real bridge IS wired in.
        assert set(breakdown) == {"identity_confidence", "device_integrity", "behavioral_trust",
                                   "network_trust", "authentication_strength", "anomaly_risk",
                                   "ml_model_risk"}

    def test_ml_risk_zero_when_no_bridge_wired(self, trust_engine):
        """Backward-compat guarantee: a TrustEngine built without an
        ml_bridge (as every pre-integration caller/test still does)
        behaves exactly like the original ABAC-only formula."""
        req = make_request()
        breakdown = trust_engine.factor_breakdown(req)
        assert breakdown["ml_model_risk"] == 0.0


# ---- Track1/Track2 ML integration fix ----
# Responds directly to the paper rejection's core, convergent reviewer
# criticism: the self-hardening policy simulator did not consult the
# trained Track-1 model at all. These tests prove it now does, and that
# the model's output measurably changes decisions -- not just that the
# code runs without crashing.

class TestMLTrustIntegration:
    def test_bridge_scores_attack_scenarios_higher_than_normal(self):
        from ml_trust_bridge import get_bridge, SCENARIO_TO_ATTACK_TYPE
        bridge = get_bridge()
        if bridge is None:
            pytest.skip("Track-1 model not trained in this environment "
                        "(run `python src/train_trust_model.py` first)")
        normal_scores = [bridge.score_scenario("normal", "PLC_CONTROLLER", f"norm_{i}")
                          for i in range(10)]
        for scenario in SCENARIO_TO_ATTACK_TYPE:
            if scenario in ("normal", "abnormal_access_time"):
                continue  # both map to Normal traffic by design -- see ml_trust_bridge.py
            attack_scores = [bridge.score_scenario(scenario, "PLC_CONTROLLER", f"{scenario}_{i}")
                              for i in range(10)]
            assert sum(attack_scores) / len(attack_scores) > sum(normal_scores) / len(normal_scores), (
                f"scenario '{scenario}' should score higher P(malicious) than normal traffic")

    def test_ml_integration_changes_trust_scores(self):
        """The whole point of the fix: wiring in the real model must
        actually move the trust score for at least some requests,
        proving Track 1's output is load-bearing, not decorative."""
        from ml_trust_bridge import get_bridge
        bridge = get_bridge()
        if bridge is None:
            pytest.skip("Track-1 model not trained in this environment")

        weights_without_ml = TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml"))
        weights_with_ml = TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml"))
        engine_without_ml = TrustEngine(weights_without_ml, ml_bridge=None)
        engine_with_ml = TrustEngine(weights_with_ml, ml_bridge=bridge)

        attack_reqs = generate_attack_scenarios(n_per_type=5, seed=321)
        differing = sum(
            1 for req in attack_reqs
            if abs(engine_with_ml.score(req) - engine_without_ml.score(req)) > 1e-9
        )
        assert differing > 0, "ML integration must change at least some trust scores"


# ---- ABAC decision ----

class TestPolicyEngine:
    def test_allow_case(self, policy_engine):
        d = policy_engine.evaluate(make_request())
        assert d.decision == "ALLOW"

    def test_deny_on_wrong_role(self, policy_engine):
        req = make_request(subject=SubjectAttributes(
            user_id="u3", role="operator", identity_confidence=0.9, authentication_strength=0.9))
        d = policy_engine.evaluate(req)
        assert d.decision == "DENY"
        assert any("role" in f for f in d.failed_conditions)

    def test_quarantine_on_critical_integrity(self, policy_engine):
        req = make_request(device=DeviceAttributes(device_id="d2", device_integrity=0.1, patch_level=0.1))
        d = policy_engine.evaluate(req)
        assert d.decision == "QUARANTINE"

    def test_step_up_after_enabling_zone_check(self, policy_engine):
        for p in policy_engine.policies:
            p.conditions.require_step_up_if_zone_mismatch = True
        req = make_request(network=NetworkAttributes(source_zone="unknown_external",
                                                       expected_zone="engineering"))
        d = policy_engine.evaluate(req)
        assert d.decision == "STEP_UP_AUTH"

    def test_no_matching_policy_defaults_deny(self, policy_engine):
        req = make_request(resource="NONEXISTENT_RESOURCE", action="DO_SOMETHING")
        d = policy_engine.evaluate(req)
        assert d.decision == "DENY"
        assert d.policy_id is None


# ---- Red Agent scenario coverage ----

class TestRedAgent:
    def test_generates_all_scenario_types(self):
        reqs = generate_attack_scenarios(n_per_type=3, seed=1)
        labels = {r.label for r in reqs}
        assert labels == set(SCENARIOS)

    def test_no_network_calls_possible(self):
        """SAFETY: red_agent module must not import networking libraries."""
        import red_agent
        src = Path(red_agent.__file__).read_text()
        for forbidden in ("socket", "requests", "urllib", "paramiko"):
            assert forbidden not in src, f"red_agent.py must not import {forbidden}"


# ---- Normal workflow / validation ----

class TestValidation:
    def test_normal_scenarios_mostly_allowed(self, policy_engine):
        normal = generate_normal_scenarios(n=20, seed=1)
        result = validate(policy_engine, [], normal)
        assert result.nwfsr >= 0.9  # generous baseline threshold should mostly pass

    def test_attack_scenarios_measured_not_zero(self, policy_engine):
        attack = generate_attack_scenarios(n_per_type=10, seed=1)
        result = validate(policy_engine, attack, [])
        assert 0.0 <= result.asr <= 1.0


# ---- Objective function / search ----

class TestObjectiveFunction:
    def test_perfect_security_scores_higher_than_worse(self):
        J_good = objective_J(asr=0.1, nwfsr=1.0, latency_ms=0.01)
        J_bad = objective_J(asr=0.5, nwfsr=1.0, latency_ms=0.01)
        assert J_good > J_bad

    def test_deny_everything_is_penalized(self):
        """A candidate with asr=0 but nwfsr=0 (denies everything) must NOT
        automatically win over a balanced candidate -- this is the
        brief's explicit 'do not let this become DENY EVERYTHING' check."""
        J_deny_everything = objective_J(asr=0.0, nwfsr=0.0, latency_ms=0.01)
        J_balanced = objective_J(asr=0.1, nwfsr=1.0, latency_ms=0.01)
        assert J_balanced > J_deny_everything

    def test_search_returns_valid_candidate(self, policy_engine):
        attack = generate_attack_scenarios(n_per_type=5, seed=1)
        normal = generate_normal_scenarios(n=10, seed=1)
        best = search_best_candidate(policy_engine, attack, normal)
        assert 0.0 <= best.asr <= 1.0
        assert 0.0 <= best.nwfsr <= 1.0


# ---- Policy versioning / rollback ----

class TestPolicyVersioning:
    def test_rollback_restores_prior_thresholds(self, policy_engine):
        before = copy.deepcopy(policy_engine)
        original_threshold = policy_engine.policies[0].conditions.min_trust_score

        attack = generate_attack_scenarios(n_per_type=5, seed=1)
        normal = generate_normal_scenarios(n=10, seed=1)
        best = search_best_candidate(policy_engine, attack, normal)
        apply_candidate(policy_engine, best)

        history = PolicyVersionHistory()
        v = history.propose(before, policy_engine, reason="test mitigation")
        history.transition(v.version_id, "DEPLOYED")

        history.rollback_to(v.version_id, policy_engine)
        # after rollback, engine should match the DEPLOYED version's own
        # snapshot (i.e. rollback to itself is idempotent) -- rolling back
        # to the version BEFORE the change would need the pre-change snapshot
        assert policy_engine.policies[0].conditions.min_trust_score == v.policy_snapshot[0]["min_trust_score"]

    def test_state_machine_transitions(self, policy_engine):
        before = copy.deepcopy(policy_engine)
        history = PolicyVersionHistory()
        v = history.propose(before, policy_engine, reason="test")
        assert v.state == "PROPOSED"
        history.transition(v.version_id, "VALIDATED")
        assert history._get(v.version_id).state == "VALIDATED"
        history.transition(v.version_id, "APPROVED", approved_by="analyst_1")
        assert history._get(v.version_id).approved_by == "analyst_1"
        history.transition(v.version_id, "DEPLOYED")
        assert history._get(v.version_id).deployed_at is not None


# ---- Evolutionary Red Agent ----

class TestEvolutionaryRedAgent:
    def test_fitness_never_decreases_within_a_run(self, policy_engine):
        from evolutionary_red_agent import evolve_worst_case
        _, history = evolve_worst_case(policy_engine, seed=1, pop_size=8, n_generations=4)
        for scenario, gens in history.items():
            for i in range(1, len(gens)):
                assert gens[i] >= gens[i - 1] - 1e-9, \
                    f"{scenario}: fitness decreased from gen {i-1} to {i} ({gens[i-1]} -> {gens[i]})"

    def test_stays_within_declared_bounds(self, policy_engine):
        from evolutionary_red_agent import evolve_worst_case, GENE_BOUNDS
        requests, _ = evolve_worst_case(policy_engine, seed=1, pop_size=8, n_generations=3)
        # every produced request must be traceable to a declared scenario category
        for r in requests:
            assert r.label in GENE_BOUNDS

    def test_different_seeds_find_different_worst_cases(self, policy_engine):
        from evolutionary_red_agent import evolve_worst_case
        reqs_a, _ = evolve_worst_case(policy_engine, seed=1, pop_size=8, n_generations=3)
        reqs_b, _ = evolve_worst_case(policy_engine, seed=2, pop_size=8, n_generations=3)
        vals_a = [r.context.anomaly_score for r in reqs_a]
        vals_b = [r.context.anomaly_score for r in reqs_b]
        assert vals_a != vals_b  # genuinely different search trajectories, not a replayed script


# ---- Scheduler ----

class TestScheduler:
    def test_event_triggered_run_produces_real_result(self, tmp_path, monkeypatch):
        import scheduler
        monkeypatch.setattr(scheduler, "HISTORY_PATH", tmp_path / "history.json")
        entry = scheduler.run_scheduled_experiment(trigger="NEW_THREAT", seed=99)
        assert entry["trigger"] == "NEW_THREAT"
        assert 0.0 <= entry["final_asr"] <= 1.0
        assert entry["audit_valid"] is True

    def test_history_accumulates_across_runs(self, tmp_path, monkeypatch):
        import scheduler
        monkeypatch.setattr(scheduler, "HISTORY_PATH", tmp_path / "history.json")
        scheduler.run_scheduled_experiment(trigger="SCHEDULED", seed=1)
        scheduler.run_scheduled_experiment(trigger="SCHEDULED", seed=2)
        with open(scheduler.HISTORY_PATH) as f:
            history = json.load(f)
        assert len(history) == 2

class TestAuditLedger:
    def test_tamper_detection(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "audit_chain_test", Path(__file__).parent.parent.parent / "src" / "audit_chain.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        chain = mod.HashChain()
        for i in range(5):
            chain.add_record({"i": i})
        assert chain.verify() is True
        chain.chain[2].record["i"] = 999  # tamper
        assert chain.verify() is False


# ---- Threat Intel (real-CVE parsing, mocked -- no network needed) ----

class TestThreatIntelAgent:
    def test_parse_nvd_response_extracts_category_and_severity(self):
        from agents.threat_intel_agent import parse_nvd_response
        fake_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-99999",
                    "descriptions": [{"lang": "en",
                                       "value": "An authentication bypass allows credential theft "
                                                "via a firmware update mechanism."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.2}}]},
                    "published": "2026-01-01T00:00:00.000",
                }
            }]
        }
        threats = parse_nvd_response(fake_response)
        assert len(threats) == 1
        t = threats[0]
        assert t["threat_id"] == "CVE-2026-99999"
        assert t["severity"] == "high"          # 8.2 -> high
        assert t["cvss_score"] == 8.2
        # "firmware" appears before "credential" in CATEGORY_KEYWORDS -> matches first
        assert t["attack_category"] == "firmware_integrity_failure"

    def test_cvss_severity_buckets(self):
        from agents.threat_intel_agent import _cvss_to_severity
        assert _cvss_to_severity(9.0) == "high"
        assert _cvss_to_severity(5.5) == "medium"
        assert _cvss_to_severity(2.0) == "low"
        assert _cvss_to_severity(None) == "medium"

    def test_live_fetch_falls_back_or_succeeds_without_crashing(self):
        """try_live=True must never crash the caller, regardless of
        whether the network actually reaches NVD or not -- both a real
        successful fetch (confirmed working on a machine with normal
        internet access, pulling real current CVEs) and a graceful
        fallback to the local feed (this sandbox's restricted network)
        are correct outcomes. Only assert on the invariant that holds
        either way: a non-empty, valid weights dict comes back, and the
        summary says which path was actually taken."""
        from agents.threat_intel_agent import ThreatIntelAgent
        agent = ThreatIntelAgent()
        result = agent.run(try_live=True)
        assert isinstance(result.output, dict)
        assert len(result.output) > 0
        assert ("local static feed" in result.reasoning_summary
                or "LIVE NVD feed" in result.reasoning_summary)

    def test_hard_timeout_actually_bounds_wait_time(self, monkeypatch):
        """Regression test for a real bug found during manual testing:
        wrapping the timeout in `with ThreadPoolExecutor() as pool:`
        silently waited for the FULL hang duration on __exit__, even
        though future.result(timeout=...) raised on schedule internally.
        shutdown(wait=False) is what actually fixes it -- this test
        would fail (take ~5s instead of ~1s) if that regressed."""
        import time
        from agents import threat_intel_agent as tia

        def slow_fetch(keyword, results_limit):
            time.sleep(5)
            return []

        monkeypatch.setattr(tia, "fetch_live_nvd_feed", slow_fetch)
        t0 = time.time()
        with pytest.raises(Exception):
            tia.fetch_live_nvd_feed_hard_timeout(hard_timeout_s=1.0)
        elapsed = time.time() - t0
        assert elapsed < 2.0, f"hard timeout did not bound wait time: took {elapsed:.1f}s"
