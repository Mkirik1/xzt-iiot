"""
app.py -- XZT-IIoT REST API
------------------------------
Real FastAPI backend over the existing 8-agent architecture, with
SQLite persistence for the audit ledger (brief Section 17/18/38).

Run:  cd self_hardening && uvicorn api.app:app --reload --port 8000
Then open http://127.0.0.1:8000/ for the dashboard, or
http://127.0.0.1:8000/docs for interactive API docs (auto-generated
by FastAPI from this file -- try requests directly from the browser).

No Docker/Postgres/MQTT here (verified unavailable in the dev
sandbox) -- SQLite + in-process agents, which is the maximum that's
honestly achievable and testable in this environment.
"""

import json
import sqlite3
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.coordinator_agent import CoordinatorAgent  # noqa: E402
from attributes import (AccessRequest, SubjectAttributes, DeviceAttributes,  # noqa: E402
                         NetworkAttributes, ContextAttributes)
from device_simulator import build_fleet, simulate_fleet_telemetry  # noqa: E402
from policy_engine import PolicyEngine  # noqa: E402
from trust_engine import TrustEngine, TrustWeights  # noqa: E402

BASE = Path(__file__).parent.parent
CONFIG = BASE / "config"
DB_PATH = BASE / "results" / "xzt_iiot.db"

app = FastAPI(title="XZT-IIoT API", version="1.0",
              description="Explainable Zero-Trust Access Control API for Industrial IoT")

# ---- global (demo-scope) state: one shared engine + one device fleet ----
_trust_engine = TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")))
_policy_engine = PolicyEngine(str(CONFIG / "policies.yaml"), _trust_engine)
_fleet = build_fleet(n_devices=15, seed=1)


def _db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS access_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, subject_id TEXT,
        device_id TEXT, resource TEXT, action TEXT, decision TEXT,
        trust_score REAL, policy_id TEXT, explanation TEXT, ts REAL)""")
    return conn


@app.on_event("startup")
def _init_db():
    _db().close()
    try:
        from scheduler import start_scheduler
        app.state.scheduler = start_scheduler()
    except Exception as e:
        print(f"Scheduler failed to start (non-fatal, manual /experiments/run still works): {e}")


# ---------------- Pydantic request/response models ----------------

class AuthRequestIn(BaseModel):
    subject_id: str
    role: str
    device_id: str
    resource: str
    action: str
    network_zone: str
    identity_confidence: float = 0.9
    authentication_strength: float = 0.9
    device_integrity: float = 0.9
    behavioral_trust: float = 0.9
    anomaly_score: float = 0.1
    access_hour: int = 12


class AuthDecisionOut(BaseModel):
    request_id: str
    decision: str
    trust_score: float
    policy_id: Optional[str]
    explanation: str
    failed_conditions: list


# ---------------- Endpoints (brief Section 38) ----------------

@app.post("/auth/request", response_model=AuthDecisionOut)
def auth_request(body: AuthRequestIn):
    req = AccessRequest(
        request_id=f"api_{body.subject_id}_{body.resource}",
        subject=SubjectAttributes(user_id=body.subject_id, role=body.role,
                                   identity_confidence=body.identity_confidence,
                                   authentication_strength=body.authentication_strength),
        device=DeviceAttributes(device_id=body.device_id, device_integrity=body.device_integrity,
                                 patch_level=0.9),
        network=NetworkAttributes(source_zone=body.network_zone, expected_zone=body.network_zone),
        context=ContextAttributes(behavioral_trust=body.behavioral_trust,
                                   anomaly_score=body.anomaly_score, access_hour=body.access_hour),
        resource=body.resource, action=body.action,
    )
    decision = _policy_engine.evaluate(req)

    conn = _db()
    conn.execute("INSERT INTO access_decisions (request_id, subject_id, device_id, resource, "
                 "action, decision, trust_score, policy_id, explanation, ts) "
                 "VALUES (?,?,?,?,?,?,?,?,?, strftime('%s','now'))",
                 (decision.request_id, body.subject_id, body.device_id, body.resource, body.action,
                  decision.decision, decision.trust_score, decision.policy_id, decision.explanation))
    conn.commit()
    conn.close()

    return AuthDecisionOut(request_id=decision.request_id, decision=decision.decision,
                            trust_score=decision.trust_score, policy_id=decision.policy_id,
                            explanation=decision.explanation, failed_conditions=decision.failed_conditions)


@app.get("/auth/decisions")
def auth_decisions(limit: int = 50):
    conn = _db()
    rows = conn.execute("SELECT request_id, subject_id, device_id, resource, action, decision, "
                         "trust_score, policy_id, explanation, ts FROM access_decisions "
                         "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    cols = ["request_id", "subject_id", "device_id", "resource", "action", "decision",
            "trust_score", "policy_id", "explanation", "ts"]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/policies")
def get_policies():
    return [{
        "policy_id": p.policy_id, "resource": p.resource, "action": p.action,
        "min_trust_score": p.conditions.min_trust_score,
        "min_device_integrity": p.conditions.min_device_integrity,
        "max_anomaly_score": p.conditions.max_anomaly_score,
        "allowed_roles": p.conditions.allowed_roles,
        "require_step_up_if_zone_mismatch": p.conditions.require_step_up_if_zone_mismatch,
    } for p in _policy_engine.policies]


@app.get("/devices")
def get_devices():
    from dataclasses import asdict
    return [asdict(d) for d in _fleet]


@app.get("/devices/telemetry")
def get_telemetry(rounds: int = 1):
    return simulate_fleet_telemetry(_fleet, n_rounds=rounds)


@app.post("/experiments/run")
def run_experiment(seed: int = 42, n_cycles: int = 5, evolutionary: bool = False):
    coord = CoordinatorAgent()
    result = coord.run_experiment(seed=seed, n_cycles=n_cycles, use_evolutionary_red=evolutionary,
                                   verbose=False)
    return {
        "cycle_results": [
            {"cycle": r["cycle"], "asr": r["asr"], "nwfsr": r["nwfsr"]}
            for r in result.output["cycle_results"]
        ],
        "audit_valid": result.output["audit_valid"],
        "audit_blocks": result.output["audit_blocks"],
        "summary": result.reasoning_summary,
    }


@app.get("/experiments/history")
def experiment_history(limit: int = 30):
    """History of all scheduled/event-triggered runs (see scheduler.py) --
    this is what makes the ASR trend visible over days/weeks rather than
    a single button-press snapshot."""
    from scheduler import HISTORY_PATH
    if not HISTORY_PATH.exists():
        return []
    with open(HISTORY_PATH) as f:
        history = json.load(f)
    return history[-limit:]


@app.post("/experiments/trigger")
def trigger_event(reason: str = "NEW_THREAT", try_live: bool = True):
    """Manually fire an event-triggered run (brief Section 14: NEW_THREAT /
    POLICY_CHANGE / etc.), same mechanism the scheduler uses automatically.
    try_live=True attempts to pull real current CVE data from NVD first,
    falling back to the local threat feed if unreachable."""
    from scheduler import run_scheduled_experiment
    entry = run_scheduled_experiment(trigger=reason, try_live=try_live)
    return entry


@app.get("/audit/verify")
def audit_verify():
    conn = _db()
    n = conn.execute("SELECT COUNT(*) FROM access_decisions").fetchone()[0]
    conn.close()
    # the live /auth/request log above is a simple SQLite append log
    # (verified by DB constraints, not a hash chain); the cryptographic
    # hash-chain integrity proof lives in the agent-driven experiment
    # runs (self_hardening/results/hardening_audit_chain_seed*.json) --
    # exposed here for convenience rather than duplicating a second chain.
    return {"live_decision_log_entries": n,
            "note": "Cryptographic hash-chain verification is performed per-experiment-run; "
                    "see /experiments/run output (audit_valid field) for a live example."}


@app.get("/metrics")
def get_metrics():
    from metrics import measure_latency_and_throughput
    from red_agent import generate_attack_scenarios
    from normal_scenarios import generate_normal_scenarios
    reqs = generate_attack_scenarios(n_per_type=20, seed=1) + generate_normal_scenarios(n=20, seed=2)
    return measure_latency_and_throughput(_policy_engine, reqs)


# ---------------- Dashboard (static files) ----------------

_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/")
def dashboard():
    return FileResponse(str(_static_dir / "index.html"))
