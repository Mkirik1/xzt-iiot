"""
scheduler.py
--------------
Brief Section 14: scheduled AND event-triggered self-hardening, not
hardcoded to "once per day" -- configurable via cron-style expression
in config/schedule.yaml. Also supports manual trigger via the API
(POST /experiments/run already does this on demand).

Runs the EVOLUTIONARY hardening experiment (fresh worst-case search
each run, not the same static scenarios) automatically, without any
human clicking a button, and appends each run's result to a running
history file -- so over days/weeks you get a real trend line, not
just a single snapshot.

Run standalone:  python scheduler.py
Or import start_scheduler() into api/app.py to run inside the FastAPI
process (see the integration note at the bottom of this file).
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

sys.path.insert(0, str(Path(__file__).parent))
from agents.coordinator_agent import CoordinatorAgent  # noqa: E402

BASE = Path(__file__).parent
CONFIG_PATH = BASE / "config" / "schedule.yaml"
HISTORY_PATH = BASE / "results" / "scheduled_run_history.json"


def _default_config():
    return {
        "adaptive_testing": {"enabled": True, "schedule_cron": "0 2 * * *"},  # 02:00 every day, brief's own example
        "triggers": ["NEW_THREAT", "POLICY_CHANGE", "SCHEDULED"],
    }


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    cfg = _default_config()
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f)
    return cfg


def run_scheduled_experiment(trigger: str = "SCHEDULED", seed: int = None, try_live: bool = False):
    """One scheduled/triggered run: fresh evolutionary search, appended
    to the running history so trends over time are visible."""
    seed = seed if seed is not None else int(time.time()) % 100000
    coord = CoordinatorAgent()
    result = coord.run_experiment(seed=seed, use_evolutionary_red=True,
                                   try_live_threat_intel=try_live, verbose=False)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trigger": trigger,
        "seed": seed,
        "threat_intel_source": result.output.get("threat_intel_source", "unknown"),
        "final_asr": result.output["cycle_results"][-1]["asr"],
        "final_nwfsr": result.output["cycle_results"][-1]["nwfsr"],
        "cycle_results": [{"cycle": r["cycle"], "asr": r["asr"], "nwfsr": r["nwfsr"]}
                           for r in result.output["cycle_results"]],
        "audit_valid": result.output["audit_valid"],
    }

    HISTORY_PATH.parent.mkdir(exist_ok=True)
    history = []
    if HISTORY_PATH.exists():
        with open(HISTORY_PATH) as f:
            history = json.load(f)
    history.append(entry)
    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2)

    print(f"[{entry['timestamp']}] Scheduled run (trigger={trigger}, seed={seed}): "
          f"final ASR={entry['final_asr']:.3f}, audit_valid={entry['audit_valid']}")
    return entry


def start_scheduler() -> BackgroundScheduler:
    """Starts a background scheduler that runs the hardening experiment
    on the configured cron schedule. Call this once when your process
    starts (e.g. from api/app.py's startup event) -- it returns the
    live scheduler object so you can also trigger event-based runs
    (on_new_threat(), on_policy_change()) from elsewhere in the app."""
    cfg = load_config()
    scheduler = BackgroundScheduler()
    if cfg["adaptive_testing"]["enabled"]:
        scheduler.add_job(run_scheduled_experiment, CronTrigger.from_crontab(
            cfg["adaptive_testing"]["schedule_cron"]), kwargs={"trigger": "SCHEDULED"})
        scheduler.start()
        print(f"Scheduler started: cron='{cfg['adaptive_testing']['schedule_cron']}'")
    return scheduler


# ---- event triggers (brief Section 14: NEW_THREAT / POLICY_CHANGE / etc.) ----

def on_new_threat():
    """Call this whenever config/threat_feed.json is updated with a new
    entry -- triggers an immediate re-run instead of waiting for the
    schedule."""
    return run_scheduled_experiment(trigger="NEW_THREAT")


def on_policy_change():
    return run_scheduled_experiment(trigger="POLICY_CHANGE")


if __name__ == "__main__":
    # Standalone demo: run once immediately (event-triggered demo), then
    # start the real cron scheduler and keep the process alive.
    print("Running one immediate demo cycle (trigger=SCHEDULED, manual start)...")
    run_scheduled_experiment(trigger="SCHEDULED")

    sched = start_scheduler()
    print("Scheduler running in background. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        sched.shutdown()
        print("Scheduler stopped.")
