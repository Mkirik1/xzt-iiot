"""
threat_intel_agent.py
------------------------
v2: can pull REAL, current threat data from the National Vulnerability
Database (NVD) -- the US government's public, official CVE database
(https://nvd.nist.gov). This is a read-only, published safety-advisory
feed -- the same kind of source security teams use for threat
prioritization every day, not an offensive tool.

SAFETY BOUNDARY (unchanged from v1, just spelled out for the real-data
path too): we NEVER extract or store exploit code, proof-of-concept
payloads, or technical exploitation steps from a CVE. We extract only:
  (a) the CVE's severity score (CVSS, a public numeric rating)
  (b) a coarse CATEGORY label, via simple keyword matching on the
      public description text, into our own pre-existing abstract
      scenario categories (stolen_credentials, firmware_integrity_failure,
      etc.) -- the same categories the Red Agent already safely
      simulates. A real CVE never produces new attack code; it only
      re-weights which of our EXISTING safe abstract tests run more.

NOTE ON TESTING: this sandbox's network access is restricted to package
registries (pypi, npm, github, ...) and does NOT include nvd.nist.gov,
so the live fetch path below could not be tested end-to-end from here.
The parsing/categorization logic IS tested (see
tests/test_xzt_iiot.py::TestThreatIntelAgent, which mocks the HTTP
response). On your own machine, with normal internet access, the live
path should work -- but treat that as untested-by-me until you confirm
it yourself; if it errors, the code degrades gracefully to the local
static feed rather than crashing (see fetch_live=False fallback below).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402

SEVERITY_WEIGHT = {"high": 1.5, "medium": 1.0, "low": 0.5}
DEFAULT_FEED = Path(__file__).parent.parent / "config" / "threat_feed.json"
CACHE_PATH = Path(__file__).parent.parent / "results" / "live_threat_cache.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CONNECT_TIMEOUT_S = 3
NVD_READ_TIMEOUT_S = 5

# Keyword -> our existing abstract scenario category. Matched against
# the CVE's public description text (case-insensitive substring match).
# Order matters: first match wins, most-specific keywords listed first.
CATEGORY_KEYWORDS = [
    ("firmware", "firmware_integrity_failure"),
    ("integrity", "firmware_integrity_failure"),
    ("privilege escalation", "privilege_escalation_attempt"),
    ("elevation of privilege", "privilege_escalation_attempt"),
    ("replay", "replay_simulation"),
    ("session", "replay_simulation"),
    ("authentication bypass", "stolen_credentials"),
    ("credential", "stolen_credentials"),
    ("password", "stolen_credentials"),
    ("segmentation", "network_zone_mismatch"),
    ("network access control", "network_zone_mismatch"),
    ("anomal", "behavioral_anomaly"),
    ("behavior", "behavioral_anomaly"),
]


def _cvss_to_severity(score) -> str:
    if score is None:
        return "medium"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _categorize(description: str) -> str:
    text = description.lower()
    for keyword, category in CATEGORY_KEYWORDS:
        if keyword in text:
            return category
    return "behavioral_anomaly"  # safe default bucket for uncategorized threats


def parse_nvd_response(data: dict) -> list:
    """Pure parsing function (no network) -- takes an NVD API JSON
    response and returns our internal threat-record format. Separated
    out so it can be unit-tested with a mocked/sample response without
    needing real network access."""
    threats = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"].get("baseScore")
                break

        threats.append({
            "threat_id": cve_id,
            "title": desc_text[:200],
            "attack_category": _categorize(desc_text),
            "severity": _cvss_to_severity(score),
            "cvss_score": score,
            "source": "NVD_live",
            "published_date": cve.get("published", ""),
        })
    return threats


def fetch_live_nvd_feed(keyword: str = "industrial control system", results_limit: int = 10) -> list:
    """Real network call to the public NVD API. Raises on failure --
    caller decides whether to fall back. NOT tested end-to-end from
    this sandbox (see module docstring); parsing logic (parse_nvd_response)
    IS unit-tested against a mocked response."""
    import requests
    resp = requests.get(NVD_API_URL, params={
        "keywordSearch": keyword, "resultsPerPage": results_limit,
    }, timeout=(NVD_CONNECT_TIMEOUT_S, NVD_READ_TIMEOUT_S))
    resp.raise_for_status()
    return parse_nvd_response(resp.json())


def fetch_live_nvd_feed_hard_timeout(keyword: str = "industrial control system",
                                      results_limit: int = 10, hard_timeout_s: float = 10.0) -> list:
    """Wraps fetch_live_nvd_feed in a real, unconditional timeout using a
    worker thread -- requests' own timeout parameter does NOT reliably
    cover DNS resolution on every platform/network configuration (a
    known gap: on some Windows + corporate/campus network + firewall
    combinations, a blackholed connection can hang past the configured
    socket timeout).

    IMPORTANT implementation detail: do NOT use
    `with ThreadPoolExecutor() as pool:` here -- its __exit__ calls
    shutdown(wait=True), which blocks until the background thread
    finishes REGARDLESS of whether future.result() already timed out.
    That defeats the entire point of a hard timeout (confirmed by
    testing: a call that hangs for 999s made the wrapping `with` block
    hang for the full 999s even though future.result(timeout=3) raised
    on schedule internally). shutdown(wait=False) below is what
    actually lets this function return promptly."""
    import concurrent.futures
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(fetch_live_nvd_feed, keyword, results_limit)
    try:
        return future.result(timeout=hard_timeout_s)
    finally:
        pool.shutdown(wait=False)  # abandon the thread, do not block on it


class ThreatIntelAgent(BaseAgent):
    agent_id = "threat_intel_agent"
    name = "Threat Intelligence Agent"

    def __init__(self, feed_path: Path = DEFAULT_FEED):
        super().__init__()
        self.feed_path = feed_path

    def _load_local_feed(self) -> list:
        with open(self.feed_path) as f:
            return json.load(f)["threats"]

    def run(self, try_live: bool = False) -> AgentResult:
        self.status = "running"
        source_note = "local static feed"
        threats = None

        if try_live:
            try:
                threats = fetch_live_nvd_feed_hard_timeout(hard_timeout_s=10.0)
                source_note = f"LIVE NVD feed ({len(threats)} real current CVEs)"
                CACHE_PATH.parent.mkdir(exist_ok=True)
                with open(CACHE_PATH, "w") as f:
                    json.dump(threats, f, indent=2)
            except Exception as e:
                # graceful degradation -- never crash or hang the hardening
                # loop because the network was unavailable/slow/blackholed
                source_note = f"local static feed (live NVD fetch failed: {e})"
                threats = None

        if threats is None:
            threats = self._load_local_feed()

        weights = {}
        for threat in threats:
            cat = threat["attack_category"]
            w = SEVERITY_WEIGHT.get(threat["severity"], 1.0)
            weights[cat] = max(weights.get(cat, 0.0), w)

        summary = "; ".join(f"{t['attack_category']} (severity={t['severity']}, {t['threat_id']})"
                             for t in threats[:8])
        return self._result(
            output=weights, confidence=1.0,
            reasoning_summary=f"Loaded {len(threats)} threat records from {source_note}: {summary}")
