"""
gateway.py -- XZT-IIoT Zero-Trust gateway for the physical testbed.

Runs on the laptop (later the Raspberry Pi). Every ESP32 talks ONLY to
the MQTT broker; the pump node obeys commands ONLY from this gateway.
For each request a device sends, the gateway builds an AccessRequest
from MEASURED attributes and asks the project's real PolicyEngine /
TrustEngine (self_hardening/) for ALLOW / STEP_UP_AUTH / DENY /
QUARANTINE, publishes the decision with its explanation, forwards the
command to the pump only on ALLOW, and appends every decision to the
same SHA-256 hash-chained audit log the rest of the project uses.

Where each attribute comes from (all measured here, none simulated):
  identity_confidence,   token check against devices.yaml
  authentication_strength
  device_integrity       firmware MD5 the device reports vs the enrolled
                         whitelist (mismatch -> 0.2 -> QUARANTINE)
  role, zone             device registry (devices.yaml)
  anomaly_score,         message rate over the last 10 s vs the device's
  behavioral_trust       baseline, plus a penalty outside working hours
  access_hour            the gateway's own clock (--demo-hour overrides
                         it, to demonstrate night-time requests)
  ml_risk                NOT USED in this version: live traffic capture
                         (tshark -> Edge-IIoTset fields -> XGBoost) is the
                         next step. The trust engine runs ABAC-only here.

LIMITATION (say it at the defense): the firmware hash is self-reported
by the device. A device running honest firmware cannot fake it, but an
attacker who writes their own firmware can send any string. Real
attestation needs secure boot or a signed challenge-response.

MQTT topics
  xzt/req/<device_id>       device -> gateway  request JSON
  xzt/tel/<device_id>       device -> gateway  telemetry JSON
  xzt/decision/<device_id>  gateway -> all     decision JSON
  xzt/cmd/pump              gateway -> pump    {"state": "on"|"off"|"toggle"}

Usage
  python gateway.py --broker 127.0.0.1            normal run
  python gateway.py --broker 127.0.0.1 --enroll   record firmware hashes
  python gateway.py --broker 127.0.0.1 --demo-hour 3   pretend it is 03:00
  python gateway.py --broker 127.0.0.1 --user xzt-gateway --password ...   with ACLs
"""

import argparse
import importlib.util
import json
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

import yaml

HERE = Path(__file__).parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "self_hardening"))

from attributes import (AccessRequest, ContextAttributes, DeviceAttributes,  # noqa: E402
                        NetworkAttributes, SubjectAttributes)
from policy_engine import PolicyEngine  # noqa: E402
from trust_engine import TrustEngine, TrustWeights  # noqa: E402

_spec = importlib.util.spec_from_file_location("audit_chain_hw", REPO / "src" / "audit_chain.py")
_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_audit)

CONFIG = REPO / "self_hardening" / "config"
RATE_WINDOW_S = 10.0
OFF_HOURS_PENALTY = 0.4
KNOWN_RESOURCES = {"PUMP_CONTROLLER": "START_STOP"}


class Gateway:
    def __init__(self, registry_path: Path, enroll: bool = False, demo_hour=None,
                 audit_path: Path = HERE / "audit_chain.json",
                 enrolled_path: Path = None):
        self.registry_path = registry_path
        self.registry = yaml.safe_load(registry_path.read_text())["devices"]
        # Enrolled firmware hashes live in their own file, so enrolling never
        # rewrites (and strips the comments from) the hand-edited registry.
        self.enrolled_path = enrolled_path or registry_path.with_name("enrolled_firmware.yaml")
        if self.enrolled_path.exists():
            enrolled = yaml.safe_load(self.enrolled_path.read_text()) or {}
            for dev, hashes in enrolled.items():
                if dev in self.registry:
                    self.registry[dev]["fw_md5"] = sorted(set(self.registry[dev]["fw_md5"]) | set(hashes))
        self.enroll = enroll
        self.demo_hour = demo_hour
        self.trust = TrustEngine(TrustWeights.from_yaml(str(CONFIG / "trust_weights.yaml")), ml_bridge=None)
        self.policy = PolicyEngine(str(CONFIG / "policies.yaml"), self.trust)
        self.seen = defaultdict(deque)          # device_id -> message timestamps
        self.chain = _audit.HashChain()
        self.audit_path = audit_path
        # QUARANTINE is sticky: a device that failed the integrity check stays
        # blocked until an operator restarts the gateway, instead of being
        # re-evaluated (and possibly allowed) on its very next request.
        self.quarantined = set()

    # ---- attribute measurement ------------------------------------------------
    def note_message(self, device_id: str, now: float):
        q = self.seen[device_id]
        q.append(now)
        while q and q[0] < now - RATE_WINDOW_S:
            q.popleft()

    def rate(self, device_id: str) -> float:
        return len(self.seen[device_id]) / RATE_WINDOW_S

    def hour(self, now: float) -> int:
        return self.demo_hour if self.demo_hour is not None else time.localtime(now).tm_hour

    def build_request(self, device_id: str, msg: dict, now: float) -> AccessRequest:
        reg = self.registry.get(device_id)
        token_ok = reg is not None and msg.get("token") == reg["token"]
        fw = str(msg.get("fw_md5", ""))
        if reg is not None and self.enroll and token_ok and fw and fw not in reg["fw_md5"]:
            reg["fw_md5"].append(fw)
            self.enrolled_path.write_text(yaml.safe_dump(
                {d: r["fw_md5"] for d, r in self.registry.items() if r["fw_md5"]}, sort_keys=True))
            print(f"[enroll] {device_id}: recorded firmware {fw} -> {self.enrolled_path.name}")
        fw_ok = reg is not None and fw in reg["fw_md5"]

        baseline = reg["baseline_rate"] if reg else 0.5
        ratio = self.rate(device_id) / baseline if baseline > 0 else 10.0
        anomaly = min(1.0, max(0.0, (ratio - 1.0) / 4.0))
        hour = self.hour(now)
        start, end = (reg["work_hours"] if reg else (8, 20))
        if not (start <= hour < end):
            anomaly = min(1.0, anomaly + OFF_HOURS_PENALTY)

        resource = msg.get("resource", "")
        return AccessRequest(
            request_id=f"{device_id}-{int(now * 1000)}",
            subject=SubjectAttributes(user_id=device_id,
                                      role=reg["role"] if reg else "unknown",
                                      identity_confidence=0.95 if token_ok else 0.05,
                                      authentication_strength=0.9 if token_ok else 0.05),
            device=DeviceAttributes(device_id=device_id, device_integrity=0.95 if fw_ok else 0.2,
                                    patch_level=0.9 if fw_ok else 0.2),
            network=NetworkAttributes(source_zone=reg["zone"] if reg else "unknown_external",
                                      expected_zone=reg["zone"] if reg else "unregistered"),
            context=ContextAttributes(behavioral_trust=1.0 - anomaly, anomaly_score=anomaly,
                                      access_hour=hour),
            resource=resource, action=KNOWN_RESOURCES.get(resource, msg.get("action", "")),
            label="live",
            metadata={"token_ok": token_ok, "fw_ok": fw_ok, "rate": round(self.rate(device_id), 2)},
        )

    # ---- decision -------------------------------------------------------------
    def decide(self, device_id: str, msg: dict, now: float) -> dict:
        req = self.build_request(device_id, msg, now)
        top = sorted(self.trust.factor_breakdown(req).items(), key=lambda kv: -abs(kv[1]))[:3]
        if device_id in self.quarantined:
            decision, trust, why = ("QUARANTINE", 0.0,
                                    "Device is in quarantine after a failed integrity check; "
                                    "an operator must release it (restart the gateway).")
        elif not req.metadata["token_ok"]:
            # Authenticate first, then authorize. In the weighted trust score a
            # failed token only lowers trust to ~0.56, which still clears the
            # pump policy's 0.55 threshold when every other attribute is clean
            # (found by test_wrong_token_is_denied). An unauthenticated request
            # must never reach the trust calculation, so it is denied here.
            decision, trust, why = ("DENY", self.trust.score(req),
                                    "Authentication failed: unknown device or wrong token.")
        else:
            dec = self.policy.evaluate(req)
            decision, trust, why = dec.decision, dec.trust_score, dec.explanation
            if decision == "QUARANTINE":
                self.quarantined.add(device_id)
        out = {
            "device": device_id, "decision": decision, "trust": round(trust, 3),
            "why": why[:180],
            "checks": req.metadata,
            "top_factors": {k: round(v, 3) for k, v in top},
            "state": msg.get("state", "toggle"),
            "ts": round(now, 3),
        }
        self.chain.add_record(out)
        if len(self.chain.chain) % 10 == 0:
            self.chain.save(str(self.audit_path))
        return out


def main():
    ap = argparse.ArgumentParser(description="XZT-IIoT lab gateway")
    ap.add_argument("--broker", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--enroll", action="store_true", help="record firmware hashes of devices with a valid token")
    ap.add_argument("--demo-hour", type=int, default=None, help="pretend the local hour is this value")
    ap.add_argument("--user", default="", help="MQTT username (with mosquitto-acl.conf: xzt-gateway)")
    ap.add_argument("--password", default="", help="MQTT password")
    args = ap.parse_args()

    import paho.mqtt.client as mqtt
    gw = Gateway(HERE / "devices.yaml", enroll=args.enroll, demo_hour=args.demo_hour)

    def on_connect(client, userdata, flags, reason_code, properties=None):
        print(f"Connected to broker {args.broker}:{args.port} ({reason_code})")
        client.subscribe("xzt/req/+")
        client.subscribe("xzt/tel/+")

    def on_message(client, userdata, m):
        now = time.time()
        kind, device_id = m.topic.split("/")[1], m.topic.split("/")[2]
        gw.note_message(device_id, now)
        if kind != "req":
            return
        try:
            msg = json.loads(m.payload.decode())
        except (ValueError, UnicodeDecodeError):
            msg = {}
        out = gw.decide(device_id, msg, now)
        client.publish(f"xzt/decision/{device_id}", json.dumps(out))
        if out["decision"] == "ALLOW" and msg.get("resource") == "PUMP_CONTROLLER":
            client.publish("xzt/cmd/pump", json.dumps({"state": out["state"]}))
        print(f"{time.strftime('%H:%M:%S')} {device_id:16s} {out['decision']:13s} "
              f"trust={out['trust']:.2f}  {out['checks']}  {out['why'][:70]}")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="xzt-gateway")
    client.on_connect = on_connect
    client.on_message = on_message
    if args.user:
        client.username_pw_set(args.user, args.password)
    client.connect(args.broker, args.port, keepalive=30)
    print("Gateway running. Ctrl+C to stop." + ("  [ENROLL MODE]" if args.enroll else ""))
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        pass
    finally:
        gw.chain.save(str(gw.audit_path))
        print(f"Audit log saved: {gw.audit_path} ({len(gw.chain.chain)} blocks, valid={gw.chain.verify()})")


if __name__ == "__main__":
    main()
