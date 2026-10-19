"""Decision logic of the lab gateway, tested without a broker or hardware.
Run from the repo root:  python -m pytest hardware/gateway -q"""

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from gateway import Gateway  # noqa: E402

FW = "a" * 32
OTHER_FW = "b" * 32
NOON = 1_700_000_000.0


@pytest.fixture
def gw(tmp_path):
    reg = tmp_path / "devices.yaml"
    shutil.copy(Path(__file__).parent / "devices.yaml", reg)
    g = Gateway(reg, audit_path=tmp_path / "audit.json", demo_hour=12,
                enrolled_path=tmp_path / "enrolled_firmware.yaml")
    g.registry["esp32_sensor"]["fw_md5"] = [FW]
    return g


def req(token="lab-sensor-token-change-me", fw=FW):
    return {"resource": "PUMP_CONTROLLER", "token": token, "fw_md5": fw, "state": "on"}


def ask(gw, device="esp32_sensor", msg=None, now=NOON):
    gw.note_message(device, now)
    return gw.decide(device, msg or req(), now)


def test_legitimate_request_is_allowed(gw):
    assert ask(gw)["decision"] == "ALLOW"


def test_wrong_token_is_denied(gw):
    out = ask(gw, msg=req(token="guess"))
    assert out["decision"] in ("DENY", "QUARANTINE") and out["checks"]["token_ok"] is False


def test_stolen_token_on_other_firmware_is_quarantined(gw):
    out = ask(gw, msg=req(fw=OTHER_FW))
    assert out["decision"] == "QUARANTINE" and out["checks"]["fw_ok"] is False


def test_quarantine_is_sticky(gw):
    assert ask(gw, msg=req(fw=OTHER_FW))["decision"] == "QUARANTINE"
    later = ask(gw, now=NOON + 30)                     # now with the right firmware
    assert later["decision"] == "QUARANTINE" and "quarantine" in later["why"]


def test_flood_is_denied(gw):
    for i in range(100):
        gw.note_message("esp32_sensor", NOON + i * 0.05)
    out = gw.decide("esp32_sensor", req(), NOON + 5)
    assert out["decision"] == "DENY" and "anomaly" in out["why"]


def test_unregistered_device_is_denied(gw):
    assert ask(gw, device="esp32_attacker", msg=req(token="x"))["decision"] != "ALLOW"


def test_night_request_lowers_trust(gw):
    day = ask(gw)["trust"]
    gw.demo_hour = 3
    assert ask(gw, now=NOON + 60)["trust"] < day


def test_enroll_records_firmware_only_with_valid_token(gw):
    gw.enroll = True
    gw.registry["esp32_sensor"]["fw_md5"] = []
    ask(gw, msg=req(token="guess", fw=OTHER_FW))
    assert gw.registry["esp32_sensor"]["fw_md5"] == []
    before = gw.registry_path.read_text()
    ask(gw, msg=req(fw=OTHER_FW))
    assert gw.registry["esp32_sensor"]["fw_md5"] == [OTHER_FW]
    assert gw.registry_path.read_text() == before          # registry and its comments untouched
    reloaded = Gateway(gw.registry_path, audit_path=gw.audit_path, enrolled_path=gw.enrolled_path)
    assert reloaded.registry["esp32_sensor"]["fw_md5"] == [OTHER_FW]


def test_every_decision_is_in_a_valid_audit_chain(gw):
    for _ in range(3):
        ask(gw)
    assert len(gw.chain.chain) == 4 and gw.chain.verify()   # genesis + 3
