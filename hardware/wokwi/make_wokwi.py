"""
make_wokwi.py -- build three Wokwi simulator projects (sensor, actuator,
attacker) from the ONE real firmware file, so the simulation always runs
exactly the code that goes onto the boards.

    python hardware/wokwi/make_wokwi.py --prefix xzt-kirik-4821

writes hardware/wokwi/{sensor,actuator,attacker}/ with sketch.ino,
diagram.json and libraries.txt. In each: create a new ESP32 project on
wokwi.com, paste sketch.ino and diagram.json over the defaults, add a
libraries.txt tab with the same content. Then run the gateway against
the same public broker and prefix:

    python hardware/gateway/gateway.py --broker broker.hivemq.com --prefix xzt-kirik-4821 --enroll

Only the four settings below differ from the real boards. The public
broker and the Wokwi Wi-Fi are not private: use placeholder tokens only.
"""

import argparse
import json
import re
from pathlib import Path

HERE = Path(__file__).parent
SOURCE = HERE.parent / "firmware" / "xzt_node" / "xzt_node.ino"
PUBLIC_BROKER = "broker.hivemq.com"
LIBRARIES = "PubSubClient\nArduinoJson\nOneWire\nDallasTemperature\n"

ESP = {"type": "board-esp32-devkit-c-v4", "id": "esp", "top": 0, "left": 0, "attrs": {}}


def part(type_, id_, top, left, **attrs):
    return {"type": type_, "id": id_, "top": top, "left": left, "attrs": {k: str(v) for k, v in attrs.items()}}


def wire(a, b, color="green"):
    return [a, b, color, []]


def button(id_, gpio, top, label, color="blue"):
    return ([part("wokwi-pushbutton", id_, top, 200, color=color, label=label, bounce="0")],
            [wire(f"{id_}:1.l", f"esp:{gpio}", "blue"), wire(f"{id_}:2.l", "esp:GND.2", "black")])


def sensor():
    parts = [ESP, part("wokwi-ds18b20", "temp", -120, 160),
             part("wokwi-resistor", "rpull", -40, 150, value=4700)]
    conns = [wire("esp:TX", "$serialMonitor:RX", ""), wire("esp:RX", "$serialMonitor:TX", ""),
             wire("temp:VCC", "esp:3V3", "red"), wire("temp:GND", "esp:GND.1", "black"),
             wire("temp:DQ", "esp:4", "yellow"),
             wire("rpull:1", "esp:4", "yellow"), wire("rpull:2", "esp:3V3", "red")]
    for i, (gpio, label, color) in enumerate([(18, "A pump ON", "green"), (19, "B pump OFF", "red")]):
        p, c = button(f"btn{i}", gpio, 40 + i * 70, label, color)
        parts += p
        conns += c
    return parts, conns


def actuator():
    parts = [ESP, part("wokwi-relay-module", "relay", -110, 180),
             part("wokwi-led", "pump", -150, 380, color="blue", label="PUMP"),
             part("wokwi-resistor", "rpump", -100, 360, value=220),
             part("wokwi-buzzer", "bz", 160, 200, volume="0.2")]
    conns = [wire("esp:TX", "$serialMonitor:RX", ""), wire("esp:RX", "$serialMonitor:TX", ""),
             wire("relay:VCC", "esp:5V", "red"), wire("relay:GND", "esp:GND.1", "black"),
             wire("relay:IN", "esp:23", "orange"),
             # the "pump" is an LED switched by the relay contacts, as the
             # real pump will be (from its own 5 V supply on the bench)
             wire("relay:COM", "esp:3V3", "red"), wire("relay:NO", "rpump:1", "red"),
             wire("rpump:2", "pump:A", "red"), wire("pump:C", "esp:GND.3", "black"),
             wire("bz:2", "esp:14", "purple"), wire("bz:1", "esp:GND.3", "black")]
    for i, (gpio, color) in enumerate([(25, "green"), (26, "yellow"), (27, "red")]):
        parts += [part("wokwi-led", f"led{i}", 20 + i * 45, 260, color=color),
                  part("wokwi-resistor", f"r{i}", 30 + i * 45, 180, value=220)]
        conns += [wire(f"esp:{gpio}", f"r{i}:1", color), wire(f"r{i}:2", f"led{i}:A", color),
                  wire(f"led{i}:C", "esp:GND.2", "black")]
    return parts, conns


def attacker():
    parts, conns = [ESP], [wire("esp:TX", "$serialMonitor:RX", ""), wire("esp:RX", "$serialMonitor:TX", "")]
    labels = ["A wrong token", "B unregistered", "C stolen token", "D bypass gateway", "E spoof + flood"]
    for i, (gpio, label) in enumerate(zip([18, 19, 32, 33, 13], labels)):
        p, c = button(f"btn{i}", gpio, -120 + i * 60, label, "red")
        parts += p
        conns += c
    return parts, conns


ROLES = {"sensor": ("ROLE_SENSOR", sensor), "actuator": ("ROLE_ACTUATOR", actuator),
         "attacker": ("ROLE_ATTACKER", attacker)}


def configure(src: str, role: str, prefix: str) -> str:
    subs = [(r'#define ROLE \w+', f'#define ROLE {role}'),
            (r'const char\* WIFI_SSID   = "[^"]*";', 'const char* WIFI_SSID   = "Wokwi-GUEST";'),
            (r'const char\* WIFI_PASS   = "[^"]*";', 'const char* WIFI_PASS   = "";'),
            (r'const char\* BROKER_IP   = "[^"]*";', f'const char* BROKER_IP   = "{PUBLIC_BROKER}";'),
            (r'const char\* PREFIX      = "[^"]*";', f'const char* PREFIX      = "{prefix}";')]
    for pattern, repl in subs:
        src, n = re.subn(pattern, repl, src, count=1)
        if n != 1:
            raise SystemExit(f"could not set {repl!r}: the firmware's settings block changed")
    return src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", required=True,
                    help="unique topic prefix for the public broker, e.g. xzt-kirik-4821")
    args = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,40}", args.prefix) or args.prefix == "xzt":
        raise SystemExit("choose a unique prefix of 6-40 letters/digits/dashes, not plain 'xzt'")
    src = SOURCE.read_text()
    for name, (role, build) in ROLES.items():
        out = HERE / name
        out.mkdir(exist_ok=True)
        parts, conns = build()
        (out / "sketch.ino").write_text(configure(src, role, args.prefix))
        (out / "diagram.json").write_text(json.dumps(
            {"version": 1, "author": "XZT-IIoT", "editor": "wokwi", "parts": parts,
             "connections": conns, "dependencies": {}}, indent=2))
        (out / "libraries.txt").write_text(LIBRARIES)
        print(f"wrote {out}")
    print(f"\nGateway:  python hardware/gateway/gateway.py --broker {PUBLIC_BROKER} "
          f"--prefix {args.prefix} --enroll")


if __name__ == "__main__":
    main()
