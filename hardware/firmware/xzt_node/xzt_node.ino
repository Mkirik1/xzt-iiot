/*
  xzt_node.ino -- one sketch for all three ESP32 boards of the XZT-IIoT testbed.
  Set ROLE below, fill in Wi-Fi / broker / tokens, upload.

  ROLE_SENSOR    DS18B20 temperature -> telemetry every 2 s.
                 Button A asks the gateway to turn the pump ON, button B OFF.
  ROLE_ACTUATOR  Relay drives the pump. Obeys ONLY <prefix>/cmd/pump (which only
                 the gateway should be allowed to publish; see mosquitto-acl.conf).
                 Green / yellow / red LEDs + buzzer show the gateway's decisions.
  ROLE_ATTACKER  Five buttons, each one test scenario against the gateway.
                 Lab use only, on the isolated testbed network.

  Every request carries ESP.getSketchMD5(): the fingerprint of the firmware
  actually running. Each ROLE compiles to a different binary, so each board
  has its own fingerprint. The gateway enrolls them once (--enroll).

  Libraries (Arduino IDE -> Library Manager): PubSubClient (Nick O'Leary),
  ArduinoJson (v7, Benoit Blanchon), OneWire, DallasTemperature.
  Board: "ESP32 Dev Module" (Espressif ESP32 core).
*/

#define ROLE_SENSOR   1
#define ROLE_ACTUATOR 2
#define ROLE_ATTACKER 3

// ======================= EDIT THESE =======================
#define ROLE ROLE_SENSOR

const char* WIFI_SSID   = "XZT-LAB";            // phone hotspot / lab router
const char* WIFI_PASS   = "change-me";
const char* BROKER_IP   = "192.168.43.100";     // laptop IP on that network (or a host name)
const int   BROKER_PORT = 1883;
// Topic prefix. "xzt" on your own broker. On a PUBLIC broker (Wokwi
// simulation) use something unique, e.g. "xzt-kirik-7341", and pass the
// same value to the gateway with --prefix.
const char* PREFIX      = "xzt";
const char* MQTT_USER   = "";                    // only with mosquitto-acl.conf
const char* MQTT_PASS   = "";

const char* SENSOR_TOKEN = "lab-sensor-token-change-me";   // must match devices.yaml
// Attacker scenario E needs the sensor's real fingerprint: copy it from the
// gateway's "[enroll] esp32_sensor: recorded firmware ..." line.
const char* SENSOR_FW_MD5_COPY = "paste-sensor-md5-here";
// ==========================================================

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

#if ROLE == ROLE_SENSOR
  #include <OneWire.h>
  #include <DallasTemperature.h>
  const char* DEVICE_ID = "esp32_sensor";
  const int PIN_TEMP = 4;       // DS18B20 data, 4.7k pull-up to 3V3
  const int PIN_BTN_A = 18;     // to GND, internal pull-up
  const int PIN_BTN_B = 19;
  OneWire oneWire(PIN_TEMP);
  DallasTemperature temps(&oneWire);
#elif ROLE == ROLE_ACTUATOR
  const char* DEVICE_ID = "esp32_actuator";
  const int PIN_RELAY = 23;
  // Use a relay module whose trigger jumper is set to HIGH (or a 3.3 V
  // module): then HIGH = on and this stays false. Set true only for a
  // low-level-trigger module that switches reliably from 3.3 V.
  const bool RELAY_ACTIVE_LOW = false;
  const int PIN_GREEN = 25, PIN_YELLOW = 26, PIN_RED = 27, PIN_BUZZER = 14;  // LEDs via 220 ohm
  const bool BUZZER_ACTIVE_LOW = false;  // some 3-pin buzzer modules sound on LOW: set true then
#else
  const char* DEVICE_ID = "esp32_attacker";
  const int BTN[5] = {18, 19, 32, 33, 13};   // scenarios A..E, to GND
#endif

const int PIN_ONBOARD_LED = 2;
WiFiClient net;
PubSubClient mqtt(net);
String fwMd5;
bool pumpOn = false;

void blink(int ms) { digitalWrite(PIN_ONBOARD_LED, HIGH); delay(ms); digitalWrite(PIN_ONBOARD_LED, LOW); }

void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.printf(" ok, IP %s\n", WiFi.localIP().toString().c_str());
}

void sendRequest(const char* asDevice, const char* token, const char* fw, const char* state) {
  JsonDocument doc;
  doc["resource"] = "PUMP_CONTROLLER";
  doc["state"] = state;
  doc["token"] = token;
  doc["fw_md5"] = fw;
  char buf[256];
  serializeJson(doc, buf);
  String topic = String(PREFIX) + "/req/" + asDevice;
  mqtt.publish(topic.c_str(), buf);
  Serial.printf("-> %s %s\n", topic.c_str(), buf);
}

#if ROLE == ROLE_ACTUATOR
void setPump(bool on) {
  pumpOn = on;
  digitalWrite(PIN_RELAY, (on ^ RELAY_ACTIVE_LOW) ? HIGH : LOW);
  Serial.printf("PUMP %s\n", on ? "ON" : "OFF");
}

void buzz(bool on) { digitalWrite(PIN_BUZZER, (on ^ BUZZER_ACTIVE_LOW) ? HIGH : LOW); }

void showDecision(const char* d) {
  digitalWrite(PIN_GREEN, LOW); digitalWrite(PIN_YELLOW, LOW); digitalWrite(PIN_RED, LOW);
  if (!strcmp(d, "ALLOW")) digitalWrite(PIN_GREEN, HIGH);
  else if (!strcmp(d, "STEP_UP_AUTH")) digitalWrite(PIN_YELLOW, HIGH);
  else digitalWrite(PIN_RED, HIGH);
  if (!strcmp(d, "QUARANTINE")) {
    for (int i = 0; i < 3; i++) { buzz(true); delay(150); buzz(false); delay(100); }
  }
}
#endif

void onMessage(char* topic, byte* payload, unsigned int len) {
  JsonDocument doc;
  if (deserializeJson(doc, payload, len)) return;
  String t(topic);
#if ROLE == ROLE_ACTUATOR
  if (t == String(PREFIX) + "/cmd/pump") {
    const char* st = doc["state"] | "toggle";
    setPump(!strcmp(st, "on") ? true : !strcmp(st, "off") ? false : !pumpOn);
  } else if (t.startsWith(String(PREFIX) + "/decision/")) {
    showDecision(doc["decision"] | "DENY");
  }
#endif
  Serial.printf("<- %s %s | %s\n", topic, (const char*)(doc["decision"] | ""), (const char*)(doc["why"] | ""));
}

void connectMqtt() {
  while (!mqtt.connected()) {
    Serial.print("MQTT...");
    bool ok = strlen(MQTT_USER) ? mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS) : mqtt.connect(DEVICE_ID);
    if (ok) {
      Serial.println(" ok");
      String p(PREFIX);
#if ROLE == ROLE_ACTUATOR
      mqtt.subscribe((p + "/cmd/pump").c_str());
      mqtt.subscribe((p + "/decision/#").c_str());
#elif ROLE == ROLE_ATTACKER
      mqtt.subscribe((p + "/decision/#").c_str());
#else
      mqtt.subscribe((p + "/decision/" + DEVICE_ID).c_str());
#endif
    } else { Serial.printf(" failed rc=%d, retry\n", mqtt.state()); delay(2000); }
  }
}

bool pressed(int pin) {               // simple debounce, active LOW
  if (digitalRead(pin) == LOW) { delay(30); if (digitalRead(pin) == LOW) { while (digitalRead(pin) == LOW) delay(5); return true; } }
  return false;
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_ONBOARD_LED, OUTPUT);
  fwMd5 = ESP.getSketchMD5();
  Serial.printf("\n%s  firmware MD5 = %s\n", DEVICE_ID, fwMd5.c_str());
#if ROLE == ROLE_SENSOR
  pinMode(PIN_BTN_A, INPUT_PULLUP); pinMode(PIN_BTN_B, INPUT_PULLUP);
  temps.begin();
#elif ROLE == ROLE_ACTUATOR
  pinMode(PIN_RELAY, OUTPUT); setPump(false);
  pinMode(PIN_GREEN, OUTPUT); pinMode(PIN_YELLOW, OUTPUT); pinMode(PIN_RED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT); buzz(false);
#else
  for (int i = 0; i < 5; i++) pinMode(BTN[i], INPUT_PULLUP);
#endif
  connectWifi();
  mqtt.setServer(BROKER_IP, BROKER_PORT);
  mqtt.setBufferSize(1024);           // gateway decisions exceed the 256-byte default
  mqtt.setCallback(onMessage);
  connectMqtt();
}

unsigned long lastTel = 0;

void loop() {
  if (!mqtt.connected()) connectMqtt();
  mqtt.loop();

#if ROLE == ROLE_SENSOR
  if (millis() - lastTel > 2000) {
    lastTel = millis();
    temps.requestTemperatures();
    float c = temps.getTempCByIndex(0);
    char buf[96];
    snprintf(buf, sizeof(buf), "{\"temp_c\":%.2f,\"fw_md5\":\"%s\"}", c, fwMd5.c_str());
    mqtt.publish((String(PREFIX) + "/tel/esp32_sensor").c_str(), buf);
    blink(20);
  }
  if (pressed(PIN_BTN_A)) sendRequest(DEVICE_ID, SENSOR_TOKEN, fwMd5.c_str(), "on");
  if (pressed(PIN_BTN_B)) sendRequest(DEVICE_ID, SENSOR_TOKEN, fwMd5.c_str(), "off");

#elif ROLE == ROLE_ATTACKER
  // A: right device name, wrong token                  -> DENY (authentication)
  if (pressed(BTN[0])) sendRequest("esp32_sensor", "guessed-token", fwMd5.c_str(), "on");
  // B: unregistered device                             -> DENY (authentication)
  if (pressed(BTN[1])) sendRequest("esp32_attacker", "guessed-token", fwMd5.c_str(), "on");
  // C: stolen token, but this board's own firmware     -> QUARANTINE (integrity),
  //    and the sensor's identity stays quarantined until the gateway restarts
  if (pressed(BTN[2])) sendRequest("esp32_sensor", SENSOR_TOKEN, fwMd5.c_str(), "on");
  // D: bypass the gateway, command the pump directly   -> works with mosquitto-day1.conf,
  //    rejected by the broker with mosquitto-acl.conf
  if (pressed(BTN[3])) { mqtt.publish((String(PREFIX) + "/cmd/pump").c_str(), "{\"state\":\"on\"}"); Serial.println("-> cmd/pump DIRECT"); }
  // E: perfect impersonation (stolen token + copied fingerprint), flooding 60 requests.
  //    The first few look legitimate and pass; the rate anomaly then gets them DENIED.
  //    This also shows the limitation: a self-reported hash can be copied.
  if (pressed(BTN[4])) for (int i = 0; i < 60; i++) { sendRequest("esp32_sensor", SENSOR_TOKEN, SENSOR_FW_MD5_COPY, "toggle"); mqtt.loop(); delay(50); }
#endif
}
