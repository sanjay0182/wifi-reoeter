// ESP8266 WiFi Repeater (NAT) + router jaisa admin web panel
// Board: NodeMCU 1.0 (ESP-12E Module)  |  lwIP Variant: v2 Higher Bandwidth
//
// Repeater ke WiFi se judo -> browser me http://10.10.10.1
// Login: user "admin", password "admin" (pehle login ke baad badal lena)
// Panel me: status, judhe devices (disconnect button), router scan, settings, proxy (PAC), restart, reset.
// LED (blue, NodeMCU): router nahi juda = 2 sec me chhota flash | juda par net nahi = LED jalti rahe |
//   net hai = blink: tez blink = net fast, dheere blink = net slow.
// Router band/password galat ho to bhi repeater WiFi + panel chalta rahega, aur router ko baar-baar try karta rahega.
// FLASH button 5 sec dabao = factory reset. Net 5 min tak na mile to router se dobara judta hai.

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>
#include <user_interface.h>
#include <lwip/napt.h>
#include <lwip/dns.h>

// 1 = CPU 160 MHz, 0 = 80 MHz (speed compare karne ke liye badlo)
#define USE_160MHZ 1
// --- Speed switches (max speed test ke liye 0 karke dekho) ---
#define LED_ENABLED 1   // 0 = LED band (CPU ka kaam kam)
#define NET_CHECK 1     // 0 = internet ping naapna band (LED bas 'juda hai' dikhayegi)
#define NAPT_ENTRIES 512
#define NAPT_PORTS 10
#define CFG_MAGIC 0xA5A50002
#define CFG_MAGIC2 0x5A5A0001
#define CFG_MAGIC3 0x5A5A0003

struct Config {
  uint32_t magic;
  char rSsid[33];   // router ka naam
  char rPass[65];   // router ka password
  char aSsid[33];   // repeater ka naam
  char aPass[65];   // repeater ka password (8+ ya khali)
  char admin[33];   // panel ka password
  // --- neeche wale naye fields (purani settings saaf nahi hoti) ---
  uint32_t magic2;
  uint8_t pEn;      // proxy chalu?
  uint8_t pType;    // 0 = HTTP, 1 = SOCKS5
  uint16_t pPort;
  char pHost[65];   // proxy ka host/IP
  uint32_t magic3;
  char dns[16];     // custom DNS (khali = router wala)
};

Config cfg;
ESP8266WebServer server(80);
IPAddress apIP(10, 10, 10, 1);
bool natOn = false;
bool wasOk = false;
uint32_t lastTick = 0;
uint32_t lastRetry = 0, discSince = 0, lastNet = 0, badSince = 0, btnSince = 0;
int netLat = -2;   // -2 = naap rahe, -1 = internet nahi, >=0 = ms
extern "C" bool wifi_softap_deauth(uint8_t mac[6]) __attribute__((weak));
#define wifi_softap_deauth_w wifi_softap_deauth

static const char PAGE_HEAD[] PROGMEM = R"rawliteral(<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>JAAT Repeater</title><style>
:root{color-scheme:light dark}
body{font-family:system-ui,sans-serif;max-width:460px;margin:auto;padding:12px}
.c{border:1px solid #8884;border-radius:12px;padding:12px 14px;margin:0 0 12px}
h2{margin:6px 0 12px}h3{margin:0 0 8px}
table{width:100%;border-collapse:collapse}
td{padding:5px 0;border-bottom:1px solid #8883;font-size:14px}
td:last-child{text-align:right}
label{display:block;font-size:13px;margin:8px 0 2px;opacity:.75}
input,select,button,.b{width:100%;box-sizing:border-box;padding:10px;font-size:16px;margin:2px 0;border-radius:8px;border:1px solid #8886;background:transparent;color:inherit}
button,.b{text-align:center;display:block;text-decoration:none;cursor:pointer}
.k{width:auto;display:inline-block;padding:4px 10px;font-size:13px}
.g{color:#2e9e5b}.r{color:#d9534f}
</style></head><body><h2>JAAT WiFi Repeater</h2>)rawliteral";

static const char PAGE_TAIL[] PROGMEM = R"rawliteral(<div class=c><h3>Tools</h3>
<a class=b href='/reboot' onclick="return confirm('Restart karein?')">Restart</a>
<a class=b href='/reset' onclick="return confirm('Sab settings default ho jayengi. Pakka?')">Factory reset</a></div>
<script>
function pk(v){if(v)document.getElementById('rs').value=v;}
function sc(){
var b=document.getElementById('sb');b.textContent='Scan ho raha hai...';
fetch('/scan.json').then(function(r){return r.json();}).then(function(l){
var s=document.getElementById('sl');
s.innerHTML='<option value="">-- chuno --</option>';
l.forEach(function(x){var o=document.createElement('option');o.value=x.s;o.textContent=x.s+' ('+x.r+' dBm'+(x.e?', lock':'')+')';s.appendChild(o);});
b.textContent='Dobara scan karo';
}).catch(function(){b.textContent='Scan fail, dobara try karo';});
}
</script></body></html>)rawliteral";

void loadConfig() {
  EEPROM.begin(sizeof(Config));
  EEPROM.get(0, cfg);
  if (cfg.magic != CFG_MAGIC) {
    memset(&cfg, 0, sizeof(cfg));
    cfg.magic = CFG_MAGIC;
    strcpy(cfg.rSsid, "ROUTER_WIFI_NAME");   // <-- apne router ka naam (ya panel se badlo)
    strcpy(cfg.rPass, "ROUTER_PASSWORD");    // <-- router ka password
    strcpy(cfg.aSsid, "JAAT_Repeater");
    strcpy(cfg.aPass, "12345678");
    strcpy(cfg.admin, "admin");
  }
  if (cfg.magic2 != CFG_MAGIC2) {
    cfg.magic2 = CFG_MAGIC2;
    cfg.pEn = 0; cfg.pType = 0; cfg.pPort = 8080;
    memset(cfg.pHost, 0, sizeof(cfg.pHost));
  }
  if (cfg.magic3 != CFG_MAGIC3) {
    cfg.magic3 = CFG_MAGIC3;
    memset(cfg.dns, 0, sizeof(cfg.dns));
  }
  cfg.dns[15] = 0;
  cfg.pHost[64] = 0;
  cfg.rSsid[32] = 0; cfg.rPass[64] = 0;
  cfg.aSsid[32] = 0; cfg.aPass[64] = 0; cfg.admin[32] = 0;
}

void saveConfig() {
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

String esc(String s) {
  s.replace("&", "&amp;");
  s.replace("<", "&lt;");
  s.replace(">", "&gt;");
  s.replace("'", "&#39;");
  s.replace("\"", "&quot;");
  return s;
}

String jsonEsc(String s) {
  s.replace("\\", "\\\\");
  s.replace("\"", "\\\"");
  return s;
}

String row(const String &a, const String &b) {
  return "<tr><td>" + a + "</td><td>" + b + "</td></tr>";
}

String uptimeStr() {
  uint32_t s = millis() / 1000;
  return String(s / 3600) + "h " + String((s / 60) % 60) + "m";
}

bool auth() {
  if (!server.authenticate("admin", cfg.admin)) {
    server.requestAuthentication();
    return false;
  }
  return true;
}

void enableNapt() {
  IPAddress d = WiFi.dnsIP(0);
  IPAddress custom;
  if (cfg.dns[0] && custom.fromString(cfg.dns)) d = custom;
  if (d == IPAddress(0, 0, 0, 0)) d = IPAddress(8, 8, 8, 8);
  WiFi.softAPDhcpServer().setDns(d);
  if (!natOn) {
    err_t ret = ip_napt_init(NAPT_ENTRIES, NAPT_PORTS);
    if (ret == ERR_OK) ret = ip_napt_enable_no(SOFTAP_IF, 1);
    natOn = (ret == ERR_OK);
    Serial.println(natOn ? "NAT chalu" : "NAT fail (lwIP variant check karo)");
  }
}

void measureNet() {
  WiFiClient c;
  c.setTimeout(500);   // connect ka timeout (ms)
  uint32_t t = millis();
  if (c.connect(IPAddress(1, 1, 1, 1), 443)) {
    netLat = (int)(millis() - t);
    c.stop();
    return;
  }
  t = millis();
  if (c.connect(IPAddress(8, 8, 8, 8), 53)) {
    netLat = (int)(millis() - t);
    c.stop();
    return;
  }
  netLat = -1;
}

void updateLed(bool ok) {
  uint32_t now = millis();
  bool on;
  if (!ok) {
    on = (now % 2000) < 80;            // router nahi juda: chhota flash
  } else if (netLat == -1) {
    on = true;                          // router juda, net nahi: LED jalti rahe
  } else {
    uint32_t hp = 500;                  // naap rahe
    if (netLat >= 0) hp = netLat <= 80 ? 100 : (netLat <= 200 ? 300 : (netLat <= 500 ? 700 : 1300));
    on = ((now / hp) & 1);
  }
  digitalWrite(LED_BUILTIN, on ? LOW : HIGH);
}

void handleRoot() {
  if (!auth()) return;
  bool ok = WiFi.status() == WL_CONNECTED;
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent_P(PAGE_HEAD);

  String h = F("<div class=c><h3>Status</h3><table>");
  h += row("Router", ok ? "<span class=g>Juda hua</span>" : "<span class=r>Nahi juda (retry chalta rahega)</span>");
  if (!ok) {
    int st = WiFi.status();
    String why = "Dhundh raha hai...";
    if (st == WL_NO_SSID_AVAIL) why = "Router mila nahi / band hai";
    else if (st == WL_CONNECT_FAILED || st == WL_WRONG_PASSWORD) why = "Password galat lagta hai";
    h += row("Wajah", why);
    h += row("Bina router", String((millis() - discSince) / 60000) + " min");
  }
  h += row("Router naam", esc(String(cfg.rSsid)));
  if (ok) {
    int r = WiFi.RSSI();
    String q = (r > -60) ? "badhiya" : (r > -75 ? "theek" : "kamzor");
    h += row("Router se mila IP", WiFi.localIP().toString());
    h += row("Signal", String(r) + " dBm (" + q + ")");
    h += row("Channel", String(WiFi.channel()));
    if (netLat >= 0) h += row("Internet", "<span class=g>Chal raha, " + String(netLat) + " ms</span>");
    else if (netLat == -1) h += row("Internet", "<span class=r>Nahi mil raha</span>");
    else h += row("Internet", "Naap rahe...");
  }
  h += row("LED", "tez blink = net fast, dheere = slow, jalti rahe = net nahi, chhota flash = router nahi");
  h += row("Repeater WiFi", esc(String(cfg.aSsid)));
  h += row("Repeater IP", apIP.toString());
  h += row("Internet sharing (NAT)", natOn ? "<span class=g>Chalu</span>" : "<span class=r>Band</span>");
  h += row("Uptime", uptimeStr());
  h += row("Free RAM", String(ESP.getFreeHeap() / 1024) + " KB");
  h += F("</table></div>");

  h += F("<div class=c><h3>Judhe devices (");
  h += WiFi.softAPgetStationNum();
  h += F(")</h3><table>");
  struct station_info *si = wifi_softap_get_station_info();
  if (!si) h += F("<tr><td>Koi device nahi juda</td></tr>");
  while (si) {
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             si->bssid[0], si->bssid[1], si->bssid[2], si->bssid[3], si->bssid[4], si->bssid[5]);
    IPAddress ip(si->ip.addr);
    h += "<tr><td>" + String(mac) + "<br>" + ip.toString() + "</td><td>";
    h += "<a class='b k' href='/kick?mac=" + String(mac) + "' onclick=\"return confirm('Disconnect karein?')\">Disconnect</a></td></tr>";
    si = STAILQ_NEXT(si, next);
  }
  wifi_softap_free_station_info();
  h += F("</table><a class=b href='/'>Refresh</a></div>");
  server.sendContent(h);

  h = F("<div class=c><h3>Settings</h3><form method=POST action='/save'>");
  h += F("<label>Router WiFi (jisse net lena hai)</label>");
  h += F("<select id=sl onchange='pk(this.value)'><option value=''>-- scan karke chuno --</option></select>");
  h += F("<button type=button id=sb onclick='sc()'>Scan karo</button>");
  h += F("<label>Router ka naam</label><input id=rs name=rs value='");
  h += esc(String(cfg.rSsid));
  h += F("'><label>Router ka password</label><input name=rp value='");
  h += esc(String(cfg.rPass));
  h += F("'><label>Repeater ka naam</label><input name=as value='");
  h += esc(String(cfg.aSsid));
  h += F("'><label>Repeater ka password (8+ ya khali)</label><input name=ap value='");
  h += esc(String(cfg.aPass));
  h += F("'><label>DNS (khali = router wala, jaise 8.8.8.8)</label><input name=dn value='");
  h += esc(String(cfg.dns));
  h += F("'><label>Panel ka password (khali = purana)</label><input name=ad value=''>");
  h += F("<button type=submit>Save aur restart</button></form></div>");
  server.sendContent(h);

  h = F("<div class=c><h3>Proxy (sirf ek device ke liye)</h3><form method=POST action='/saveproxy'>");
  h += F("<label><input type=checkbox name=pe value=1 style='width:auto' ");
  if (cfg.pEn) h += F("checked");
  h += F("> Proxy chalu</label><label>Type</label><select name=pt><option value=0>HTTP</option><option value=1");
  if (cfg.pType) h += F(" selected");
  h += F(">SOCKS5</option></select><label>Proxy host / IP</label><input name=ph value='");
  h += esc(String(cfg.pHost));
  h += F("'><label>Port</label><input name=pp type=number value='");
  h += String(cfg.pPort);
  h += F("'><button type=submit>Proxy save karo</button></form>");
  h += F("<p style='font-size:13px;opacity:.75'>Us device ki WiFi settings me Proxy = Auto-config (PAC), URL: <b>http://10.10.10.1/proxy.pac</b>. Sirf wahi device proxy se chalega, baaki normal. Proxy band hua to us device ka net band rahega.</p></div>");
  server.sendContent(h);

  server.sendContent_P(PAGE_TAIL);
  server.sendContent("");
}

void handleScan() {
  if (!auth()) return;
  int n = WiFi.scanNetworks();
  String j = "[";
  for (int i = 0; i < n; i++) {
    if (i) j += ",";
    j += "{\"s\":\"" + jsonEsc(WiFi.SSID(i)) + "\",\"r\":" + String(WiFi.RSSI(i)) +
         ",\"e\":" + (WiFi.encryptionType(i) != ENC_TYPE_NONE ? "true" : "false") + "}";
  }
  j += "]";
  WiFi.scanDelete();
  server.send(200, "application/json", j);
}

void handleKick() {
  if (!auth()) return;
  String m = server.arg("mac");
  if (m.length() == 17) {
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) {
      mac[i] = (uint8_t)strtoul(m.substring(i * 3, i * 3 + 2).c_str(), NULL, 16);
    }
    if (wifi_softap_deauth_w) {
      wifi_softap_deauth_w(mac);
    } else {
      // deauth API na mile to AP dobara chalu karo (sab device reconnect honge)
      WiFi.softAPdisconnect(false);
      delay(200);
      WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
      WiFi.softAP(cfg.aSsid, strlen(cfg.aPass) >= 8 ? cfg.aPass : nullptr, 1, 0, 8);
      WiFi.softAPDhcpServer().setDns(WiFi.dnsIP(0));
    }
  }
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleSave() {
  if (!auth()) return;
  String rs = server.arg("rs");
  String rp = server.arg("rp");
  String as = server.arg("as");
  String ap = server.arg("ap");
  String ad = server.arg("ad");
  String dn = server.arg("dn");
  dn.trim();
  IPAddress dtest;
  bool dnsBad = dn.length() > 0 && (dn.length() > 15 || !dtest.fromString(dn));
  if (as.length() < 1 || as.length() > 32 || rs.length() > 32 || rp.length() > 64 ||
      ap.length() > 64 || (ap.length() > 0 && ap.length() < 8) ||
      ad.length() > 32 || (ad.length() > 0 && ad.length() < 4) || dnsBad) {
    server.send(400, "text/html",
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<body style='font-family:sans-serif;padding:16px'>Galat input. Repeater password 8+ character ka ho (ya khali), panel password 4+ ka, DNS sahi IP ho (jaise 8.8.8.8). <a href='/'>Wapas</a></body>");
    return;
  }
  memset(cfg.rSsid, 0, sizeof(cfg.rSsid));
  memset(cfg.rPass, 0, sizeof(cfg.rPass));
  memset(cfg.aSsid, 0, sizeof(cfg.aSsid));
  memset(cfg.aPass, 0, sizeof(cfg.aPass));
  strncpy(cfg.rSsid, rs.c_str(), 32);
  strncpy(cfg.rPass, rp.c_str(), 64);
  strncpy(cfg.aSsid, as.c_str(), 32);
  strncpy(cfg.aPass, ap.c_str(), 64);
  memset(cfg.dns, 0, sizeof(cfg.dns));
  strncpy(cfg.dns, dn.c_str(), 15);
  if (ad.length() > 0) {
    memset(cfg.admin, 0, sizeof(cfg.admin));
    strncpy(cfg.admin, ad.c_str(), 32);
  }
  saveConfig();
  server.send(200, "text/html",
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<body style='font-family:sans-serif;padding:16px'>Save ho gaya. Restart ho raha hai, 20 second baad dobara judo.</body>");
  delay(1500);
  ESP.restart();
}

void handlePac() {
  String p = F("function FindProxyForURL(url,host){\n");
  p += F("if(isPlainHostName(host)||host=='localhost'||shExpMatch(host,'10.*')||shExpMatch(host,'192.168.*')||shExpMatch(host,'127.*'))return 'DIRECT';\n");
  if (cfg.pEn && cfg.pHost[0]) {
    String hp = String(cfg.pHost) + ":" + String(cfg.pPort);
    if (cfg.pType) p += "return 'SOCKS5 " + hp + "; SOCKS " + hp + "';\n";
    else p += "return 'PROXY " + hp + "';\n";
  } else {
    p += F("return 'DIRECT';\n");
  }
  p += "}\n";
  server.sendHeader("Cache-Control", "no-cache");
  server.send(200, "application/x-ns-proxy-autoconfig", p);
}

void handleProxySave() {
  if (!auth()) return;
  String h = server.arg("ph");
  h.trim();
  int port = server.arg("pp").toInt();
  bool en = server.hasArg("pe");
  bool bad = h.length() > 64 || (en && (h.length() < 1 || port < 1 || port > 65535));
  for (unsigned i = 0; i < h.length() && !bad; i++) {
    char c = h[i];
    if (!(isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_' || c == ':')) bad = true;
  }
  if (bad) {
    server.send(400, "text/html",
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<body style='font-family:sans-serif;padding:16px'>Proxy host/port galat hai. <a href='/'>Wapas</a></body>");
    return;
  }
  cfg.pEn = en ? 1 : 0;
  cfg.pType = server.arg("pt").toInt() == 1 ? 1 : 0;
  cfg.pPort = (port >= 1 && port <= 65535) ? port : 8080;
  memset(cfg.pHost, 0, sizeof(cfg.pHost));
  strncpy(cfg.pHost, h.c_str(), 64);
  saveConfig();
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleReboot() {
  if (!auth()) return;
  server.send(200, "text/html",
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<body style='font-family:sans-serif;padding:16px'>Restart ho raha hai...</body>");
  delay(1000);
  ESP.restart();
}

void handleReset() {
  if (!auth()) return;
  cfg.magic = 0;
  saveConfig();
  server.send(200, "text/html",
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<body style='font-family:sans-serif;padding:16px'>Factory reset ho gaya. Default WiFi: JAAT_Repeater / 12345678, login admin/admin.</body>");
  delay(1500);
  ESP.restart();
}

void setup() {
#if USE_160MHZ
  system_update_cpu_freq(SYS_CPU_160MHZ);   // NAT ke liye tez CPU (80 -> 160 MHz)
#endif
  Serial.begin(115200);
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);
  loadConfig();

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.setPhyMode(WIFI_PHY_MODE_11N);   // mode n (martin-ger repeater ka default) = sabse tez
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  WiFi.setOutputPower(20.5);
  WiFi.setAutoReconnect(true);
  WiFi.hostname("JAAT-Repeater");
  pinMode(0, INPUT_PULLUP);   // FLASH button: 5 sec dabao = factory reset

  // Pehle repeater WiFi + panel chalu (router mile ya na mile, panel hamesha khulega)
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(cfg.aSsid, strlen(cfg.aPass) >= 8 ? cfg.aPass : nullptr, 1, 0, 8);

  server.on("/", handleRoot);
  server.on("/scan.json", handleScan);
  server.on("/kick", handleKick);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/saveproxy", HTTP_POST, handleProxySave);
  server.on("/proxy.pac", handlePac);
  server.on("/reboot", handleReboot);
  server.on("/reset", handleReset);
  server.begin();
  Serial.println("Panel: http://10.10.10.1");

  // Router se connect (background me, setup ko rokta nahi)
  WiFi.begin(cfg.rSsid, cfg.rPass);
  lastRetry = millis();
  discSince = millis();
}

void loop() {
  server.handleClient();
  uint32_t now = millis();
  bool ok = (WiFi.status() == WL_CONNECTED);

  if (ok) {
    if (!wasOk) {            // abhi-abhi juda (pehli baar ya router wapas aaya)
      wasOk = true;
      netLat = -2;
      lastNet = 0;
      enableNapt();
    }
#if NET_CHECK
    if (now - lastNet > (netLat < 0 ? 10000UL : 60000UL)) {
      lastNet = now;
      measureNet();
    }
#else
    netLat = 0;   // naapna band: LED tez blink = router se juda hai
#endif
  } else {
    if (wasOk) {             // abhi-abhi toota
      wasOk = false;
      discSince = now;
      netLat = -1;
    }
    // Router na mile / password galat ho to bhi har 45 sec me naya try, hamesha
    if (now - lastRetry > 45000UL) {
      lastRetry = now;
      WiFi.disconnect();
      WiFi.begin(cfg.rSsid, cfg.rPass);
    }
  }

  // Net 5 min se nahi mil raha (par router juda hai) -> router se dobara judo
  if (ok && netLat == -1) {
    if (!badSince) badSince = now;
    else if (now - badSince > 300000UL) {
      badSince = 0;
      WiFi.disconnect();
      WiFi.begin(cfg.rSsid, cfg.rPass);
    }
  } else {
    badSince = 0;
  }

  // Button + LED har loop me nahi, sirf 20 ms me ek baar (CPU bachane ke liye)
  if (now - lastTick >= 20) {
    lastTick = now;

    // FLASH button 5 second dabaye rakho = factory reset (password bhool jao to kaam aata hai)
    if (digitalRead(0) == LOW) {
      if (!btnSince) btnSince = now;
      else if (now - btnSince > 5000UL) {
        cfg.magic = 0;
        saveConfig();
        ESP.restart();
      }
    } else {
      btnSince = 0;
    }

#if LED_ENABLED
    updateLed(ok);
#else
    digitalWrite(LED_BUILTIN, HIGH);
#endif
  }
}
