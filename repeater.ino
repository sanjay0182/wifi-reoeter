// ESP8266 WiFi Repeater (NAT) + router jaisa admin web panel
// Board: NodeMCU 1.0 (ESP-12E Module)  |  lwIP Variant: v2 Higher Bandwidth
//
// Repeater ke WiFi se judo -> browser me http://10.10.10.1
// Login: user "admin", password "admin" (pehle login ke baad badal lena)
// Panel me: status, judhe devices (disconnect button), router scan, settings, proxy (PAC), restart, reset.
// LED (blue, NodeMCU): router nahi juda = 2 sec me chhota flash | juda par net nahi = LED jalti rahe |
//   net hai = blink: tez blink = net fast, dheere blink = net slow.
// Router band/password galat ho to bhi repeater WiFi + panel chalta rahega, aur router ko baar-baar try karta rahega.
// Transparent mode (Proxy card me checkbox): DNS hijack + tunnel, device me proxy setting nahi; panel tab :8080 par.
// FLASH button 5 sec dabao = factory reset. Net 5 min tak na mile to router se dobara judta hai.

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>
#include <user_interface.h>
#include <lwip/napt.h>
#include <lwip/dns.h>
#include <DNSServer.h>

struct Tun;   // forward declaration: Arduino auto-prototype ke liye zaroori

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
#define CFG_MAGIC4 0x5A5A0004
#define CFG_MAGIC5 0x5A5A0005
#define CFG_MAGIC6 0x5A5A0006
// Repeater ka default network: 10.10.<ye number>.1  (is board ke liye chaho to 20 kar do)
#define DEFAULT_AP_OCT 10

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
  uint32_t magic4;
  uint8_t apOct;    // repeater network: 10.10.<apOct>.1
  uint32_t magic5;
  char apMac[18];   // repeater (AP) MAC, khali = board ka apna
  uint32_t magic6;
  uint8_t tEn;      // transparent proxy (DNS hijack + tunnel) chalu?
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

bool parseMac(const char *t, uint8_t *m) {
  if (strlen(t) != 17) return false;
  for (int i = 0; i < 6; i++) {
    char a = t[i * 3], b = t[i * 3 + 1];
    if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)b)) return false;
    if (i < 5 && t[i * 3 + 2] != ':') return false;
    char h[3] = {a, b, 0};
    m[i] = (uint8_t)strtoul(h, NULL, 16);
  }
  return true;
}

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
  if (cfg.magic4 != CFG_MAGIC4) {
    cfg.magic4 = CFG_MAGIC4;
    cfg.apOct = DEFAULT_AP_OCT;
  }
  if (cfg.magic5 != CFG_MAGIC5) {
    cfg.magic5 = CFG_MAGIC5;
    memset(cfg.apMac, 0, sizeof(cfg.apMac));
  }
  if (cfg.magic6 != CFG_MAGIC6) {
    cfg.magic6 = CFG_MAGIC6;
    cfg.tEn = 0;
  }
  cfg.tEn = cfg.tEn ? 1 : 0;
  cfg.apMac[17] = 0;
  if (cfg.apOct < 1 || cfg.apOct > 254) cfg.apOct = DEFAULT_AP_OCT;
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
  if (cfg.tEn) d = apIP;   // transparent mode: clients ka DNS = repeater khud
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
  if (cfg.tEn && cfg.pEn && cfg.pHost[0]) {   // proxy se net: proxy tak pahunch = net theek
    if (c.connect(cfg.pHost, cfg.pPort)) { netLat = (int)(millis() - t); c.stop(); }
    else netLat = -1;
    return;
  }
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

// ================= Transparent proxy: DNS hijack + tunnel =================
// 1) DHCP se client ko DNS = repeater milta hai, repeater har naam ka jawab apna IP deta hai.
// 2) Client repeater ke port 80 (HTTP) ya 443 (HTTPS) par aata hai.
// 3) Repeater HTTP "Host:" ya HTTPS ClientHello ka SNI padh ke site ka naam nikalta hai.
// 4) Upar wale proxy ko CONNECT site:port bhejta hai (ya SOCKS5), phir dono taraf ka data pipe karta hai.
// Limit: sirf port 80/443. ESP8266 me ~5 TCP socket hote hain aur har tunnel 2 leta hai, isliye TUN_MAX 2.
#define TUN_MAX 2            // ek saath kitne tunnel
#define TUN_HEAD 2048        // shuru ke bytes (ClientHello / HTTP head) rakhne ki jagah
#define TUN_HEAD_MS 4000UL   // itni der me client ne kuch na bheja to band
#define TUN_IDLE_MS 60000UL  // tunnel me itni der kuch na chale to band
#define PANEL_ALT_PORT 8080  // transparent mode me panel yaha khulta hai (port 80 tunnel ke liye chahiye)

// ==== PURE-START (sirf bytes parse karne wale functions, koi ESP cheez nahi)
static bool okHostName(const char *h) {
  if (!h[0]) return false;
  for (const char *p = h; *p; p++) {
    char c = *p;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return false;
  }
  return true;
}

// TLS ClientHello se SNI (site ka naam) nikalo. Mila to length, nahi mila to 0.
static int parseSNI(const uint8_t *b, int n, char *out, int cap) {
  if (n < 9 || b[0] != 0x16 || b[5] != 0x01) return 0;   // handshake record + ClientHello
  int p = 5 + 4 + 2 + 32;                                // record(5) + hs header(4) + version(2) + random(32)
  if (p + 1 > n) return 0;
  p += 1 + b[p];                                         // session id
  if (p + 2 > n) return 0;
  p += 2 + ((b[p] << 8) | b[p + 1]);                     // cipher suites
  if (p + 1 > n) return 0;
  p += 1 + b[p];                                         // compression
  if (p + 2 > n) return 0;
  int extEnd = p + 2 + ((b[p] << 8) | b[p + 1]);
  p += 2;
  if (extEnd > n) extEnd = n;                            // adhura aaya ho to jitna hai utna dekho
  while (p + 4 <= extEnd) {
    int type = (b[p] << 8) | b[p + 1];
    int len = (b[p + 2] << 8) | b[p + 3];
    p += 4;
    if (type == 0) {                                     // server_name extension
      if (p + 5 > n || b[p + 2] != 0) return 0;          // list len(2), name type(1)=host_name
      int nl = (b[p + 3] << 8) | b[p + 4];
      if (nl <= 0 || nl >= cap || p + 5 + nl > n) return 0;
      memcpy(out, b + p + 5, nl);
      out[nl] = 0;
      return nl;
    }
    p += len;
  }
  return 0;
}

// HTTP request ke head se "Host:" nikalo (port hata ke). Mila to length, nahi mila to 0.
static int parseHttpHost(const uint8_t *b, int n, char *out, int cap) {
  int i = 0;
  while (i < n && b[i] != '\n') i++;   // request line chhodo
  i++;
  while (i < n) {
    int ls = i;
    while (i < n && b[i] != '\n') i++;
    int le = i;
    if (le > ls && b[le - 1] == '\r') le--;
    if (le == ls) break;               // khali line = headers khatam
    if (le - ls > 5 && strncasecmp((const char *)b + ls, "host:", 5) == 0) {
      int s = ls + 5;
      while (s < le && (b[s] == ' ' || b[s] == '\t')) s++;
      int e = s;
      while (e < le && b[e] != ':') e++;
      int nl = e - s;
      if (nl <= 0 || nl >= cap) return 0;
      memcpy(out, b + s, nl);
      out[nl] = 0;
      return nl;
    }
    i++;
  }
  return 0;
}

// HTTP head poora aaya? (\r\n\r\n mila)
static bool httpHeadDone(const uint8_t *b, int n) {
  for (int i = 3; i < n; i++)
    if (b[i] == '\n' && b[i - 1] == '\r' && b[i - 2] == '\n' && b[i - 3] == '\r') return true;
  return false;
}

// request line se path nikalo (redirect ke liye)
static void parseReqPath(const uint8_t *b, int n, char *out, int cap) {
  int i = 0, o = 0;
  while (i < n && b[i] != ' ' && b[i] != '\r' && b[i] != '\n') i++;
  if (i < n && b[i] == ' ') i++;
  while (i < n && b[i] > ' ' && b[i] < 0x7F && o < cap - 1) out[o++] = (char)b[i++];
  out[o] = 0;
  if (o == 0 || out[0] != '/') { out[0] = '/'; out[1] = 0; }
}
// ==== PURE-END

struct Tun {
  bool used, relay;
  uint16_t port, hl;
  uint8_t *head;
  uint32_t t0, last;
  WiFiClient c, u;   // c = client (repeater se juda), u = upstream (proxy ki taraf)
};
static Tun tun[TUN_MAX];
static WiFiServer tsrv80(80), tsrv443(443);
static DNSServer dnsSrv;
static uint8_t rbuf[1460];
static uint32_t proxyBadAt = 0, tunOk = 0, tunFail = 0;
static char tunErr[56] = "-";

static inline bool older(uint32_t now, uint32_t t, uint32_t ms) {
  return (int32_t)(now - t) > (int32_t)ms;
}

static void tunClose(Tun &t) {
  t.c.stop();
  t.u.stop();
  if (t.head) { free(t.head); t.head = NULL; }
  t.used = false;
  t.relay = false;
  t.hl = 0;
}

static void tunReply(WiFiClient &c, const char *code, const char *msg) {
  c.print("HTTP/1.1 ");
  c.print(code);
  c.print("\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: ");
  c.print((int)strlen(msg));
  c.print("\r\n\r\n");
  c.print(msg);
}

static bool readN(WiFiClient &u, uint8_t *b, int n, uint32_t ms) {
  uint32_t t0 = millis();
  int got = 0;
  while (got < n) {
    int a = u.available();
    if (a > 0) {
      int r = u.read(b + got, (a < n - got) ? a : (n - got));
      if (r > 0) got += r;
      continue;
    }
    if (!u.connected() || (millis() - t0) > ms) return false;
    delay(1);
  }
  return true;
}

// Proxy se juro aur "host:port" tak ka rasta kholo. Sahi hua to true.
static bool openUpstream(WiFiClient &u, const char *host, uint16_t port) {
  if (!cfg.pEn || !cfg.pHost[0]) { strcpy(tunErr, "proxy set nahi (Proxy chalu + host/port bharo)"); return false; }
  u.setTimeout(1500);
  if (!u.connect(cfg.pHost, cfg.pPort)) { strcpy(tunErr, "proxy se connect nahi hua (host/port ya router check karo)"); return false; }
  u.setNoDelay(true);
  if (cfg.pType == 0) {
    // HTTP proxy: CONNECT host:port
    char req[220];
    int n = snprintf(req, sizeof(req), "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Connection: keep-alive\r\n\r\n", host, port, host, port);
    u.write((const uint8_t *)req, n);
    char line[16] = {0};
    int ln = 0;
    uint32_t tail = 0, t0 = millis();
    while ((millis() - t0) < 2500) {
      while (u.available()) {
        int ch = u.read();
        if (ln < (int)sizeof(line) - 1) line[ln++] = (char)ch;
        tail = (tail << 8) | (uint8_t)ch;
        if (tail == 0x0D0A0D0AUL) {
          if (strstr(line, " 200")) return true;
          snprintf(tunErr, sizeof(tunErr), "proxy ne CONNECT mana kiya (%.3s) port %u", line + 9, port);
          return false;
        }
      }
      if (!u.connected() && !u.available()) { strcpy(tunErr, "proxy ne connection tod diya"); return false; }
      delay(1);
    }
    strcpy(tunErr, "proxy ne jawab nahi diya (CONNECT)");
    return false;
  }
  // SOCKS5 (bina password)
  uint8_t g[3] = {5, 1, 0};
  u.write(g, 3);
  uint8_t r[4];
  if (!readN(u, r, 2, 2000) || r[0] != 5 || r[1] != 0) { strcpy(tunErr, "SOCKS5 handshake fail"); return false; }
  int hl = strlen(host);
  uint8_t q[5 + 96 + 2];
  q[0] = 5; q[1] = 1; q[2] = 0; q[3] = 3; q[4] = (uint8_t)hl;
  memcpy(q + 5, host, hl);
  q[5 + hl] = (uint8_t)(port >> 8);
  q[6 + hl] = (uint8_t)(port & 255);
  u.write(q, 7 + hl);
  if (!readN(u, r, 4, 2500) || r[0] != 5 || r[1] != 0) { strcpy(tunErr, "SOCKS5 ne connect mana kiya"); return false; }
  int skip = 0;
  if (r[3] == 1) skip = 6;
  else if (r[3] == 4) skip = 18;
  else if (r[3] == 3) {
    uint8_t l;
    if (!readN(u, &l, 1, 2000)) { strcpy(tunErr, "SOCKS5 jawab adhura"); return false; }
    skip = l + 2;
  }
  uint8_t d;
  while (skip-- > 0) {
    if (!readN(u, &d, 1, 2000)) { strcpy(tunErr, "SOCKS5 jawab adhura"); return false; }
  }
  return true;
}

static void tunAccept(WiFiServer &s, uint16_t port, uint32_t now) {
  for (int i = 0; i < TUN_MAX; i++) {
    if (tun[i].used) continue;
    WiFiClient c = s.available();
    if (!c) return;
    uint8_t *h = (uint8_t *)malloc(TUN_HEAD);
    if (!h) { c.stop(); return; }
    Tun &t = tun[i];
    t.c = c;
    t.c.setNoDelay(true);
    t.head = h;
    t.hl = 0;
    t.port = port;
    t.used = true;
    t.relay = false;
    t.t0 = now;
    t.last = now;
    return;   // ek baar me ek hi naya connection
  }
}

static void tunStep(Tun &t, uint32_t now) {
  if (!t.relay) {
    // ---- pehle client ke shuru ke bytes padho ----
    int a = t.c.available();
    if (a > 0) {
      if (a > TUN_HEAD - t.hl) a = TUN_HEAD - t.hl;
      if (a > 0) {
        int r = t.c.read(t.head + t.hl, a);
        if (r > 0) { t.hl += r; t.last = now; }
      }
    }
    bool ready;
    if (t.port == 443) {
      ready = false;
      if (t.hl >= 5) {
        uint32_t need = 5 + (((uint32_t)t.head[3] << 8) | t.head[4]);
        ready = (t.hl >= need) || (t.hl >= TUN_HEAD) || older(now, t.last, 800);
      }
    } else {
      ready = httpHeadDone(t.head, t.hl) || t.hl >= TUN_HEAD;
    }
    if (!ready) {
      if (older(now, t.t0, TUN_HEAD_MS) || (!t.c.connected() && t.c.available() == 0)) tunClose(t);
      return;
    }

    char host[96];
    host[0] = 0;
    if (t.port == 443) parseSNI(t.head, t.hl, host, sizeof(host));
    else parseHttpHost(t.head, t.hl, host, sizeof(host));

    // port 80 par repeater ka apna IP likha ho (ya Host na ho) = panel kholna hai -> :8080 par bhejo
    if (t.port == 80 && (host[0] == 0 || apIP.toString() == host)) {
      char path[80];
      parseReqPath(t.head, t.hl, path, sizeof(path));
      t.c.print("HTTP/1.1 302 Found\r\nLocation: http://" + apIP.toString() + ":" + String(PANEL_ALT_PORT) + path +
                "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      tunClose(t);
      return;
    }
    if (!okHostName(host)) {
      strcpy(tunErr, t.port == 443 ? "HTTPS: site ka naam (SNI) nahi mila" : "HTTP: Host nahi mila");
      tunFail++;
      tunClose(t);
      return;
    }
    if (proxyBadAt && !older(millis(), proxyBadAt, 3000)) {   // proxy abhi atka tha: 3 sec ruko
      tunFail++;
      if (t.port == 80) tunReply(t.c, "502 Bad Gateway", "Proxy se connect nahi hua");
      tunClose(t);
      return;
    }
    if (!openUpstream(t.u, host, t.port)) {
      proxyBadAt = millis();
      if (!proxyBadAt) proxyBadAt = 1;
      tunFail++;
      if (t.port == 80) tunReply(t.c, "502 Bad Gateway", "Proxy se connect nahi hua");
      tunClose(t);
      return;
    }
    proxyBadAt = 0;
    t.u.write(t.head, t.hl);        // shuru ke bytes proxy ko aage bhejo
    free(t.head);
    t.head = NULL;
    t.hl = 0;
    t.relay = true;
    t.last = millis();
    tunOk++;
    return;
  }

  // ---- tunnel chalu: data idhar se udhar ----
  int a = t.c.available();
  if (a > 0) {
    int w = t.u.availableForWrite();
    if (w > 0) {
      if (a > w) a = w;
      if (a > (int)sizeof(rbuf)) a = sizeof(rbuf);
      int r = t.c.read(rbuf, a);
      if (r > 0) { t.u.write(rbuf, r); t.last = now; }
    }
  }
  a = t.u.available();
  if (a > 0) {
    int w = t.c.availableForWrite();
    if (w > 0) {
      if (a > w) a = w;
      if (a > (int)sizeof(rbuf)) a = sizeof(rbuf);
      int r = t.u.read(rbuf, a);
      if (r > 0) { t.c.write(rbuf, r); t.last = now; }
    }
  }
  bool cc = t.c.connected() || t.c.available();
  bool uc = t.u.connected() || t.u.available();
  if (!cc || !uc || older(now, t.last, TUN_IDLE_MS)) tunClose(t);
}

static void tunnelLoop() {
  uint32_t now = millis();
  dnsSrv.processNextRequest();
  tunAccept(tsrv80, 80, now);
  tunAccept(tsrv443, 443, now);
  for (int i = 0; i < TUN_MAX; i++)
    if (tun[i].used) tunStep(tun[i], now);
}
// ================= Transparent proxy khatam =================

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
  h += row("Repeater MAC", WiFi.softAPmacAddress());
  h += row("Internet sharing (NAT)", natOn ? "<span class=g>Chalu</span>" : "<span class=r>Band</span>");
  if (cfg.tEn) {
    h += row("Transparent proxy", "<span class=g>Chalu</span> (panel port " + String(PANEL_ALT_PORT) + ")");
    h += row("Tunnel", "ok " + String(tunOk) + " / fail " + String(tunFail));
    h += row("Tunnel error", esc(String(tunErr)));
  }
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
  h += F("'><label>Repeater network number (10.10.__.1). Repeater ko repeater se jodo to alag rakho</label><input name=an type=number min=1 max=254 value='");
  h += String(cfg.apOct);
  h += F("'><label>Repeater MAC (khali = board ka apna, jaise 02:11:22:33:44:55)</label><input name=am value='");
  h += esc(String(cfg.apMac));
  h += F("'><label>Panel ka password (khali = purana)</label><input name=ad value=''>");
  h += F("<button type=submit>Save aur restart</button></form></div>");
  server.sendContent(h);

  h = F("<div class=c><h3>Proxy</h3><form method=POST action='/saveproxy'>");
  h += F("<label><input type=checkbox name=pe value=1 style='width:auto' ");
  if (cfg.pEn) h += F("checked");
  h += F("> Proxy chalu</label><label>Type</label><select name=pt><option value=0>HTTP</option><option value=1");
  if (cfg.pType) h += F(" selected");
  h += F(">SOCKS5</option></select><label>Proxy host / IP</label><input name=ph value='");
  h += esc(String(cfg.pHost));
  h += F("'><label>Port</label><input name=pp type=number value='");
  h += String(cfg.pPort);
  h += F("'><label><input type=checkbox name=te value=1 style='width:auto' ");
  if (cfg.tEn) h += F("checked");
  h += F("> Transparent mode (device me koi proxy setting nahi)</label>");
  h += F("<button type=submit>Proxy save karo</button></form>");

  h += F("<p style='font-size:13px;opacity:.75'>Transparent mode: sab devices bina setting ke chalenge (sirf port 80/443). Chalu/band karne par restart hoga, aur panel <b>http://10.10.10.1:8080</b> par khulega. Band rakho to purana tareeka: device me PAC URL <b>http://10.10.10.1/proxy.pac</b>.</p></div>");
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
      WiFi.softAPDhcpServer().setDns(cfg.tEn ? apIP : WiFi.dnsIP(0));
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
  int an = server.arg("an").toInt();
  String dn = server.arg("dn");
  String am = server.arg("am");
  am.trim();
  uint8_t amt[6];
  bool macBad = am.length() > 0 && (!parseMac(am.c_str(), amt) || (amt[0] & 1));
  dn.trim();
  IPAddress dtest;
  bool dnsBad = dn.length() > 0 && (dn.length() > 15 || !dtest.fromString(dn));
  if (as.length() < 1 || as.length() > 32 || rs.length() > 32 || rp.length() > 64 ||
      ap.length() > 64 || (ap.length() > 0 && ap.length() < 8) ||
      ad.length() > 32 || (ad.length() > 0 && ad.length() < 4) || dnsBad || macBad || an < 1 || an > 254) {
    server.send(400, "text/html",
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<body style='font-family:sans-serif;padding:16px'>Galat input. Repeater password 8+ character ka ho (ya khali), panel password 4+ ka, DNS sahi IP ho (jaise 8.8.8.8), MAC aisa ho 02:11:22:33:44:55. <a href='/'>Wapas</a></body>");
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
  cfg.apOct = (uint8_t)an;
  memset(cfg.apMac, 0, sizeof(cfg.apMac));
  strncpy(cfg.apMac, am.c_str(), 17);
  if (ad.length() > 0) {
    memset(cfg.admin, 0, sizeof(cfg.admin));
    strncpy(cfg.admin, ad.c_str(), 32);
  }
  saveConfig();
  server.send(200, "text/html",
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<body style='font-family:sans-serif;padding:16px'>Save ho gaya. Restart ho raha hai, 20 second baad dobara judo. Panel ab http://10.10.NETWORK.1 par khulega (jo network number daala).</body>");
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
  bool te = server.hasArg("te");
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
  bool tchg = (te ? 1 : 0) != cfg.tEn;
  cfg.tEn = te ? 1 : 0;
  saveConfig();
  if (tchg) {
    String u = "http://" + apIP.toString() + (te ? ":" + String(PANEL_ALT_PORT) : String(""));
    server.send(200, "text/html",
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<body style='font-family:sans-serif;padding:16px'>Save ho gaya. Restart ho raha hai, 20 second baad dobara judo. Panel ab " + u + " par khulega.</body>");
    delay(1500);
    ESP.restart();
    return;
  }
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
  {
    uint8_t am[6];
    if (cfg.apMac[0] && parseMac(cfg.apMac, am) && !(am[0] & 1)) wifi_set_macaddr(SOFTAP_IF, am);
  }
  WiFi.setPhyMode(WIFI_PHY_MODE_11N);   // mode n (martin-ger repeater ka default) = sabse tez
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  WiFi.setOutputPower(20.5);
  WiFi.setAutoReconnect(true);
  WiFi.hostname("JAAT-Repeater");
  pinMode(0, INPUT_PULLUP);   // FLASH button: 5 sec dabao = factory reset

  // Pehle repeater WiFi + panel chalu (router mile ya na mile, panel hamesha khulega)
  apIP = IPAddress(10, 10, cfg.apOct, 1);
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
  if (cfg.tEn) {
    WiFi.softAPDhcpServer().setDns(apIP);
    dnsSrv.start(53, "*", apIP);   // har naam ka jawab = repeater ka IP
    tsrv80.begin();
    tsrv80.setNoDelay(true);
    tsrv443.begin();
    tsrv443.setNoDelay(true);
  }
  server.begin(cfg.tEn ? PANEL_ALT_PORT : 80);
  Serial.println(cfg.tEn ? "Panel: http://10.10.10.1:8080 (transparent mode)" : "Panel: http://10.10.10.1");

  // Router se connect (background me, setup ko rokta nahi)
  WiFi.begin(cfg.rSsid, cfg.rPass);
  lastRetry = millis();
  discSince = millis();
}

void loop() {
  server.handleClient();
  if (cfg.tEn) tunnelLoop();
  uint32_t now = millis();
  bool ok = (WiFi.status() == WL_CONNECTED);

  if (ok) {
    if (!wasOk) {            // abhi-abhi juda (pehli baar ya router wapas aaya)
      wasOk = true;
      IPAddress li = WiFi.localIP();
      if (li[0] == apIP[0] && li[1] == apIP[1] && li[2] == apIP[2]) {
        // Router ka network aur repeater ka network same (jaise repeater 1 -> repeater 2): net nahi chalega.
        // Apne aap alag network chuno aur restart.
        cfg.apOct = (apIP[2] == 10) ? 20 : 10;
        saveConfig();
        delay(300);
        ESP.restart();
      }
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
