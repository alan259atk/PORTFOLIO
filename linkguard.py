#!/usr/bin/env python3
"""
linkguard.py - enhanced URL scanner with detection for camera, mic, location,
keystroke logging, IP tracking (WebRTC/STUN/public-ip calls), canvas fingerprinting,
and system info collection. Uses static heuristics + optional Playwright dynamic checks.

Usage:
  ./linkguard.py https://example.com
  ./linkguard.py -f urls.txt --dynamic
  ./linkguard.py --json --dynamic https://suspicious-site.example
"""

import sys, argparse, re, json, socket, urllib.parse, subprocess, time, os
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import tldextract
import whois
import dns.resolver

# Optional dynamic analysis using Playwright
USE_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    USE_PLAYWRIGHT = True
except Exception:
    USE_PLAYWRIGHT = False

# --- Heuristic weights (tweakable) ---
WEIGHTS = {
    "long_url": 1,
    "ip_in_host": 2,
    "suspicious_tld": 1,
    "no_https": 2,
    "invalid_cert": 2,
    "whois_recent": 2,
    "form_exfil": 3,
    "hidden_inputs": 1,
    "meta_refresh": 1,
    "suspicious_js": 2,
    "shortened": 2,
    "camera_patterns": 4,
    "iframe_allow_camera": 4,
    "web_rtc": 3,
    "dynamic_camera_call": 6,
    "dynamic_mic_call": 6,
    "dynamic_location_call": 5,
    "keystroke_listener": 5,
    "websocket_exfil": 4,
    "fetch_xhr_exfil": 4,
    "canvas_fp": 3,
    "navigator_fingerprint": 3,
    "public_ip_call": 3
}

SHORTENERS = ("bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly")
SUSPICIOUS_TLDS = (".xyz", ".top", ".club", ".icu", ".pw", ".tk")
PUBLIC_IP_DOMAINS = ("api.ipify.org", "icanhazip.com", "ident.me", "ifconfig.me", "ipinfo.io")

# --- Utilities ---
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("target", help="URL or - for stdin or -f filename", nargs='?')
    p.add_argument("-f","--file", help="file with URLs, one per line")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--dynamic", action="store_true", help="use Playwright dynamic JS checks (optional, needs playwright installed)")
    p.add_argument("--timeout", type=int, default=12, help="request timeout seconds")
    return p.parse_args()

def norm_url(u):
    if not u:
        return None
    u = u.strip()
    if not u:
        return None
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', u):
        u = "http://" + u
    return u

def host_is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False

def check_tls(url, timeout=8):
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=True)
        return True, None
    except requests.exceptions.SSLError as e:
        return False, str(e)
    except Exception:
        return None, None

def fetch_page(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"LinkGuard/1.0 (+)"} , allow_redirects=True)
        return r.status_code, r.text, r.headers
    except Exception as e:
        return None, None, {"error": str(e)}

def analyze_html(html, base_url):
    findings = {
        "forms":[], "hidden_inputs":0, "meta_refresh":False, "suspicious_js":0,
        "camera_patterns": [], "iframe_allow_camera": [], "webrtc_signatures": [],
        "geolocation_patterns": [], "keystroke_patterns": [], "canvas_usage": [], "public_ip_calls": []
    }
    if not html:
        return findings
    soup = BeautifulSoup(html, "html.parser")
    # forms
    for form in soup.find_all("form"):
        action = form.get("action","").strip()
        action_url = urllib.parse.urljoin(base_url, action) if action else base_url
        findings["forms"].append(action_url)
    hidden_count = len(soup.find_all("input", {"type":"hidden"}))
    findings["hidden_inputs"] = hidden_count
    # meta refresh
    for m in soup.find_all("meta"):
        if m.get("http-equiv","").lower() == "refresh":
            findings["meta_refresh"]=True
            break
    # suspicious js patterns (static search inside inline and script content)
    scripts = soup.find_all("script")
    js_text = ""
    for s in scripts:
        if s.string:
            js_text += s.string + " "
        elif s.contents:
            js_text += " ".join([str(c) for c in s.contents]) + " "
    suspicious_patterns = [r"eval\(", r"document\.cookie", r"window\.location", r"atob\(", r"unescape\("]
    count = 0
    for pat in suspicious_patterns:
        if re.search(pat, js_text, re.I):
            count += 1
    findings["suspicious_js"] = count

    # camera/mic/location related static patterns
    camera_patterns = [
        r"navigator\.mediaDevices\.getUserMedia", r"\.getUserMedia\s*\(",
        r"navigator\.getUserMedia", r"Permissions\.request\s*\(\s*\{\s*name\s*:\s*['\"]camera['\"]",
        r"enumerateDevices\s*\(", r"RTCPeerConnection", r"getDisplayMedia\s*\(", r"attachMediaStream"
    ]
    for pat in camera_patterns:
        if re.search(pat, js_text, re.I):
            findings["camera_patterns"].append(pat)

    # geolocation
    if re.search(r"navigator\.geolocation\.getCurrentPosition|watchPosition|Permissions\.request\s*\(\s*\{\s*name\s*:\s*['\"]geolocation['\"]", js_text, re.I):
        findings["geolocation_patterns"].append("geolocation_api")

    # keystroke detection patterns
    if re.search(r"addEventListener\s*\(\s*['\"](key|keydown|keyup|keypress)['\"]", js_text, re.I) or re.search(r"onkeydown\s*=", html, re.I):
        findings["keystroke_patterns"].append("keydown_listener")

    # canvas fingerprinting
    if re.search(r"toDataURL\s*\(|getImageData\s*\(", js_text, re.I) or re.search(r"getContext\s*\(\s*['\"]webgl|2d['\"]\s*\)", js_text, re.I):
        findings["canvas_usage"].append("canvas_toDataURL_or_webgl")

    # public IP calls (static)
    for dom in PUBLIC_IP_DOMAINS:
        if dom in js_text or dom in html:
            findings["public_ip_calls"].append(dom)

    # iframe allow attributes
    for iframe in soup.find_all(["iframe","embed","object"]):
        allow = (iframe.get("allow") or "").lower()
        if "camera" in allow or "microphone" in allow or "geolocation" in allow:
            findings["iframe_allow_camera"].append(allow)

    # inputs that hint camera capture
    for inp in soup.find_all("input"):
        accept = (inp.get("accept") or "").lower()
        capture = inp.get("capture")
        if "image" in accept and (capture is not None or "camera" in accept):
            findings["camera_patterns"].append("file_input_capture")

    # simple webrtc signatures
    webrtc_sigs = [r"RTCPeerConnection", r"createOffer\s*\(", r"setRemoteDescription", r"addIceCandidate"]
    for pat in webrtc_sigs:
        if re.search(pat, js_text, re.I):
            findings["webrtc_signatures"].append(pat)

    return findings

def whois_age_days(domain):
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not cd:
            return None
        delta = datetime.utcnow() - cd
        return delta.days
    except Exception:
        return None

def resolve_ips(host):
    try:
        answers = dns.resolver.resolve(host, "A")
        return [a.to_text() for a in answers]
    except Exception:
        return []

def score_url(u, html_findings, tls_ok, tls_err, whois_days, dynamic_flags=None):
    score = 0
    reasons = []
    parsed = urllib.parse.urlparse(u)
    host = parsed.hostname or ""
    if len(u) > 120:
        score += WEIGHTS["long_url"]; reasons.append("long_url")
    if host_is_ip(host):
        score += WEIGHTS["ip_in_host"]; reasons.append("ip_host")
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += WEIGHTS["suspicious_tld"]; reasons.append("suspicious_tld"); break
    if parsed.scheme != "https":
        score += WEIGHTS["no_https"]; reasons.append("no_https")
    else:
        if tls_ok is False:
            score += WEIGHTS["invalid_cert"]; reasons.append("invalid_cert")
    if whois_days is not None and whois_days < 90:
        score += WEIGHTS["whois_recent"]; reasons.append("young_domain")
    if any(host.endswith(s) for s in SHORTENERS):
        score += WEIGHTS["shortened"]; reasons.append("shortened_url")

    if html_findings:
        if html_findings.get("forms"):
            for action in html_findings["forms"]:
                a_host = urllib.parse.urlparse(action).hostname or ""
                if a_host and a_host != host:
                    score += WEIGHTS["form_exfil"]; reasons.append("form_exfil"); break
        if html_findings.get("hidden_inputs",0) > 3:
            score += WEIGHTS["hidden_inputs"]; reasons.append("many_hidden_inputs")
        if html_findings.get("meta_refresh"):
            score += WEIGHTS["meta_refresh"]; reasons.append("meta_refresh")
        if html_findings.get("suspicious_js",0) > 0:
            score += WEIGHTS["suspicious_js"]; reasons.append("suspicious_js")
        if html_findings.get("camera_patterns"):
            score += WEIGHTS["camera_patterns"]; reasons.append("static_camera_patterns")
        if html_findings.get("iframe_allow_camera"):
            score += WEIGHTS["iframe_allow_camera"]; reasons.append("iframe_allows_camera")
        if html_findings.get("webrtc_signatures"):
            score += WEIGHTS["web_rtc"]; reasons.append("webrtc_signatures")
        if html_findings.get("geolocation_patterns"):
            score += WEIGHTS["dynamic_location_call"]; reasons.append("static_geolocation_patterns")
        if html_findings.get("keystroke_patterns"):
            score += WEIGHTS["keystroke_listener"]; reasons.append("static_keystroke_patterns")
        if html_findings.get("canvas_usage"):
            score += WEIGHTS["canvas_fp"]; reasons.append("canvas_usage")
        if html_findings.get("public_ip_calls"):
            score += WEIGHTS["public_ip_call"]; reasons.append("public_ip_calls_static")

    if dynamic_flags:
        if dynamic_flags.get("camera_requested"):
            score += WEIGHTS["dynamic_camera_call"]; reasons.append("dynamic_camera_call")
        if dynamic_flags.get("microphone_requested"):
            score += WEIGHTS["dynamic_mic_call"]; reasons.append("dynamic_mic_call")
        if dynamic_flags.get("location_requested"):
            score += WEIGHTS["dynamic_location_call"]; reasons.append("dynamic_location_call")
        if dynamic_flags.get("key_event_listeners"):
            score += WEIGHTS["keystroke_listener"]; reasons.append("dynamic_key_listeners")
        if dynamic_flags.get("websocket_suspicious"):
            score += WEIGHTS["websocket_exfil"]; reasons.append("websocket_exfil")
        if dynamic_flags.get("fetch_xhr_suspicious"):
            score += WEIGHTS["fetch_xhr_exfil"]; reasons.append("fetch_xhr_exfil")
        if dynamic_flags.get("canvas_fp_attempt"):
            score += WEIGHTS["canvas_fp"]; reasons.append("dynamic_canvas_fp")
        if dynamic_flags.get("rtcp_stun_detected"):
            score += WEIGHTS["web_rtc"]; reasons.append("rtcp_stun_detected")
        if dynamic_flags.get("public_ip_detected"):
            score += WEIGHTS["public_ip_call"]; reasons.append("public_ip_dynamic")
        if dynamic_flags.get("navigator_fingerprint_attempt"):
            score += WEIGHTS["navigator_fingerprint"]; reasons.append("navigator_fingerprint_attempt")

    return score, reasons

def classify(score):
    if score >= 10:
        return "likely-malicious"
    elif score >= 5:
        return "suspicious"
    else:
        return "safe"

# --- Playwright dynamic check with richer instrumentation ---
def dynamic_check_playwright(url, timeout=12):
    """
    Launch Playwright, instrument page BEFORE load to override/observe:
    - navigator.mediaDevices.getUserMedia
    - navigator.geolocation.getCurrentPosition/watchPosition
    - navigator.permissions.query
    - RTCPeerConnection constructor to inspect iceServers (STUN)
    - fetch and XMLHttpRequest to inspect destinations and payloads (for keywords)
    - WebSocket constructor to inspect messages sent
    - addEventListener and element.onkeydown/keypress to detect key listeners
    - HTMLCanvasElement.toDataURL / getContext to detect fingerprinting
    This code ONLY observes and sets flags; it does not exfiltrate any data.
    """
    flags = {
        "camera_requested": False,
        "microphone_requested": False,
        "location_requested": False,
        "permission_queries": [],
        "key_event_listeners": False,
        "websocket_suspicious": False,
        "fetch_xhr_suspicious": False,
        "canvas_fp_attempt": False,
        "rtcp_stun_detected": False,
        "public_ip_detected": False,
        "navigator_fingerprint_attempt": False,
        "console_logs": [],
        "error": None
    }
    if not USE_PLAYWRIGHT:
        flags["error"] = "playwright-not-installed"
        return flags

    injection = r"""
    (function(){
      // safe guard
      if (window.__linkguard_injected) return;
      window.__linkguard_injected = true;
      window.__linkguard_flags = {
        camera_requested:false, microphone_requested:false, location_requested:false,
        permission_queries:[], key_event_listeners:false, websocket_suspicious:false,
        fetch_xhr_suspicious:false, canvas_fp_attempt:false, rtcp_stun_detected:false,
        public_ip_detected:false, navigator_fingerprint_attempt:false
      };

      // helper: check payload/content for sensitive keywords
      function suspicious_text(s){
        if(!s) return false;
        try{
          var lowered = (typeof s === 'string') ? s.toLowerCase() : JSON.stringify(s).toLowerCase();
          var keys = ['password','passwd','pwd','creditcard','ccnum','ssn','social','token','secret','key','keystroke','keystrokes','camera','microphone','microphone','location','geolocation','sysinfo','fingerprint','navigator','platform','useragent','user-agent'];
          for(var i=0;i<keys.length;i++){
            if(lowered.indexOf(keys[i]) !== -1) return true;
          }
        } catch(e){ return false; }
        return false;
      }

      // override navigator.mediaDevices.getUserMedia
      try{
        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia){
          const origGet = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
          navigator.mediaDevices.getUserMedia = function(constraints){
            try{
              var cstr = JSON.stringify(constraints || {});
              window.__linkguard_flags.camera_requested = window.__linkguard_flags.camera_requested || (cstr.indexOf('video')!==-1);
              window.__linkguard_flags.microphone_requested = window.__linkguard_flags.microphone_requested || (cstr.indexOf('audio')!==-1);
            }catch(e){}
            // Do not call original to avoid requesting real hardware — return rejected promise to be safe
            return Promise.reject(new Error('LinkGuard-intercepted-getUserMedia'));
          };
        }
      } catch(e){}

      // legacy getUserMedia
      try{
        if (navigator.getUserMedia){
          navigator.getUserMedia = function(){ window.__linkguard_flags.camera_requested=true; return; };
        }
      } catch(e){}

      // override geolocation
      try{
        if (navigator.geolocation){
          const origGetGeo = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
          navigator.geolocation.getCurrentPosition = function(success, error, opts){
            window.__linkguard_flags.location_requested = true;
            if (typeof error === 'function') error(new Error('LinkGuard-intercepted-geolocation'));
            return;
          };
          navigator.geolocation.watchPosition = function(){ window.__linkguard_flags.location_requested = true; return -1; };
        }
      } catch(e){}

      // Permissions API
      try{
        if (navigator.permissions && navigator.permissions.query){
          const origQuery = navigator.permissions.query.bind(navigator.permissions);
          navigator.permissions.query = function(params){
            try{
              if(params && params.name) window.__linkguard_flags.permission_queries.push(params.name);
              // Forward to original to retain behavior
            }catch(e){}
            return origQuery(params);
          };
        }
      } catch(e){}

      // RTCPeerConnection wrapper to detect STUN servers in iceServers
      try{
        const OrigPC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
        if (OrigPC){
          function WrappedPC(config){
            try{
              if(config && config.iceServers){
                try{
                  var s = JSON.stringify(config.iceServers);
                  // detect stun/turn endpoints (likely IP exfil via STUN)
                  if(/stun:|turn:|stuns:|stuns:/.test(s)){
                    window.__linkguard_flags.rtcp_stun_detected = true;
                    if(/(api\.ipify|icanhazip|ident\.me|ifconfig\.me|ipinfo\.io)/.test(s)) window.__linkguard_flags.public_ip_detected = true;
                  }
                }catch(e){}
              }
            }catch(e){}
            return new OrigPC(config);
          }
          // copy prototype
          WrappedPC.prototype = OrigPC.prototype;
          window.RTCPeerConnection = WrappedPC;
        }
      } catch(e){}

      // XMLHttpRequest wrapper
      try{
        const OrigXHR = window.XMLHttpRequest;
        function XHRProxy(){
          const x = new OrigXHR();
          let _url = null;
          let _send = x.send;
          x.open = function(method, url){
            try{ _url = url; }catch(e){}
            return OrigXHR.prototype.open.apply(x, arguments);
          };
          x.send = function(body){
            try{
              var c = '';
              if(typeof body === 'string') c = body;
              else if (body && body.constructor && body.constructor.name === 'FormData'){
                // inspect first entries (best-effort)
                try{
                  var arr = [];
                  body.forEach(function(v,k){ arr.push(k+':'+v); });
                  c = arr.join(' ');
                } catch(e){}
              } else {
                try { c = JSON.stringify(body||''); } catch(e){}
              }
              if(suspicious_text(_url) || suspicious_text(c)) window.__linkguard_flags.fetch_xhr_suspicious = true;
              // detect public ip endpoints
              if(_url && /api\.ipify|icanhazip|ident\.me|ifconfig\.me|ipinfo\.io/.test(_url)) window.__linkguard_flags.public_ip_detected = true;
            }catch(e){}
            return _send.apply(x, arguments);
          };
          return x;
        }
        window.XMLHttpRequest = XHRProxy;
      } catch(e){}

      // fetch wrapper
      try{
        const origFetch = window.fetch.bind(window);
        window.fetch = function(input, init){
          try{
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            var body = init && init.body ? init.body : null;
            if(suspicious_text(url) || suspicious_text(body)) window.__linkguard_flags.fetch_xhr_suspicious = true;
            if(url && /api\.ipify|icanhazip|ident\.me|ifconfig\.me|ipinfo\.io/.test(url)) window.__linkguard_flags.public_ip_detected = true;
          } catch(e){}
          return origFetch(input, init);
        };
      } catch(e){}

      // WebSocket wrapper
      try{
        const OrigWS = window.WebSocket;
        function WSProxy(url){
          const ws = new OrigWS(url);
          const origSend = ws.send;
          ws.send = function(data){
            try{
              if(suspicious_text(url) || suspicious_text(data)) window.__linkguard_flags.websocket_suspicious = true;
            }catch(e){}
            return origSend.apply(ws, arguments);
          };
          // detect connection to public ip endpoints
          try{
            if(url && /api\.ipify|icanhazip|ident\.me|ifconfig\.me|ipinfo\.io/.test(url)) window.__linkguard_flags.public_ip_detected = true;
          }catch(e){}
          return ws;
        }
        window.WebSocket = WSProxy;
      } catch(e){}

      // AddEventListener wrapper to detect key event listeners
      try{
        const origAdd = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, opts){
          try{
            if(typeof type === 'string' && (/key(down|up)|keypress/i).test(type)) window.__linkguard_flags.key_event_listeners = true;
            // check inline attribute attach too
          }catch(e){}
          return origAdd.apply(this, arguments);
        };
        // detect inline onkeydown/onkeypress attributes by scanning elements when DOMContent loaded
        document.addEventListener('DOMContentLoaded', function(){
          try{
            var els = document.querySelectorAll('[onkeydown],[onkeypress],[onkeyup]');
            if(els && els.length > 0) window.__linkguard_flags.key_event_listeners = true;
          }catch(e){}
        });
      } catch(e){}

      // Canvas fingerprint detection (toDataURL interception)
      try{
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(){
          try{ window.__linkguard_flags.canvas_fp_attempt = true; }catch(e){}
          return origToDataURL.apply(this, arguments);
        };
        const origGetCtx = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type){
          try{ if(/2d|webgl/i.test(type)) window.__linkguard_flags.canvas_fp_attempt = true; }catch(e){}
          return origGetCtx.apply(this, arguments);
        };
      } catch(e){}

      // Navigator fingerprint attempt detection - conservative: override some getters to mark if accessed via JS using custom getters
      try{
        function markNavigatorProp(prop){
          try{
            const orig = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
            if(!orig || !orig.get) return;
            Object.defineProperty(navigator, prop, {
              get: function(){
                try{ window.__linkguard_flags.navigator_fingerprint_attempt = true; }catch(e){}
                return orig.get.apply(this);
              },
              configurable: true
            });
          }catch(e){}
        }
        ['userAgent','platform','language','hardwareConcurrency','deviceMemory'].forEach(markNavigatorProp);
      } catch(e){}

    })();
    """

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox","--disable-web-security"])
            context = browser.new_context()
            page = context.new_page()
            page.on("console", lambda msg: flags["console_logs"].append(f"{msg.type}: {msg.text}"))
            page.add_init_script(injection)
            try:
                page.goto(url, timeout=timeout*1000)
            except PWTimeout:
                # continue; injection already set
                pass
            except Exception:
                pass
            # allow some time for dynamic scripts to run
            try:
                page.wait_for_timeout(3000)
            except Exception:
                pass

            # read flags safely
            try:
                # use evaluate in a safe manner
                res = page.evaluate("() => { try { return window.__linkguard_flags || {}; } catch(e) { return {}; } }")
                # normalize expected keys
                for k in flags.keys():
                    if k in res:
                        flags[k] = res[k]
                # 'permission_queries' and console logs may be present
                if isinstance(res.get('permission_queries', None), list):
                    flags['permission_queries'] = res.get('permission_queries', [])
            except Exception as e:
                flags["error"] = str(e)

            try:
                browser.close()
            except Exception:
                pass
    except Exception as e:
        flags["error"] = str(e)
    return flags

# --- main per-URL analysis ---
def analyze_one(url, timeout=12, use_dynamic=False):
    u = norm_url(url)
    if not u:
        return None
    parsed = urllib.parse.urlparse(u)
    host = parsed.hostname or ""
    # whois age
    whois_days = None
    try:
        t = tldextract.extract(host)
        domain = f"{t.domain}.{t.suffix}" if t.suffix else t.domain
        whois_days = whois_age_days(domain)
    except Exception:
        whois_days = None
    tls_ok, tls_err = check_tls(u, timeout=timeout)
    status, html, headers = fetch_page(u, timeout=timeout)
    html_findings = analyze_html(html, u)
    dynamic_flags = None
    if use_dynamic:
        dynamic_flags = dynamic_check_playwright(u, timeout=timeout)
    score, reasons = score_url(u, html_findings, tls_ok, tls_err, whois_days, dynamic_flags)
    ips = resolve_ips(host)
    return {
        "url": u,
        "host": host,
        "ips": ips,
        "status_code": status,
        "tls_ok": tls_ok,
        "tls_err": tls_err,
        "whois_age_days": whois_days,
        "html_findings": html_findings,
        "dynamic_flags": dynamic_flags,
        "score": score,
        "reasons": reasons,
        "classification": classify(score),
        "timestamp": datetime.utcnow().isoformat()+"Z"
    }

def main():
    args = parse_args()
    targets = []
    if args.file:
        with open(args.file, "r") as f:
            targets = [l.strip() for l in f if l.strip()]
    elif args.target == "-" or (not args.target and not sys.stdin.isatty()):
        targets = [l.strip() for l in sys.stdin if l.strip()]
    elif args.target:
        targets = [args.target.strip()]
    else:
        print("No target provided. See help.")
        sys.exit(1)

    if args.dynamic and not USE_PLAYWRIGHT:
        print("[!] --dynamic requested but Playwright is not installed or importable. Install with: pip install playwright && python -m playwright install")
        args.dynamic = False

    results = []
    for t in targets:
        print(f"[+] Scanning {t}")
        res = analyze_one(t, timeout=args.timeout, use_dynamic=args.dynamic)
        results.append(res)
        if not args.json:
            print(f"URL: {res['url']}")
            print(f"Classification: {res['classification']} (score {res['score']})")
            print("Reasons:", ", ".join(res['reasons']) or "none")
            print(f"Status: {res['status_code']}, TLS OK: {res['tls_ok']}, WHOIS age: {res['whois_age_days']}")
            if res['html_findings']['forms']:
                print("Sample forms:", res['html_findings']['forms'][:3])
            if res.get('dynamic_flags'):
                print("Dynamic flags summary:")
                for k,v in res['dynamic_flags'].items():
                    # only show truthy and console_logs/errors
                    if k == 'console_logs' and v:
                        print("  console_logs:", v[:6])
                    elif k == 'error' and v:
                        print("  error:", v)
                    elif k != 'console_logs' and k != 'error' and v:
                        print(f"  {k}: {v}")
            print("-"*80)
    if args.json:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
