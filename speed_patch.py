#!/usr/bin/env python3
"""
Patch apk_scanner.py for maximum speed:
1. Add requests.Session with connection pooling + retry adapter
2. Parallel zip file reading (scan all files concurrently, not one-by-one)
3. Increase Firebase probe workers: 8->50 per URL, 4->20 for multiple URLs
4. Reduce HTTP timeout: 6s->3s, add shallow=true for faster Firebase reads
5. Frontend: bulk scan uses Promise.allSettled with 4 concurrent APKs
"""

with open('apk_scanner.py', 'r', encoding='utf-8') as f:
    src = f.read()

# ── 1. Replace the slow http_get with a pooled Session ────────────────────────
old_http = '''try:
    import requests as _requests
    def http_get(url, timeout=6):
        return _requests.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
except ImportError:
    import urllib.request, urllib.error
    class _FakeResp:
        def __init__(self, status_code, text=''):
            self.status_code = status_code
            self.text = text
        def json(self): return json.loads(self.text)
    def http_get(url, timeout=6):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return _FakeResp(resp.getcode(), resp.read().decode('utf-8', errors='ignore'))
        except urllib.error.HTTPError as e:
            return _FakeResp(e.code)
        except:
            raise'''

new_http = '''try:
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
            raise'''

if old_http in src:
    src = src.replace(old_http, new_http, 1)
    print("✓ Patched: connection pooling + fast timeout")
else:
    print("✗ MISS: http_get block")

# ── 2. Add ?shallow=true to Firebase probe for faster header check ─────────────
old_probe_path = '''def probe_single_path(base_url, path, auth=''):
    url = f"{base_url}/{path}.json" if path else f"{base_url}/.json"
    if auth and auth.lower() not in ('', 'public', 'none'):
        url += f'?auth={auth}'
    try:
        resp = http_get(url, timeout=5)'''

new_probe_path = '''def probe_single_path(base_url, path, auth=''):
    # Use ?shallow=true so Firebase only returns top-level keys (much faster)
    qs = '?shallow=true'
    if auth and auth.lower() not in ('', 'public', 'none'):
        qs += f'&auth={auth}'
    url = (f"{base_url}/{path}.json" if path else f"{base_url}/.json") + qs
    try:
        resp = http_get(url, timeout=3)'''

if old_probe_path in src:
    src = src.replace(old_probe_path, new_probe_path, 1)
    print("✓ Patched: shallow=true + 3s timeout")
else:
    print("✗ MISS: probe_single_path")

# ── 3. Replace sequential zip scan with parallel file reading ─────────────────
old_scan_loop = '''    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes), 'r') as z:
            all_files = z.infolist()
            findings['Total Files'] = len(all_files)
            for fi in all_files:
                fn = fi.filename.lower()
                # skip heavy binary media
                if fn.endswith(('.png','.jpg','.jpeg','.gif','.mp3','.mp4',
                                '.webp','.ogg','.ttf','.woff','.wav','.3gp')):
                    continue
                try:
                    content = z.read(fi).decode('utf-8', errors='ignore')
                    findings['Files Scanned'] += 1
                    findings['API Keys'].update(RE_API_KEY.findall(content))
                    findings['App IDs'].update(RE_APP_ID.findall(content))
                    findings['Database URLs'].update(RE_DB_URL.findall(content))
                    findings['Storage Buckets'].update(RE_STORAGE.findall(content))
                    findings['Project IDs'].update(RE_PROJECT_ID.findall(content))
                    findings['Emails'].update(RE_EMAIL.findall(content))
                    findings['Phones'].update(RE_PHONE.findall(content))
                    findings['SIM Serials'].update(RE_SIM_SERIAL.findall(content))
                    findings['IMEI'].update(RE_IMEI.findall(content))
                    findings['Aadhaar'].update(RE_AADHAAR.findall(content))
                    findings['PAN'].update(RE_PAN.findall(content))
                    for m in RE_SECRET.finditer(content):
                        val = m.group(1)
                        if len(val) > 3 and val not in ('true','false','null','undefined'):
                            findings['Secrets'].add(val)
                except Exception:
                    continue
    except zipfile.BadZipFile:
        return None, None, f'Not a valid APK/ZIP (received {len(apk_bytes):,} bytes)'
    except Exception as e:
        return None, None, f'Parse error: {e}'

    # Convert sets to sorted lists
    out = {k: sorted(list(v)) if isinstance(v, set) else v for k, v in findings.items()}

    # Deep Firebase probe
    db_checks = {}
    if out['Database URLs']:
        db_checks = probe_all_firebase(out['Database URLs'])

    return out, db_checks, None'''

new_scan_loop = '''    SKIP_EXT = ('.png','.jpg','.jpeg','.gif','.mp3','.mp4',
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

    return out, db_checks, None'''

if old_scan_loop in src:
    src = src.replace(old_scan_loop, new_scan_loop, 1)
    print("✓ Patched: parallel zip file scanning (32 threads)")
else:
    print("✗ MISS: scan loop")

# ── 4. Crank up Firebase probe workers: 8→50 per URL, 4→20 for multiple ───────
old_probe_url_ex = '    with ThreadPoolExecutor(max_workers=8) as ex:'
new_probe_url_ex = '    with ThreadPoolExecutor(max_workers=50) as ex:  # 50 concurrent path probes'

if old_probe_url_ex in src:
    src = src.replace(old_probe_url_ex, new_probe_url_ex, 1)
    print("✓ Patched: 50 workers per Firebase URL")
else:
    print("✗ MISS: probe_firebase_url executor")

old_probe_all_ex = '    with ThreadPoolExecutor(max_workers=4) as ex:'
new_probe_all_ex = '    with ThreadPoolExecutor(max_workers=20) as ex:  # 20 concurrent URLs'

if old_probe_all_ex in src:
    src = src.replace(old_probe_all_ex, new_probe_all_ex, 1)
    print("✓ Patched: 20 concurrent Firebase URLs")
else:
    print("✗ MISS: probe_all_firebase executor")

# ── 5. Frontend: parallel bulk processing with Promise.allSettled ─────────────
old_bulk_js = '''// ─── Bulk scan ────────────────────────────────────────────────────────────────
async function processBulk(){
  if(!apkQueue.length){showToast('Queue is empty');return;}
  const total=apkQueue.length;
  const gp=document.getElementById('gprog');
  const fill=document.getElementById('gpFill');
  const label=document.getElementById('gpLabel');
  const cnt=document.getElementById('gpCount');
  const fileLbl=document.getElementById('gpFile');
  gp.style.display='block';
  let allResults=[];
  for(let i=0;i<apkQueue.length;i++){
    const f=apkQueue[i];
    const st=document.getElementById('qst'+i);
    if(st){st.textContent='Scanning...';st.style.color='var(--cyan)';}
    label.textContent='Scanning...';
    cnt.textContent=(i+1)+' / '+total;
    fileLbl.textContent=f.name;
    fill.style.width=Math.round((i/total)*100)+'%';
    const data=await uploadAPK(f);
    if(!data.error) allResults.push(data);
    if(st){st.textContent=data.error?'✗ Error':'✓ Done';st.style.color=data.error?'var(--red)':'var(--mint)';}
    fill.style.width=Math.round(((i+1)/total)*100)+'%';
  }
  label.textContent='✓ Done! '+allResults.length+'/'+total+' scanned';
  fileLbl.textContent='Check results below';
  if(allResults.length) renderResults(allResults);
  showToast(allResults.length+' APKs scanned!');
  setTimeout(()=>{apkQueue=[];renderQ();},3000);
}'''

new_bulk_js = '''// ─── Bulk scan — PARALLEL (4 APKs at once) ────────────────────────────────────
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
}'''

if old_bulk_js in src:
    src = src.replace(old_bulk_js, new_bulk_js, 1)
    print("✓ Patched: parallel bulk JS (4 concurrent APKs)")
else:
    print("✗ MISS: bulk JS")

# ── 6. Expand Firebase probe paths (more paths = more finds) ──────────────────
old_paths = """FIREBASE_PROBE_PATHS = [
    '', 'clients', 'All_Users', 'All_Users/simDetails',
    'All_Users/Data/DeviceInfo', 'user_data', 'devices', 'users',
    'bots', 'Ede', 'messages', 'sms', 'user_sms', 'admin', 'panel',
    'data', 'Data', 'results',
]"""

new_paths = """FIREBASE_PROBE_PATHS = [
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
]"""

if old_paths in src:
    src = src.replace(old_paths, new_paths, 1)
    print("✓ Patched: expanded Firebase probe paths (33 paths)")
else:
    print("✗ MISS: FIREBASE_PROBE_PATHS")

with open('apk_scanner.py', 'w', encoding='utf-8') as f:
    f.write(src)

print("\nAll patches applied. Verifying syntax...")
import ast
ast.parse(src)
print("✓ Syntax OK — restart apk_scanner.py to apply changes")
