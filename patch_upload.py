with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the upload pane and replace it
start_marker = '        <!-- UPLOAD & EXTRACT -->'
end_marker = '        <!-- GLOBAL DASHBOARD -->'

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx == -1 or end_idx == -1:
    print(f"ERROR: markers not found. start={start_idx}, end={end_idx}")
    # Try to find pane-upload
    idx = content.find('id="pane-upload"')
    print(f"pane-upload found at: {idx}")
    print(content[idx-50:idx+200])
    exit(1)

new_section = '''        <!-- UPLOAD & EXTRACT -->
        <div class="pane" id="pane-upload">

          <!-- BULK APK UPLOAD HERO -->
          <div style="background:linear-gradient(145deg,rgba(255,34,68,.08),rgba(0,229,255,.04));border:2px solid rgba(255,34,68,.28);border-radius:var(--r20);padding:22px;margin-bottom:18px;position:relative;overflow:hidden;">
            <div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--red),var(--cyan),var(--red2),var(--cyan2));background-size:300%;animation:shimmer 2s linear infinite;border-radius:var(--r20) var(--r20) 0 0;"></div>
            <div style="display:flex;align-items:center;gap:14px;margin-bottom:16px;">
              <div style="font-size:36px;filter:drop-shadow(0 0 14px rgba(255,34,68,.6));animation:fireFlicker 2s ease-in-out infinite;">&#x1F525;</div>
              <div>
                <div style="font-size:20px;font-weight:700;font-family:Orbitron,monospace;margin-bottom:2px;color:var(--red2);">Bulk APK Upload</div>
                <div style="font-size:12px;color:var(--sub);">Drop multiple APKs, JSONs, DBs at once. All extracted and merged into Global Dashboard automatically.</div>
              </div>
            </div>
            <div class="drop-zone" id="bulkDropZone" style="border-color:rgba(255,34,68,.35);background:rgba(255,34,68,.03);padding:36px 24px;margin-bottom:12px;" onclick="document.getElementById(\'bulkFileInput\').click()">
              <input type="file" id="bulkFileInput" multiple onchange="queueFiles(this.files)" style="position:absolute;inset:0;opacity:0;cursor:pointer;"/>
              <div style="font-size:60px;margin-bottom:10px;animation:float 3s ease-in-out infinite;filter:drop-shadow(0 0 18px rgba(255,34,68,.5));">&#x1F4E6;</div>
              <div style="font-size:20px;font-weight:700;font-family:Orbitron,monospace;margin-bottom:6px;color:var(--red2);">DROP APKs / FILES HERE</div>
              <div style="font-size:12px;color:var(--sub);margin-bottom:10px;">Select any number of files — added to queue below</div>
              <div style="display:flex;gap:5px;flex-wrap:wrap;justify-content:center;">
                <span style="background:rgba(255,34,68,.12);border:1px solid rgba(255,34,68,.25);color:var(--red2);font-size:9px;font-weight:700;padding:3px 9px;border-radius:20px;font-family:JetBrains Mono,monospace;">.APK</span>
                <span style="background:rgba(0,229,255,.07);border:1px solid var(--border);color:var(--cyan2);font-size:9px;font-weight:700;padding:3px 9px;border-radius:20px;font-family:JetBrains Mono,monospace;">.JSON</span>
                <span style="background:rgba(0,229,255,.07);border:1px solid var(--border);color:var(--sub);font-size:9px;font-weight:700;padding:3px 9px;border-radius:20px;">.TXT .DB .ZIP .XML</span>
                <span style="background:rgba(255,153,0,.1);border:1px solid rgba(255,153,0,.2);color:var(--amber);font-size:9px;font-weight:700;padding:3px 9px;border-radius:20px;">ANY SIZE &#x221E;</span>
              </div>
            </div>
            <div id="uploadQueue" style="display:none;margin-bottom:12px;">
              <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--sub);margin-bottom:8px;">Queue: <span id="queueCount">0</span> files ready</div>
              <div id="queueList" style="display:flex;flex-direction:column;gap:5px;max-height:180px;overflow-y:auto;"></div>
              <div style="display:flex;gap:8px;margin-top:10px;">
                <button onclick="processQueue()" style="flex:1;padding:13px;border:none;border-radius:10px;color:#020810;font-family:Orbitron,monospace;font-size:13px;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--red),#cc0022);box-shadow:0 4px 24px rgba(255,34,68,.35);letter-spacing:.5px;transition:all .18s;">&#x1F525; EXTRACT ALL &rarr; DASHBOARD</button>
                <button class="fb-btn" style="background:var(--red-dim);border-color:var(--rborder);color:var(--red2);" onclick="clearQueue()">&#x2715; Clear</button>
              </div>
            </div>
            <div id="globalProgress" style="display:none;background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;">
              <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                <div style="font-size:11px;font-weight:700;" id="globalProgLabel">Extracting...</div>
                <div style="font-size:11px;color:var(--sub);" id="globalProgCount">0 / 0</div>
              </div>
              <div style="height:5px;background:var(--bg3);border-radius:5px;overflow:hidden;">
                <div id="globalProgFill" style="height:100%;background:linear-gradient(90deg,var(--red),var(--cyan));border-radius:5px;transition:width .4s ease;width:0%;"></div>
              </div>
              <div style="font-size:10px;color:var(--sub);margin-top:6px;" id="globalProgFile">Waiting...</div>
            </div>
          </div>

          <!-- SINGLE FILE UPLOAD -->
          <div class="upload-section">
            <div class="sec-hdr">Single File Quick Upload</div>
            <div class="drop-zone" id="dropZone" onclick="document.getElementById(\'fileInput\').click()">
              <input type="file" id="fileInput" multiple onchange="handleFiles(this.files)" style="position:absolute;inset:0;opacity:0;cursor:pointer;"/>
              <div class="dz-icon">&#x1F4C2;</div>
              <div class="dz-title">Drop File Here</div>
              <div class="dz-sub">or click to browse</div>
              <div class="dz-hint">APK, JSON, TXT, DB, ZIP — any format, any size</div>
            </div>
            <div class="upload-progress" id="uploadProgress">
              <div class="up-name" id="upName">Uploading...</div>
              <div class="progress-bar"><div class="progress-fill" id="progFill"></div></div>
              <div class="up-status" id="upStatus">Preparing...</div>
            </div>
            <div class="ext-results" id="extResults"></div>
          </div>
        </div>

        '''

content = content[:start_idx] + new_section + content[end_idx:]

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("SUCCESS - upload section replaced")
print(f"New file size: {len(content)} bytes")
