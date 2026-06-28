with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add bulk drag events after the dropZone listener block
old_dz_listeners = "const dropZone=document.getElementById('dropZone');\ndropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('drag-over');});\ndropZone.addEventListener('dragleave',()=>dropZone.classList.remove('drag-over'));\ndropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('drag-over');handleFiles(e.dataTransfer.files);});\n\nasync function handleFiles(files){"

new_dz_listeners = """const dropZone=document.getElementById('dropZone');
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('drag-over');});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('drag-over');handleFiles(e.dataTransfer.files);});

// Bulk drop zone
const bulkDZ=document.getElementById('bulkDropZone');
if(bulkDZ){
  bulkDZ.addEventListener('dragover',e=>{e.preventDefault();bulkDZ.classList.add('drag-over');});
  bulkDZ.addEventListener('dragleave',()=>bulkDZ.classList.remove('drag-over'));
  bulkDZ.addEventListener('drop',e=>{e.preventDefault();bulkDZ.classList.remove('drag-over');queueFiles(e.dataTransfer.files);});
}

// ============================================================
// BULK QUEUE SYSTEM
// ============================================================
let fileQueue = [];

function queueFiles(files) {
  const arr = Array.from(files);
  fileQueue.push(...arr);
  renderQueue();
  showToast(arr.length + ' file(s) added to queue');
}

function renderQueue() {
  const qDiv = document.getElementById('uploadQueue');
  const qList = document.getElementById('queueList');
  const qCount = document.getElementById('queueCount');
  if (!fileQueue.length) { qDiv.style.display = 'none'; return; }
  qDiv.style.display = 'block';
  qCount.textContent = fileQueue.length;
  qList.innerHTML = fileQueue.map((f, i) => `
    <div style="display:flex;align-items:center;gap:8px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 12px;" id="qi${i}">
      <span style="font-size:14px">${f.name.endsWith('.apk') ? '📦' : f.name.endsWith('.json') ? '📄' : f.name.endsWith('.db') || f.name.endsWith('.sqlite') ? '🗄️' : '📂'}</span>
      <span style="flex:1;font-size:11px;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.name}</span>
      <span style="font-size:9px;color:var(--sub);">${formatBytes(f.size)}</span>
      <span id="qiStatus${i}" style="font-size:9px;font-weight:700;color:var(--sub);">Queued</span>
      <span onclick="removeFromQueue(${i})" style="cursor:pointer;color:var(--dim);font-size:12px;padding:2px 6px;background:var(--red-dim);border-radius:4px;border:1px solid var(--rborder);">✕</span>
    </div>`).join('');
}

function removeFromQueue(i) {
  fileQueue.splice(i, 1);
  renderQueue();
}

function clearQueue() {
  fileQueue = [];
  renderQueue();
  document.getElementById('globalProgress').style.display = 'none';
}

async function processQueue() {
  if (!fileQueue.length) { showToast('Queue is empty'); return; }
  const total = fileQueue.length;
  const prog = document.getElementById('globalProgress');
  const fill = document.getElementById('globalProgFill');
  const label = document.getElementById('globalProgLabel');
  const countEl = document.getElementById('globalProgCount');
  const fileEl = document.getElementById('globalProgFile');
  prog.style.display = 'block';
  let done = 0;
  for (let i = 0; i < fileQueue.length; i++) {
    const f = fileQueue[i];
    const statusEl = document.getElementById('qiStatus' + i);
    if (statusEl) { statusEl.textContent = 'Uploading...'; statusEl.style.color = 'var(--cyan)'; }
    label.textContent = 'Extracting...';
    countEl.textContent = (i + 1) + ' / ' + total;
    fileEl.textContent = f.name;
    fill.style.width = Math.round(((i) / total) * 100) + '%';
    try {
      const fd = new FormData();
      fd.append('file', f);
      const r = await fetch(API + '/api/upload', { method: 'POST', body: fd });
      const data = await r.json();
      done++;
      if (statusEl) { statusEl.textContent = '\u2713 Done'; statusEl.style.color = 'var(--mint)'; }
    } catch (e) {
      if (statusEl) { statusEl.textContent = '\u2717 Error'; statusEl.style.color = 'var(--red)'; }
    }
    fill.style.width = Math.round(((i + 1) / total) * 100) + '%';
  }
  label.textContent = '\u2713 Complete! ' + done + '/' + total + ' files extracted';
  fileEl.textContent = 'Done. Check Global Dashboard.';
  fill.style.width = '100%';
  refreshDashboard();
  showToast(done + ' files extracted! Dashboard updated.');
  // Clear queue after success
  setTimeout(() => { fileQueue = []; renderQueue(); }, 3000);
}

async function handleFiles(files){"""

if old_dz_listeners in content:
    content = content.replace(old_dz_listeners, new_dz_listeners, 1)
    print("SUCCESS: bulk queue JS injected")
else:
    print("ERROR: target not found in content")
    # Find the spot manually
    idx = content.find("async function handleFiles(files){")
    print(f"handleFiles found at: {idx}")
    if idx > 0:
        print(content[idx-300:idx+50])

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print(f"File size: {len(content)} bytes")
