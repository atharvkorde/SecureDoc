const $ = (id) => document.getElementById(id);
let toastTimer;
const uploadedFiles = new Map();
let cachedActivity = [];
let activityFilter = 'all';
let verifyTab = 'rsa';

const VIEW_TITLES = {
  overview: 'Dashboard',
  rsa: 'RSA & Digital Signature',
  verify: 'Verify Document',
  integrity: 'Integrity Checker',
  authentication: 'HMAC Authentication',
  activity: 'Security Activity',
  settings: 'Settings',
};

const SEARCH_CATALOG = [
  { label: 'Dashboard Overview', tag: 'Overview', view: 'overview' },
  { label: 'Integrity Checker (SHA-256 & SHA-1)', tag: 'Practical 06', view: 'integrity' },
  { label: 'RSA Encryption & Decryption (OAEP/SHA-256)', tag: 'Practical 04', view: 'rsa', scrollTo: 'rsa-oaep-card' },
  { label: 'Digital Signature (RSA-PSS/SHA-256)', tag: 'Practical 04', view: 'rsa', scrollTo: 'rsa-pss-card' },
  { label: 'Verify Document (Signature / HMAC / Hash)', tag: 'Verification', view: 'verify' },
  { label: 'HMAC-SHA256 Authentication', tag: 'Practical 08', view: 'authentication' },
  { label: 'Security Activity Log', tag: 'Telemetry', view: 'activity' },
  { label: 'Settings & Security Policy', tag: 'System', view: 'settings' },
];

const MAX_FILE_BYTES = 10 * 1024 * 1024;
const TEXT_ENCODER = new TextEncoder();

function uint8ToBase64(bytes) {
  const chunkSize = 0x4000;
  const parts = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + chunkSize)));
  }
  return btoa(parts.join(''));
}

function validateFilename(name) {
  if (!name || typeof name !== 'string' || name.length > 255) {
    return 'Invalid file name.';
  }
  if (/[\x00/\\]|\.\./.test(name)) {
    return 'File name contains disallowed path characters.';
  }
  return null;
}

function documentPayload(id) {
  if (uploadedFiles.has(id)) {
    const fileEntry = uploadedFiles.get(id);
    return { document_base64: fileEntry.base64, filename: fileEntry.name };
  }
  return { document: text(id) };
}

function attachFileToTarget(targetId, file) {
  if (!file) return;
  const nameErr = validateFilename(file.name);
  if (nameErr) {
    toast(nameErr);
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    toast('Maximum file size is 10 MB.');
    return;
  }
  file.arrayBuffer().then((buffer) => {
    uploadedFiles.set(targetId, {
      name: file.name,
      size: file.size,
      base64: uint8ToBase64(new Uint8Array(buffer)),
    });
    $(targetId).value = `[Attached file: ${file.name} · ${file.size.toLocaleString()} bytes]`;
    const meta = $(targetId + '-meta');
    if (meta) meta.textContent = `Attached: ${file.name} (${file.size.toLocaleString()} bytes)`;
    toast(`Attached ${file.name} in browser memory.`);
  }).catch(() => toast('Could not read the selected file.'));
}

function clearTargetInput(targetId) {
  uploadedFiles.delete(targetId);
  $(targetId).value = '';
  const fileInput = document.querySelector(`[data-file-target="${targetId}"]`);
  if (fileInput) fileInput.value = '';
  const meta = $(targetId + '-meta');
  if (meta) meta.textContent = 'No file attached — type text below or select a file.';
}

document.querySelectorAll('[data-file-target]').forEach((input) => {
  input.addEventListener('change', () => {
    const file = input.files[0];
    if (!file) return;
    if (file.size > MAX_FILE_BYTES || validateFilename(file.name)) {
      attachFileToTarget(input.dataset.fileTarget, file);
      input.value = '';
      return;
    }
    attachFileToTarget(input.dataset.fileTarget, file);
  });
});

document.querySelectorAll('[data-dropzone]').forEach((zone) => {
  const targetId = zone.dataset.dropzone;
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer?.files?.[0];
    if (file) attachFileToTarget(targetId, file);
  });
});

document.querySelectorAll('.clear-target').forEach((btn) => {
  btn.addEventListener('click', () => clearTargetInput(btn.dataset.clearTarget));
});

document.querySelectorAll('textarea').forEach((area) => {
  area.addEventListener('input', () => {
    if (uploadedFiles.has(area.id)) {
      uploadedFiles.delete(area.id);
      const meta = $(area.id + '-meta');
      if (meta) meta.textContent = 'Switched to manual text input.';
    }
    if (area.value === '') {
      const fileInput = document.querySelector(`[data-file-target="${area.id}"]`);
      if (fileInput) fileInput.value = '';
      const meta = $(area.id + '-meta');
      if (meta) meta.textContent = 'No file attached — type text below or select a file.';
    }
  });
});

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

function showResult(id) {
  $(id).classList.remove('hidden');
}

function text(id) {
  return $(id).value;
}

function setStatus(id, message, ok) {
  const el = $(id);
  el.textContent = message;
  el.classList.remove('hidden', 'bad');
  if (!ok) el.classList.add('bad');
}

function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

async function api(path, data, method = 'POST') {
  const options = {
    method,
    cache: 'no-store',
    headers: {},
  };
  if (method !== 'GET') {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(data ?? {});
  }
  const response = await fetch('/api' + path, options);
  const result = await response.json().catch(() => ({ error: 'Unexpected server response.' }));
  if (!response.ok) {
    throw new Error(result.error || 'Request failed.');
  }
  return result;
}

function download(name, content, type = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function bindAction(id, fn, loadingText = 'Processing...') {
  const button = $(id);
  if (!button) return;
  button.addEventListener('click', async () => {
    if (button.disabled) return;
    const originalHtml = button.innerHTML;
    button.disabled = true;
    button.classList.add('is-loading');
    button.setAttribute('aria-busy', 'true');
    button.textContent = loadingText;
    try {
      await fn();
      await refreshTelemetry();
    } catch (e) {
      toast(e.message || 'Something went wrong.');
      await refreshTelemetry().catch(() => {});
    } finally {
      button.disabled = false;
      button.classList.remove('is-loading');
      button.removeAttribute('aria-busy');
      button.innerHTML = originalHtml;
    }
  });
}

/* Sidebar Drawer (Mobile & Tablet) */
function setDrawerOpen(open) {
  $('sidebar').classList.toggle('open', open);
  $('sidebar-backdrop').classList.toggle('open', open);
  $('menu-toggle').setAttribute('aria-expanded', open ? 'true' : 'false');
}

$('menu-toggle').addEventListener('click', () => {
  setDrawerOpen(!$('sidebar').classList.contains('open'));
});
$('sidebar-close').addEventListener('click', () => setDrawerOpen(false));
$('sidebar-backdrop').addEventListener('click', () => setDrawerOpen(false));
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    setDrawerOpen(false);
    $('notif-popover').classList.add('hidden');
    $('notif-btn').setAttribute('aria-expanded', 'false');
    $('search-results').classList.add('hidden');
  }
});

function navigate(view) {
  if (!VIEW_TITLES[view]) return;
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach((v) => {
    const active = v.dataset.view === view;
    v.classList.toggle('active', active);
    if (active) {
      v.setAttribute('aria-current', 'page');
    } else {
      v.removeAttribute('aria-current');
    }
  });
  $('view-' + view).classList.add('active');
  $('page-title').textContent = VIEW_TITLES[view];
  if (window.location.hash !== '#' + view) {
    history.replaceState(null, '', '#' + view);
  }
  setDrawerOpen(false);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('[data-view]').forEach((b) => {
  b.addEventListener('click', () => navigate(b.dataset.view));
});

document.querySelectorAll('[data-go]').forEach((b) => {
  b.addEventListener('click', (e) => {
    e.preventDefault();
    navigate(b.dataset.go);
    if (b.dataset.scrollTo) {
      const target = $(b.dataset.scrollTo);
      if (target) {
        requestAnimationFrame(() => target.scrollIntoView({ behavior: 'smooth', block: 'start' }));
      }
    }
  });
});

/* Clipboard & Masking */
async function copyToClipboard(value, okMessage = 'Copied to clipboard.') {
  try {
    await navigator.clipboard.writeText(value);
    toast(okMessage);
  } catch {
    const helper = document.createElement('textarea');
    helper.value = value;
    helper.setAttribute('readonly', '');
    helper.style.position = 'fixed';
    helper.style.opacity = '0';
    document.body.appendChild(helper);
    helper.select();
    document.execCommand('copy');
    helper.remove();
    toast(okMessage);
  }
}

document.querySelectorAll('[data-copy]').forEach((b) => {
  b.addEventListener('click', () => {
    const el = $(b.dataset.copy);
    if (!el.value) {
      toast('Nothing to copy yet.');
      return;
    }
    copyToClipboard(el.value);
  });
});

document.querySelectorAll('[data-copy-text]').forEach((b) => {
  b.addEventListener('click', () => {
    const el = $(b.dataset.copyText);
    if (!el.textContent.trim()) {
      toast('Nothing to copy yet.');
      return;
    }
    copyToClipboard(el.textContent.trim());
  });
});

document.querySelectorAll('[data-mask-target]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const target = $(btn.dataset.maskTarget);
    const nowMasked = target.classList.toggle('masked');
    btn.textContent = nowMasked ? (btn.textContent.includes('Key') ? 'Reveal Key' : 'Reveal') : 'Hide';
  });
});

/* Practical 04: RSA */
bindAction('rsa-generate', async () => {
  const r = await api('/rsa/keys', {});
  $('rsa-public').value = r.public_key;
  $('rsa-private').value = r.private_key;
  toast('RSA-2048 key pair generated. Keep the private key secret.');
}, 'Generating...');

$('rsa-clear-keys').addEventListener('click', () => {
  $('rsa-public').value = '';
  $('rsa-private').value = '';
  $('rsa-signature').value = '';
  $('rsa-cipher').value = '';
  $('rsa-plain').textContent = '';
  $('rsa-plain-result').classList.add('hidden');
  $('rsa-verify-result').classList.add('hidden');
  toast('RSA keys cleared from page memory.');
});

bindAction('rsa-encrypt', async () => {
  const r = await api('/rsa/encrypt', {
    public_key: text('rsa-public'),
    document: text('rsa-text'),
  });
  $('rsa-cipher').value = r.ciphertext;
  toast('Message encrypted with RSA-OAEP.');
}, 'Encrypting...');

bindAction('rsa-decrypt', async () => {
  const r = await api('/rsa/decrypt', {
    private_key: text('rsa-private'),
    ciphertext: text('rsa-cipher'),
  });
  $('rsa-plain').textContent = r.document ?? r.document_base64;
  showResult('rsa-plain-result');
  toast('Message decrypted.');
}, 'Decrypting...');

bindAction('rsa-sign', async () => {
  const r = await api('/rsa/sign', {
    private_key: text('rsa-private'),
    ...documentPayload('rsa-sign-text'),
  });
  $('rsa-signature').value = r.signature;
  toast('Document signed using RSA-PSS.');
}, 'Signing...');

bindAction('rsa-verify', async () => {
  $('rsa-verify-result').classList.add('hidden');
  const r = await api('/rsa/verify', {
    public_key: text('rsa-public'),
    ...documentPayload('rsa-sign-text'),
    signature: text('rsa-signature'),
  });
  setStatus('rsa-verify-result', r.message, r.valid);
}, 'Verifying...');

$('download-rsa-sig').addEventListener('click', () => {
  if (!text('rsa-signature').trim()) {
    toast('Sign a document first.');
    return;
  }
  download(
    'securedoc-rsa-signature.json',
    JSON.stringify(
      {
        algorithm: 'RSA-PSS-SHA256',
        public_key: text('rsa-public'),
        signature: text('rsa-signature'),
      },
      null,
      2
    ),
    'application/json'
  );
});

const rsaText = $('rsa-text');
const rsaByteCount = $('rsa-byte-count');
rsaText.addEventListener('input', () => {
  const byteLen = TEXT_ENCODER.encode(rsaText.value).length;
  rsaByteCount.textContent = `${byteLen} / 190 bytes`;
  rsaByteCount.classList.toggle('over', byteLen > 190);
});

/* Unified Verify Document Page */
function setVerifyTab(tab) {
  verifyTab = tab;
  document.querySelectorAll('[data-verify-tab]').forEach((btn) => {
    const active = btn.dataset.verifyTab === tab;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  $('verify-panel-rsa').classList.toggle('hidden', tab !== 'rsa');
  $('verify-panel-hmac').classList.toggle('hidden', tab !== 'hmac');
  $('verify-panel-hash').classList.toggle('hidden', tab !== 'hash');
  $('verify-unified-result').classList.add('hidden');
}

document.querySelectorAll('[data-verify-tab]').forEach((btn) => {
  btn.addEventListener('click', () => setVerifyTab(btn.dataset.verifyTab));
});

bindAction('verify-run-rsa', async () => {
  $('verify-unified-result').classList.add('hidden');
  const r = await api('/rsa/verify', {
    public_key: text('verify-rsa-public'),
    ...documentPayload('verify-doc-text'),
    signature: text('verify-rsa-sig'),
  });
  setStatus('verify-unified-result', r.message, r.valid);
}, 'Verifying...');

bindAction('verify-run-hmac', async () => {
  $('verify-unified-result').classList.add('hidden');
  const r = await api('/hmac/verify', {
    ...documentPayload('verify-doc-text'),
    key: text('verify-hmac-key'),
    tag: text('verify-hmac-tag'),
  });
  setStatus('verify-unified-result', r.message, r.valid);
}, 'Verifying...');

bindAction('verify-run-hash', async () => {
  $('verify-unified-result').classList.add('hidden');
  const r = await api('/hash/compare', {
    ...documentPayload('verify-doc-text'),
    algorithm: $('verify-hash-algo').value,
    expected_hash: text('verify-hash-expected'),
  });
  setStatus('verify-unified-result', `${r.message} (Actual ${r.algorithm}: ${r.actual_hash})`, r.match);
}, 'Comparing...');

/* Practical 06: Integrity Checker */
bindAction('hash-btn', async () => {
  const r = await api('/hash', documentPayload('integrity-text'));
  $('sha1-value').textContent = r.sha1;
  $('sha256-value').textContent = r.sha256;
  $('hash-bytes').textContent = `${r.bytes.toLocaleString()} bytes processed`;
  showResult('hash-result');
}, 'Hashing...');

bindAction('integrity-compare-btn', async () => {
  $('integrity-compare-result').classList.add('hidden');
  const r = await api('/hash/compare', {
    ...documentPayload('integrity-text'),
    algorithm: 'sha256',
    expected_hash: text('integrity-expected'),
  });
  setStatus('integrity-compare-result', r.message, r.match);
}, 'Comparing...');

/* Practical 08: HMAC */
bindAction('hmac-generate', async () => {
  const customKey = text('hmac-custom-key').trim();
  if (customKey) {
    const r = await api('/hmac/create', {
      ...documentPayload('hmac-text'),
      key: customKey,
    });
    $('hmac-key').value = customKey;
    $('hmac-tag').value = r.tag;
    toast('HMAC-SHA256 tag generated with provided key.');
  } else {
    const r = await api('/hmac/generate', documentPayload('hmac-text'));
    $('hmac-key').value = r.key;
    $('hmac-tag').value = r.tag;
    toast('256-bit secret key and HMAC tag generated.');
  }
  showResult('hmac-result');
}, 'Generating...');

$('download-hmac').addEventListener('click', () => {
  download(
    'securedoc-hmac-record.json',
    JSON.stringify({ algorithm: 'HMAC-SHA256', key: text('hmac-key'), tag: text('hmac-tag') }, null, 2),
    'application/json'
  );
});

$('use-hmac-verify').addEventListener('click', () => {
  $('hmac-verify-key').value = text('hmac-key');
  $('hmac-verify-tag').value = text('hmac-tag');
  if (!uploadedFiles.has('hmac-text')) {
    $('hmac-verify-text').value = text('hmac-text');
  }
  toast('HMAC key and tag loaded into verifier below.');
});

bindAction('hmac-verify', async () => {
  $('hmac-verify-result').classList.add('hidden');
  const r = await api('/hmac/verify', {
    ...documentPayload('hmac-verify-text'),
    key: text('hmac-verify-key'),
    tag: text('hmac-verify-tag'),
  });
  setStatus('hmac-verify-result', r.message, r.valid);
}, 'Verifying...');

/* Telemetry, Activity Log, Notifications & Search */
function renderActivityTable(events, containerId, emptyHeading, emptyBody, maxRows = 50) {
  const container = $(containerId);
  const query = $('global-search').value.trim().toLowerCase();
  const filtered = events.filter((ev) => {
    if (containerId === 'activity-table-wrap' && activityFilter !== 'all' && ev.status !== activityFilter) {
      return false;
    }
    if (!query || containerId !== 'activity-table-wrap') return true;
    return (
      ev.operation.toLowerCase().includes(query) ||
      ev.algorithm.toLowerCase().includes(query) ||
      ev.detail.toLowerCase().includes(query)
    );
  }).slice(0, maxRows);

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state"><b>${escapeHtml(emptyHeading)}</b><p>${escapeHtml(emptyBody)}</p></div>`;
    return;
  }

  const rows = filtered
    .map(
      (ev) => `<tr>
        <td class="mono">${escapeHtml(ev.timestamp)}</td>
        <td><strong>${escapeHtml(ev.operation)}</strong></td>
        <td class="mono">${escapeHtml(ev.algorithm)}</td>
        <td class="mono">${ev.bytes.toLocaleString()} B</td>
        <td><span class="status-pill ${ev.status === 'success' ? 'good' : 'bad'}">${ev.status === 'success' ? 'Passed' : 'Failed'}</span></td>
        <td>${escapeHtml(ev.detail || '—')}</td>
      </tr>`
    )
    .join('');

  container.innerHTML = `<table class="activity-table">
    <thead>
      <tr><th>Time</th><th>Operation</th><th>Algorithm</th><th>Size</th><th>Status</th><th>Detail</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderNotifications(events, metrics) {
  const badge = $('notif-badge');
  const list = $('notif-list');
  const count = metrics.integrity_failures > 0 ? metrics.integrity_failures : events.length;
  if (count > 0) {
    badge.textContent = String(count);
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }

  if (!events.length) {
    list.innerHTML = '<div class="empty-mini">No security events recorded yet.</div>';
    return;
  }

  list.innerHTML = events
    .slice(0, 6)
    .map(
      (ev) => `<div class="notif-row">
        <b><span>${escapeHtml(ev.operation)}</span><span>${ev.status === 'success' ? '✓' : '✕'}</span></b>
        <small>${escapeHtml(ev.algorithm)} · ${escapeHtml(ev.detail || ev.timestamp)}</small>
      </div>`
    )
    .join('');
}

async function refreshTelemetry() {
  const data = await api('/activity', null, 'GET');
  const m = data.metrics;
  cachedActivity = data.events || [];

  $('stat-total').textContent = m.total_processed.toLocaleString();
  $('stat-signatures').textContent = m.signatures_created.toLocaleString();
  $('stat-verified').textContent = m.verified_documents.toLocaleString();
  $('stat-failures').textContent = m.integrity_failures.toLocaleString();
  $('stat-total-sub').textContent =
    m.total_processed === 0
      ? 'No operations recorded in this session'
      : `${m.signatures_created} signatures · ${m.hashes_computed} hashes · ${m.hmacs_generated} HMACs`;

  renderActivityTable(
    cachedActivity,
    'overview-activity',
    'No activity recorded yet',
    'Hash, sign, encrypt with RSA, or verify a document to inspect real-time backend telemetry here.',
    5
  );
  renderActivityTable(
    cachedActivity,
    'activity-table-wrap',
    'No matching security events',
    'Run any cryptographic tool or clear filters to inspect backend telemetry.',
    50
  );
  renderNotifications(cachedActivity, m);
}

document.querySelectorAll('[data-activity-filter]').forEach((btn) => {
  btn.addEventListener('click', () => {
    activityFilter = btn.dataset.activityFilter;
    document.querySelectorAll('[data-activity-filter]').forEach((b) => b.classList.toggle('active', b === btn));
    renderActivityTable(
      cachedActivity,
      'activity-table-wrap',
      'No matching security events',
      'No events match the selected filter.',
      50
    );
  });
});

$('refresh-activity').addEventListener('click', () => {
  refreshTelemetry().then(() => toast('Security activity refreshed.')).catch(() => toast('Failed to load activity.'));
});

async function resetBackendActivity() {
  await api('/activity/clear', {});
  await refreshTelemetry();
  toast('Session telemetry cleared.');
}

$('clear-activity').addEventListener('click', () => resetBackendActivity().catch((e) => toast(e.message)));
$('reset-telemetry-btn').addEventListener('click', () => resetBackendActivity().catch((e) => toast(e.message)));

/* Notifications Popover */
$('notif-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  const pop = $('notif-popover');
  const open = pop.classList.toggle('hidden');
  $('notif-btn').setAttribute('aria-expanded', open ? 'false' : 'true');
});

document.addEventListener('click', (e) => {
  if (!e.target.closest('.notif-wrap')) {
    $('notif-popover').classList.add('hidden');
    $('notif-btn').setAttribute('aria-expanded', 'false');
  }
  if (!e.target.closest('.search-wrap')) {
    $('search-results').classList.add('hidden');
  }
});

/* Global Search */
$('global-search').addEventListener('input', () => {
  const q = $('global-search').value.trim().toLowerCase();
  const box = $('search-results');

  if ($('view-activity').classList.contains('active')) {
    renderActivityTable(
      cachedActivity,
      'activity-table-wrap',
      'No matching security events',
      'No events match your search query.',
      50
    );
  }

  if (!q) {
    box.classList.add('hidden');
    box.innerHTML = '';
    return;
  }

  const matches = SEARCH_CATALOG.filter(
    (item) => item.label.toLowerCase().includes(q) || item.tag.toLowerCase().includes(q)
  );
  if (!matches.length) {
    box.innerHTML = '<div class="empty-mini" style="padding:8px 10px;">No matching tools</div>';
  } else {
    box.innerHTML = matches
      .map(
        (m) => `<button type="button" class="search-item" data-search-view="${m.view}">
          <span>${escapeHtml(m.label)}</span>
          <small>${escapeHtml(m.tag)}</small>
        </button>`
      )
      .join('');
    box.querySelectorAll('[data-search-view]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const match = SEARCH_CATALOG.find((item) => item.view === btn.dataset.searchView && btn.textContent.includes(item.label));
        navigate(btn.dataset.searchView);
        if (match?.scrollTo) {
          const target = $(match.scrollTo);
          if (target) requestAnimationFrame(() => target.scrollIntoView({ behavior: 'smooth', block: 'start' }));
        }
        box.classList.add('hidden');
      });
    });
  }
  box.classList.remove('hidden');
});

$('global-search').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const first = $('search-results').querySelector('[data-search-view]');
    if (first) {
      e.preventDefault();
      navigate(first.dataset.searchView);
      $('search-results').classList.add('hidden');
    }
  }
});

/* Settings */
$('pref-mask-secrets').addEventListener('change', (e) => {
  const masked = e.target.checked;
  document.querySelectorAll('.secret-field').forEach((el) => el.classList.toggle('masked', masked));
  document.querySelectorAll('[data-mask-target]').forEach((btn) => {
    btn.textContent = masked ? (btn.textContent.includes('Key') ? 'Reveal Key' : 'Reveal') : 'Hide';
  });
});

$('wipe-browser-state').addEventListener('click', () => {
  uploadedFiles.clear();
  document.querySelectorAll('textarea').forEach((el) => { el.value = ''; });
  document.querySelectorAll('input[type="password"], input[type="text"]').forEach((el) => { el.value = ''; });
  document.querySelectorAll('input[type="file"]').forEach((el) => { el.value = ''; });
  document.querySelectorAll('.file-meta').forEach((el) => {
    el.textContent = 'No file attached — type text below or select a file.';
  });
  document.querySelectorAll('.result, .inline-status').forEach((el) => el.classList.add('hidden'));
  $('rsa-plain').textContent = '';
  $('sha1-value').textContent = '';
  $('sha256-value').textContent = '';
  $('rsa-byte-count').textContent = '0 / 190 bytes';
  toast('All browser inputs, keys, and attached file buffers cleared.');
});

async function loadBackendConfig() {
  try {
    const cfg = await api('/config', null, 'GET');
    $('cfg-max-file').textContent = `${Math.round(cfg.max_file_bytes / (1024 * 1024))} MB`;
    $('cfg-rsa').textContent = cfg.rsa_algorithm;
    $('cfg-rsa-bits').textContent = `${cfg.rsa_min_bits} bits minimum`;
    $('cfg-rsa-bytes').textContent = `${cfg.max_rsa_bytes} UTF-8 bytes`;
    $('cfg-hmac').textContent = cfg.hmac_algorithm;
    $('cfg-storage').textContent = cfg.storage_mode;
  } catch {}
}

async function checkApiHealth() {
  const statusEl = $('api-status');
  try {
    const res = await fetch('/health', { cache: 'no-store' });
    const data = await res.json();
    if (!res.ok || data.status !== 'ok') throw new Error();
    statusEl.classList.remove('offline');
    statusEl.innerHTML = '<i aria-hidden="true"></i> API ready';
  } catch {
    statusEl.classList.add('offline');
    statusEl.innerHTML = '<i aria-hidden="true"></i> API unreachable';
  }
}

const initialView = window.location.hash.replace('#', '');
if (VIEW_TITLES[initialView]) {
  navigate(initialView);
}
checkApiHealth();
loadBackendConfig();
refreshTelemetry().catch(() => {});
