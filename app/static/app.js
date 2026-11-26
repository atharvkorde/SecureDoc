const $ = (id) => document.getElementById(id);
let toastTimer;
const uploadedFiles = new Map();
const VIEW_TITLES = {
  overview: 'Document security overview',
  integrity: 'Document integrity',
  encryption: 'AES encryption workspace',
  rsa: 'RSA security toolkit',
  authentication: 'HMAC authentication',
};

function uint8ToBase64(bytes) {
  const chunkSize = 0x8000;
  const parts = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + chunkSize)));
  }
  return btoa(parts.join(''));
}

function documentPayload(id) {
  return uploadedFiles.has(id)
    ? { document_base64: uploadedFiles.get(id) }
    : { document: text(id) };
}

document.querySelectorAll('[data-file-target]').forEach((input) => {
  input.addEventListener('change', async () => {
    const file = input.files[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      toast('Maximum file size is 10 MB.');
      input.value = '';
      return;
    }
    const data = await file.arrayBuffer();
    uploadedFiles.set(input.dataset.fileTarget, uint8ToBase64(new Uint8Array(data)));
    $(input.dataset.fileTarget).value = `[Attached file: ${file.name} · ${file.size.toLocaleString()} bytes]`;
    toast('File attached for this operation.');
  });
});

document.querySelectorAll('textarea').forEach((area) => {
  area.addEventListener('input', () => {
    if (uploadedFiles.has(area.id)) {
      uploadedFiles.delete(area.id);
    }
    if (area.value === '') {
      const fileInput = document.querySelector(`[data-file-target="${area.id}"]`);
      if (fileInput) fileInput.value = '';
    }
  });
});

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

function showResult(id) {
  $(id).classList.remove('hidden');
}

async function api(path, data) {
  const response = await fetch('/api' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const result = await response.json().catch(() => ({ error: 'Unexpected server response.' }));
  if (!response.ok) {
    throw new Error(result.error || 'Request failed.');
  }
  return result;
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

function packageData() {
  return {
    algorithm: 'AES-256-GCM',
    key: text('aes-key'),
    nonce: text('aes-nonce'),
    ciphertext: text('aes-ciphertext'),
  };
}

function bindAction(id, fn, loadingText = 'Processing...') {
  const button = $(id);
  button.addEventListener('click', async () => {
    if (button.disabled) return;
    const originalHtml = button.innerHTML;
    button.disabled = true;
    button.classList.add('is-loading');
    button.setAttribute('aria-busy', 'true');
    button.textContent = loadingText;
    try {
      await fn();
    } catch (e) {
      toast(e.message || 'Something went wrong.');
    } finally {
      button.disabled = false;
      button.classList.remove('is-loading');
      button.removeAttribute('aria-busy');
      button.innerHTML = originalHtml;
    }
  });
}

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
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('[data-view]').forEach((b) => {
  b.addEventListener('click', () => navigate(b.dataset.view));
});

document.querySelectorAll('[data-go]').forEach((b) => {
  b.addEventListener('click', (e) => {
    e.preventDefault();
    navigate(b.dataset.go);
  });
});

document.querySelectorAll('[data-copy]').forEach((b) => {
  b.addEventListener('click', async () => {
    const el = $(b.dataset.copy);
    if (!el.value) {
      toast('Nothing to copy yet.');
      return;
    }
    try {
      await navigator.clipboard.writeText(el.value);
      toast('Copied to clipboard.');
    } catch {
      el.select();
      document.execCommand('copy');
      toast('Copied.');
    }
  });
});

bindAction('hash-btn', async () => {
  const r = await api('/hash', documentPayload('integrity-text'));
  $('sha1-value').textContent = r.sha1;
  $('sha256-value').textContent = r.sha256;
  $('hash-bytes').textContent = `${r.bytes} bytes processed`;
  showResult('hash-result');
}, 'Hashing...');

bindAction('aes-encrypt', async () => {
  const r = await api('/aes/encrypt', documentPayload('aes-text'));
  $('aes-key').value = r.key;
  $('aes-nonce').textContent = r.nonce;
  $('aes-ciphertext').value = r.ciphertext;
  showResult('aes-result');
  toast('Document encrypted. Save your key securely.');
}, 'Encrypting...');

$('download-aes').addEventListener('click', () => {
  download('securedoc-encrypted-package.json', JSON.stringify(packageData(), null, 2), 'application/json');
});

bindAction('aes-decrypt', async () => {
  const rawPackage = text('aes-package').trim();
  if (!rawPackage) {
    throw new Error('Paste an encrypted package JSON first.');
  }
  let parsed;
  try {
    parsed = JSON.parse(rawPackage);
  } catch {
    throw new Error('Invalid JSON format in encrypted package.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Encrypted package must be a JSON object.');
  }
  const r = await api('/aes/decrypt', parsed);
  $('aes-plain').value = r.document ?? `Binary document (${r.bytes} bytes) decrypted. Use Download restored document.`;
  window.restoredDocumentBase64 = r.document_base64;
  window.restoredIsBinary = r.document === null;
  showResult('aes-plain-result');
  toast('Authentication passed. Document decrypted.');
}, 'Decrypting...');

$('download-plain').addEventListener('click', () => {
  if (window.restoredIsBinary && window.restoredDocumentBase64) {
    const raw = atob(window.restoredDocumentBase64);
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    download('securedoc-restored-document.bin', bytes, 'application/octet-stream');
  } else {
    download('securedoc-restored-document.txt', text('aes-plain'));
  }
});

bindAction('rsa-generate', async () => {
  const r = await api('/rsa/keys', {});
  $('rsa-public').value = r.public_key;
  $('rsa-private').value = r.private_key;
  toast('RSA-2048 key pair generated. Keep the private key secret.');
}, 'Generating...');

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
  const r = await api('/rsa/verify', {
    public_key: text('rsa-public'),
    ...documentPayload('rsa-sign-text'),
    signature: text('rsa-signature'),
  });
  setStatus('rsa-verify-result', r.message, r.valid);
}, 'Verifying...');

bindAction('hmac-generate', async () => {
  const r = await api('/hmac/generate', documentPayload('hmac-text'));
  $('hmac-key').value = r.key;
  $('hmac-tag').value = r.tag;
  showResult('hmac-result');
  toast('HMAC generated. Keep the shared key secret.');
}, 'Generating...');

$('download-hmac').addEventListener('click', () => {
  download(
    'securedoc-hmac-record.json',
    JSON.stringify({ algorithm: 'HMAC-SHA256', key: text('hmac-key'), tag: text('hmac-tag') }, null, 2),
    'application/json'
  );
});

bindAction('hmac-verify', async () => {
  const r = await api('/hmac/verify', {
    ...documentPayload('hmac-verify-text'),
    key: text('hmac-verify-key'),
    tag: text('hmac-verify-tag'),
  });
  setStatus('hmac-verify-result', r.message, r.valid);
}, 'Verifying...');

const rsaText = $('rsa-text');
const rsaByteCount = $('rsa-byte-count');
const textEncoder = new TextEncoder();
rsaText.addEventListener('input', () => {
  const byteLen = textEncoder.encode(rsaText.value).length;
  rsaByteCount.textContent = `${byteLen} / 190 bytes`;
  rsaByteCount.classList.toggle('over', byteLen > 190);
});

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
