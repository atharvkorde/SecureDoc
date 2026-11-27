# SecureDoc — Secure Document Authentication System

A college cryptography practical project that combines four core security modules in one responsive dark-theme web application:

| Module | Concept | SecureDoc implementation |
|---|---|---|
| Document Integrity | Message digest (Practical 06) | SHA-1 legacy academic demonstration and SHA-256 integrity digest & comparison |
| RSA Encryption & Decryption | Public-key cryptography (Practical 04) | RSA-2048 key-pair generation and RSA-OAEP (SHA-256) short-message encryption/decryption |
| Digital Signature | Asymmetric signatures (Practical 04) | RSA-PSS (SHA-256) document signing and verification |
| HMAC Authentication | Message authentication (Practical 08) | HMAC-SHA256 generation and constant-time verification |

## Features

- Dark obsidian & warm-gold security dashboard with dedicated pages for **Dashboard**, **Integrity Checker**, **RSA & Digital Signature**, **Verify Document**, **HMAC Authentication**, **Security Activity**, and **Settings**, plus a collapsible mobile navigation drawer.
- Real-time backend telemetry counters (`Total Documents Processed`, `Digital Signatures`, `Verified Documents`, `Integrity Failures`) and non-sensitive activity log (no keys, plaintexts, or documents persisted).
- Drag-and-drop or file-picker upload (up to 10 MB raw file size) with filename path-traversal validation and in-memory processing.
- **RSA-2048** key-pair generation, **RSA-OAEP (SHA-256)** encryption/decryption for short messages (up to 190 UTF-8 bytes with live byte counter), and **RSA-PSS (SHA-256)** digital signatures. Enforces a minimum 2048-bit key size.
- **SHA-1** (explicitly labeled as legacy/insecure for academic demonstration only) and **SHA-256** document digests, plus constant-time digest comparison.
- **HMAC-SHA256** using a 256-bit CSPRNG secret (`secrets.token_bytes`) or custom ≥256-bit key and constant-time comparison (`hmac.compare_digest`).
- Downloadable RSA signature record JSON and HMAC record JSON, plus UI masking toggles for sensitive keys.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, strict `Content-Security-Policy`, `Cache-Control: no-store` on `/api/*`, and `no-cache` on static/HTML assets), JSON error handlers, upload-size limits, and automated tests.

## Requirements

- Python 3.10 or newer
- pip

## Run locally (Windows PowerShell)

```powershell
cd SecureDoc
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000>.

## Run locally (macOS/Linux)

```bash
cd SecureDoc
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000>.

## Run tests

```bash
python -m pytest -v
```

## API overview

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Serves the SecureDoc web interface |
| `/health` | `GET` | Health check returning `{"status": "ok", "service": "SecureDoc"}` |
| `/api/hash` | `POST` | Computes SHA-1 (legacy demo) and SHA-256 digests |
| `/api/hash/compare` | `POST` | Compares document bytes against an expected SHA-256/SHA-1 digest |
| `/api/rsa/keys` | `POST` | Generates an RSA-2048 key pair (PKCS#8 + SPKI PEM) |
| `/api/rsa/encrypt` | `POST` | Encrypts up to 190 UTF-8 bytes using RSA-OAEP (SHA-256) |
| `/api/rsa/decrypt` | `POST` | Decrypts RSA-OAEP (SHA-256) ciphertext |
| `/api/rsa/sign` | `POST` | Signs document bytes using RSA-PSS (SHA-256) |
| `/api/rsa/verify` | `POST` | Verifies an RSA-PSS (SHA-256) signature |
| `/api/hmac/generate` | `POST` | Generates a 256-bit secret key and HMAC-SHA256 tag |
| `/api/hmac/create` | `POST` | Computes an HMAC-SHA256 tag with a provided key (≥ 32 bytes) |
| `/api/hmac/verify` | `POST` | Verifies an HMAC-SHA256 tag in constant time |
| `/api/metrics` | `GET` | Returns real in-memory session telemetry counters |
| `/api/activity` | `GET` | Returns recent non-sensitive security events and counters |
| `/api/activity/clear` | `POST` | Resets in-memory session telemetry counters and events |
| `/api/config` | `GET` | Returns active server-side cryptographic limits |

## Demonstration guide

1. **Integrity:** Open **Integrity Checker**, type text or attach a file, and generate SHA-1 and SHA-256. Change one character and run it again to observe the avalanche effect, or use **Compare Against Expected SHA-256**.
2. **RSA Encryption & Decryption:** Open **RSA & Digital Signature**, generate a 2048-bit key pair, enter a short message (≤ 190 UTF-8 bytes), encrypt with the public key using RSA-OAEP (SHA-256), and decrypt with the private key.
3. **Digital Signatures:** Sign a text or uploaded file with the private key using RSA-PSS (SHA-256), then verify with the public key (or on the **Verify Document** page). Modify the document to see verification fail.
4. **HMAC:** Generate a random 256-bit secret and tag. Paste the exact document, key, and tag in the verification panel (or click **Load into Verifier**). Change the document or key to see verification fail.

## Security notes and limitations

- **SHA-1 is included only for the syllabus demonstration.** SHA-1 has known collision weaknesses and must not be used for modern security. Use SHA-256 or stronger hashes for integrity workflows.
- **RSA** is not suitable for encrypting large files directly. This project caps the direct RSA-OAEP encryption demo at 190 UTF-8 bytes and rejects keys smaller than 2048 bits.
- **Educational key handling:** RSA private keys and HMAC secret keys are returned to the browser for this local demonstration. The server does not persist them, and API responses carry `Cache-Control: no-store`, but production systems should use client-side key generation or a dedicated key-management service (KMS/HSM).
- **HMAC** keys are shared secrets. Anyone holding the key can create valid tags. Never send keys over untrusted channels; use TLS and a secure key exchange/storage design.
- **Deployment considerations:** The API processes uploaded bytes in memory only. If deployed beyond localhost, use HTTPS (HSTS via reverse proxy), a strong unique `FLASK_SECRET_KEY`, rate limiting, CSRF protection for any session-authenticated routes, and a production WSGI server such as Gunicorn rather than Flask's development server.
- Do not use real confidential documents or production secrets in this academic demonstration.

## Project structure

```text
SecureDoc/
├── app/
│   ├── __init__.py
│   ├── crypto_service.py
│   ├── routes.py
│   ├── telemetry.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── app.js
│       └── styles.css
├── tests/
│   ├── conftest.py
│   ├── test_api.py
│   └── test_crypto.py
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
└── run.py
```

## Academic declaration

SecureDoc is an educational implementation intended to demonstrate the selected cryptography practicals. It is not a certified document-management or production key-management product.
