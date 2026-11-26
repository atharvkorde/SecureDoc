# SecureDoc — Secure Document Authentication System

A college cryptography practical project that combines four syllabus concepts in one responsive web application:

| Practical | Concept | SecureDoc implementation |
|---|---|---|
| 03 | Symmetric-key cryptography | AES-256-GCM document encryption/decryption |
| 04 | RSA public-key cryptography | RSA-2048, OAEP/SHA-256 encryption and PSS/SHA-256 digital signatures |
| 06 | Message digest | SHA-1 academic demonstration and SHA-256 integrity digest |
| 08 | Message authentication | HMAC-SHA256 generation and verification |

## Features

- Responsive dashboard with a separate workspace for each practical.
- Text input and file upload (up to 10 MB) for hashing, AES encryption, signing and HMAC.
- AES-256-GCM uses a fresh random 256-bit key and 96-bit nonce. Authentication is checked during decryption.
- RSA-2048 key-pair generation, RSA-OAEP encryption for short messages (up to 190 bytes in this demo), RSA-PSS digital signatures and verification.
- SHA-1 and SHA-256 document digests.
- HMAC-SHA256 using a random 256-bit secret and constant-time comparison.
- Downloadable encrypted package and restored document.
- Security headers, upload-size limits, input validation and automated tests.

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

Open http://127.0.0.1:5000.

## Run locally (macOS/Linux)

```bash
cd SecureDoc
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:5000.

## Run tests

```bash
pytest -q
```

## Demonstration guide

1. **Integrity:** open Integrity Check, type text or attach a file, and generate SHA-1 and SHA-256. Change one character and run it again to observe the digest change.
2. **AES:** attach/type a document and encrypt it. Save the key and download the encrypted package JSON. Paste that JSON in the decrypt panel to restore the document. Modify the ciphertext to see GCM authentication fail.
3. **RSA:** generate a key pair and keep the private key confidential. Encrypt a short message with the public key and decrypt it with the private key. For signatures, sign the exact document with the private key, then verify with the public key. Change the document to make verification fail.
4. **HMAC:** generate a random secret and tag. Paste the exact document, key and tag in the verification panel. Change the document or key to see verification fail.

## Security notes and limitations

- **SHA-1 is included only for the syllabus demonstration.** SHA-1 has known collision weaknesses and must not be used for modern security. Use SHA-256 or a stronger modern hash for integrity workflows.
- AES-GCM protects confidentiality and authenticates ciphertext. Never reuse a nonce with the same AES key. SecureDoc generates a fresh key and nonce for every encryption.
- RSA is not suitable for encrypting large files directly. This project caps the direct RSA encryption demo at 190 bytes; use hybrid encryption (AES-GCM for the file and RSA-OAEP to wrap the AES key) for a production file-encryption design.
- RSA keys are generated on the server and returned to the browser for this educational demo. The server does not persist them, but production key generation/storage should use a protected client or dedicated key-management service. The browser receives the private key, so only use test data.
- HMAC keys are shared secrets. Anyone holding the key can create valid tags. Do not send keys over untrusted channels; use TLS and a secure key exchange/storage design.
- The API receives uploaded file bytes in memory. The app does not intentionally save document uploads, keys or operation results to disk.
- A production deployment must use HTTPS, a strong random `FLASK_SECRET_KEY`, rate limiting, CSRF protections where cookie-authenticated actions exist, hardened reverse-proxy settings, monitoring, dependency updates and an audited key-management process.
- The built-in Flask development server is for local demonstrations only. For deployment use a production WSGI server such as Gunicorn behind a properly configured HTTPS reverse proxy.
- Do not use real confidential documents or production secrets in this academic demonstration.

## Project structure

```text
SecureDoc/
├── app/
│   ├── __init__.py
│   ├── crypto_service.py
│   ├── routes.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── app.js
│       └── styles.css
├── tests/
│   ├── conftest.py
│   └── test_crypto.py
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
└── run.py
```

## Academic declaration

SecureDoc is an educational implementation intended to demonstrate the selected cryptography practicals. It is not a certified document-management or production key-management product.
