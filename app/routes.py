import base64
import hmac
import re
from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename
from . import crypto_service as crypto

api = Blueprint("api", __name__)

MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
HEX_DIGEST_RE = re.compile(r"^[0-9a-fA-F]+$")


def _telemetry():
    return current_app.extensions["telemetry"]


def payload():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("A JSON object request body is required.")
    return data


def _require_text_field(data: dict, field: str, label: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required.")
    return value


def _sanitize_filename(data: dict) -> str:
    name = data.get("filename")
    if name is None:
        return ""
    if not isinstance(name, str) or len(name) > 255:
        raise ValueError("Invalid filename.")
    if "\x00" in name or "/" in name or "\\" in name or ".." in name:
        raise ValueError("Filename contains invalid path characters.")
    cleaned = secure_filename(name)
    if not cleaned:
        raise ValueError("Invalid filename.")
    return cleaned


def document_bytes(data):
    _sanitize_filename(data)
    encoded = data.get("document_base64")
    if encoded is not None:
        if not isinstance(encoded, str) or len(encoded) > 14_000_000:
            raise ValueError("Invalid or oversized document upload.")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError("Invalid document Base64 encoding.") from exc
    else:
        value = data.get("document")
        if not isinstance(value, str):
            raise ValueError("Document text or uploaded file is required.")
        raw = value.encode("utf-8")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("Document exceeds 10 MB.")
    return raw


def _file_detail(data: dict, fallback: str) -> str:
    name = _sanitize_filename(data)
    return f"File: {name}" if name else fallback


@api.errorhandler(ValueError)
def bad_request(error):
    return jsonify(error=str(error)), 400


@api.get("/metrics")
def get_metrics():
    return jsonify(_telemetry().metrics())


@api.get("/activity")
def get_activity():
    return jsonify(events=_telemetry().events(), metrics=_telemetry().metrics())


@api.post("/activity/clear")
def clear_activity():
    _telemetry().clear()
    return jsonify(cleared=True, metrics=_telemetry().metrics(), events=[])


@api.get("/config")
def get_config():
    return jsonify(
        max_file_bytes=MAX_DOCUMENT_BYTES,
        max_rsa_bytes=crypto.MAX_RSA_MESSAGE,
        rsa_min_bits=crypto.MIN_RSA_KEY_BITS,
        rsa_max_bits=crypto.MAX_RSA_KEY_BITS,
        rsa_algorithm="RSA-OAEP / RSA-PSS (SHA-256)",
        hmac_algorithm="HMAC-SHA256",
        sha1_legacy_only=True,
        storage_mode="In-memory only (zero server persistence)",
    )


@api.post("/hash")
def hash_document():
    data = payload()
    raw = document_bytes(data)
    result = {
        "sha1": crypto.sha1_digest(raw),
        "sha256": crypto.sha256_digest(raw),
        "bytes": len(raw),
    }
    _telemetry().record(
        operation="Hash Digest",
        algorithm="SHA-256 & SHA-1",
        success=True,
        byte_count=len(raw),
        detail=_file_detail(data, "Text digest generated"),
        category="hash",
    )
    return jsonify(result)


@api.post("/hash/compare")
def compare_hash():
    data = payload()
    raw = document_bytes(data)
    algorithm = data.get("algorithm", "sha256")
    if algorithm not in ("sha256", "sha1"):
        raise ValueError("Algorithm must be 'sha256' or 'sha1'.")
    expected = _require_text_field(data, "expected_hash", "Expected hash").strip().lower()
    expected_len = 64 if algorithm == "sha256" else 40
    if len(expected) != expected_len or not HEX_DIGEST_RE.match(expected):
        raise ValueError(f"Expected {algorithm.upper()} digest must be {expected_len} hexadecimal characters.")

    actual = crypto.sha256_digest(raw) if algorithm == "sha256" else crypto.sha1_digest(raw)
    match = hmac.compare_digest(actual, expected)
    _telemetry().record(
        operation="Integrity Compare",
        algorithm=algorithm.upper(),
        success=match,
        byte_count=len(raw),
        detail="Digest matched" if match else "Digest mismatch detected",
        category="verify",
    )
    return jsonify(
        match=match,
        algorithm=algorithm.upper(),
        actual_hash=actual,
        bytes=len(raw),
        message="Integrity verified: document matches the expected digest."
        if match
        else "Integrity warning: document hash does not match the expected digest.",
    )


@api.post("/rsa/keys")
def rsa_keys():
    pair = crypto.rsa_generate()
    _telemetry().record(
        operation="RSA Key Pair",
        algorithm="RSA-2048",
        success=True,
        byte_count=0,
        detail="Generated 2048-bit key pair",
        category="general",
    )
    return jsonify(pair)


@api.post("/rsa/encrypt")
def rsa_encrypt():
    data = payload()
    raw = document_bytes(data)
    ciphertext = crypto.rsa_encrypt(data.get("public_key", ""), raw)
    _telemetry().record(
        operation="RSA Encrypt",
        algorithm="RSA-OAEP-SHA256",
        success=True,
        byte_count=len(raw),
        detail="Short message encrypted",
        category="encrypt",
    )
    return jsonify(ciphertext=ciphertext)


@api.post("/rsa/decrypt")
def rsa_decrypt():
    data = payload()
    try:
        plain = crypto.rsa_decrypt(data.get("private_key", ""), data.get("ciphertext", ""))
    except ValueError as exc:
        _telemetry().record(
            operation="RSA Decrypt",
            algorithm="RSA-OAEP-SHA256",
            success=False,
            byte_count=0,
            detail=str(exc),
            category="decrypt",
        )
        raise
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    _telemetry().record(
        operation="RSA Decrypt",
        algorithm="RSA-OAEP-SHA256",
        success=True,
        byte_count=len(plain),
        detail="RSA message decrypted",
        category="decrypt",
    )
    return jsonify(document=text, document_base64=crypto.b64e(plain), bytes=len(plain))


@api.post("/rsa/sign")
def rsa_sign():
    data = payload()
    raw = document_bytes(data)
    signature = crypto.rsa_sign(data.get("private_key", ""), raw)
    _telemetry().record(
        operation="Digital Sign",
        algorithm="RSA-PSS-SHA256",
        success=True,
        byte_count=len(raw),
        detail=_file_detail(data, "Document signed"),
        category="sign",
    )
    return jsonify(signature=signature)


@api.post("/rsa/verify")
def rsa_verify():
    data = payload()
    raw = document_bytes(data)
    signature = _require_text_field(data, "signature", "Signature")
    valid = crypto.rsa_verify(data.get("public_key", ""), raw, signature)
    _telemetry().record(
        operation="Signature Verify",
        algorithm="RSA-PSS-SHA256",
        success=valid,
        byte_count=len(raw),
        detail="Signature valid" if valid else "Signature verification failed",
        category="verify",
    )
    return jsonify(valid=valid, message="Signature is valid." if valid else "Signature is invalid or document was changed.")


@api.post("/hmac/generate")
def hmac_generate():
    data = payload()
    raw = document_bytes(data)
    generated = crypto.hmac_generate(raw)
    _telemetry().record(
        operation="HMAC Generate",
        algorithm="HMAC-SHA256",
        success=True,
        byte_count=len(raw),
        detail=_file_detail(data, "256-bit key + tag generated"),
        category="hmac",
    )
    return jsonify(generated)


@api.post("/hmac/create")
def hmac_create():
    data = payload()
    raw = document_bytes(data)
    tag = crypto.hmac_sha256(data.get("key", ""), raw)
    _telemetry().record(
        operation="HMAC Compute",
        algorithm="HMAC-SHA256",
        success=True,
        byte_count=len(raw),
        detail=_file_detail(data, "Tag computed with provided key"),
        category="hmac",
    )
    return jsonify(tag=tag)


@api.post("/hmac/verify")
def hmac_check():
    data = payload()
    raw = document_bytes(data)
    tag = _require_text_field(data, "tag", "Expected HMAC tag")
    valid = crypto.hmac_verify(data.get("key", ""), raw, tag)
    _telemetry().record(
        operation="HMAC Verify",
        algorithm="HMAC-SHA256",
        success=valid,
        byte_count=len(raw),
        detail="HMAC tag matched" if valid else "HMAC tag mismatch",
        category="verify",
    )
    return jsonify(valid=valid, message="HMAC matches." if valid else "HMAC mismatch: wrong key or modified document.")
