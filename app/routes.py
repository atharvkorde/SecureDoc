import base64
from flask import Blueprint, jsonify, request
from . import crypto_service as crypto

api = Blueprint("api", __name__)


def payload():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("A JSON request body is required.")
    return data


def document_bytes(data):
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
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("Document exceeds 10 MB.")
    return raw


@api.errorhandler(ValueError)
def bad_request(error):
    return jsonify(error=str(error)), 400


@api.post("/hash")
def hash_document():
    raw = document_bytes(payload())
    return jsonify(sha1=crypto.sha1_digest(raw), sha256=crypto.sha256_digest(raw), bytes=len(raw))


@api.post("/aes/encrypt")
def aes_encrypt():
    return jsonify(crypto.aes_encrypt(document_bytes(payload())))


@api.post("/aes/decrypt")
def aes_decrypt():
    data = payload()
    plain = crypto.aes_decrypt(data.get("key", ""), data.get("nonce", ""), data.get("ciphertext", ""))
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return jsonify(document=text, document_base64=crypto.b64e(plain), bytes=len(plain))


@api.post("/rsa/keys")
def rsa_keys():
    return jsonify(crypto.rsa_generate())


@api.post("/rsa/encrypt")
def rsa_encrypt():
    data = payload()
    return jsonify(ciphertext=crypto.rsa_encrypt(data.get("public_key", ""), document_bytes(data)))


@api.post("/rsa/decrypt")
def rsa_decrypt():
    data = payload()
    plain = crypto.rsa_decrypt(data.get("private_key", ""), data.get("ciphertext", ""))
    try:
        text = plain.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return jsonify(document=text, document_base64=crypto.b64e(plain), bytes=len(plain))


@api.post("/rsa/sign")
def rsa_sign():
    data = payload()
    return jsonify(signature=crypto.rsa_sign(data.get("private_key", ""), document_bytes(data)))


@api.post("/rsa/verify")
def rsa_verify():
    data = payload()
    valid = crypto.rsa_verify(data.get("public_key", ""), document_bytes(data), data.get("signature", ""))
    return jsonify(valid=valid, message="Signature is valid." if valid else "Signature is invalid or document was changed.")


@api.post("/hmac/generate")
def hmac_generate():
    import secrets
    key = secrets.token_bytes(32)
    return jsonify(key=crypto.b64e(key), tag=crypto.hmac_sha256(crypto.b64e(key), document_bytes(payload())))


@api.post("/hmac/create")
def hmac_create():
    data = payload()
    return jsonify(tag=crypto.hmac_sha256(data.get("key", ""), document_bytes(data)))


@api.post("/hmac/verify")
def hmac_check():
    data = payload()
    valid = crypto.hmac_verify(data.get("key", ""), document_bytes(data), data.get("tag", ""))
    return jsonify(valid=valid, message="HMAC matches." if valid else "HMAC mismatch: wrong key or modified document.")
