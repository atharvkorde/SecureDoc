"""Cryptographic primitives used by SecureDoc's educational API."""
import base64
import hashlib
import hmac
import os
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_RSA_MESSAGE = 190  # conservative limit for RSA-2048 OAEP/SHA-256


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 15_000_000:
        raise ValueError("Invalid or oversized Base64 value.")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Invalid Base64 encoding.") from exc


def sha1_digest(data: bytes) -> str:
    # Used only for syllabus demonstration. SHA-1 is collision-broken and legacy.
    return hashlib.sha1(data).hexdigest()


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def aes_encrypt(data: bytes) -> dict:
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return {"algorithm": "AES-256-GCM", "key": b64e(key), "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def aes_decrypt(key_text: str, nonce_text: str, ciphertext_text: str) -> bytes:
    key, nonce, ciphertext = b64d(key_text), b64d(nonce_text), b64d(ciphertext_text)
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("AES-256-GCM requires a 32-byte key and 12-byte nonce.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Authentication failed: data or key was modified.") from exc


def rsa_generate() -> dict:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"private_key": private_pem.decode(), "public_key": public_pem.decode()}


def load_public(pem: str):
    if not isinstance(pem, str) or len(pem) > 20_000:
        raise ValueError("Invalid public key.")
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except Exception as exc:
        raise ValueError("Could not read public PEM key.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("An RSA public key is required.")
    return key


def load_private(pem: str):
    if not isinstance(pem, str) or len(pem) > 20_000:
        raise ValueError("Invalid private key.")
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except Exception as exc:
        raise ValueError("Could not read unencrypted PKCS#8 private PEM key.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("An RSA private key is required.")
    return key


def rsa_encrypt(public_pem: str, data: bytes) -> str:
    if len(data) > MAX_RSA_MESSAGE:
        raise ValueError("RSA demo accepts up to 190 bytes. Use AES for larger documents.")
    encrypted = load_public(public_pem).encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return b64e(encrypted)


def rsa_decrypt(private_pem: str, ciphertext: str) -> bytes:
    try:
        return load_private(private_pem).decrypt(
            b64d(ciphertext),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("RSA decryption failed. Check the private key and ciphertext.") from exc


def rsa_sign(private_pem: str, data: bytes) -> str:
    signature = load_private(private_pem).sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64e(signature)


def rsa_verify(public_pem: str, data: bytes, signature: str) -> bool:
    try:
        load_public(public_pem).verify(
            b64d(signature), data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def hmac_sha256(key_text: str, data: bytes) -> str:
    key = b64d(key_text)
    if len(key) < 32:
        raise ValueError("Use a randomly generated HMAC key of at least 32 bytes (256 bits).")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key_text: str, data: bytes, expected: str) -> bool:
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    actual = hmac_sha256(key_text, data)
    return hmac.compare_digest(actual, expected.lower())
