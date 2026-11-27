"""Cryptographic primitives used by SecureDoc's educational API."""
import base64
import hashlib
import hmac
import secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_RSA_MESSAGE = 190  # conservative limit for RSA-2048 OAEP/SHA-256
MIN_RSA_KEY_BITS = 2048
MAX_RSA_KEY_BITS = 8192


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 15_000_000:
        raise ValueError("Invalid or oversized Base64 value.")
    cleaned = value.strip()
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        raise ValueError("Invalid Base64 encoding.") from exc


def sha1_digest(data: bytes) -> str:
    # Used only for syllabus demonstration. SHA-1 is collision-broken and legacy.
    return hashlib.sha1(data).hexdigest()


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _validate_rsa_key_size(key) -> None:
    if key.key_size < MIN_RSA_KEY_BITS:
        raise ValueError(f"RSA keys must be at least {MIN_RSA_KEY_BITS} bits.")
    if key.key_size > MAX_RSA_KEY_BITS:
        raise ValueError(f"RSA key size exceeds maximum supported {MAX_RSA_KEY_BITS} bits.")


def load_public(pem: str):
    if not isinstance(pem, str) or not pem.strip() or len(pem) > 20_000:
        raise ValueError("Invalid public key.")
    try:
        key = serialization.load_pem_public_key(pem.strip().encode("utf-8"))
    except Exception as exc:
        raise ValueError("Could not read public PEM key.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("An RSA public key is required.")
    _validate_rsa_key_size(key)
    return key


def load_private(pem: str):
    if not isinstance(pem, str) or not pem.strip() or len(pem) > 20_000:
        raise ValueError("Invalid private key.")
    try:
        key = serialization.load_pem_private_key(pem.strip().encode("utf-8"), password=None)
    except Exception as exc:
        raise ValueError("Could not read unencrypted PKCS#8 private PEM key.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("An RSA private key is required.")
    _validate_rsa_key_size(key)
    return key


def rsa_encrypt(public_pem: str, data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Message bytes are required.")
    if len(data) > MAX_RSA_MESSAGE:
        raise ValueError("RSA demo accepts up to 190 UTF-8 bytes.")
    encrypted = load_public(public_pem).encrypt(
        bytes(data),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return b64e(encrypted)


def rsa_decrypt(private_pem: str, ciphertext: str) -> bytes:
    private_key = load_private(private_pem)
    raw_ciphertext = b64d(ciphertext)
    if not raw_ciphertext:
        raise ValueError("Ciphertext is required.")
    try:
        return private_key.decrypt(
            raw_ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
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
    public_key = load_public(public_pem)
    sig_bytes = b64d(signature)
    if not sig_bytes:
        return False
    try:
        public_key.verify(
            sig_bytes,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def hmac_generate(data: bytes) -> dict:
    key = secrets.token_bytes(32)
    key_b64 = b64e(key)
    return {"key": key_b64, "tag": hmac.new(key, data, hashlib.sha256).hexdigest()}


def hmac_sha256(key_text: str, data: bytes) -> str:
    key = b64d(key_text)
    if len(key) < 32:
        raise ValueError("Use a randomly generated HMAC key of at least 32 bytes (256 bits).")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key_text: str, data: bytes, expected: str) -> bool:
    actual = hmac_sha256(key_text, data)
    if not isinstance(expected, str):
        return False
    candidate = expected.strip().lower()
    if len(candidate) != 64:
        return False
    return hmac.compare_digest(actual, candidate)
