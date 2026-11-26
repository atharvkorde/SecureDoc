import base64
import hashlib
import hmac as stdlib_hmac
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app import crypto_service as c


def test_hashes_match_stdlib_and_edge_cases():
    samples = [
        b"",
        b"hello",
        "SecureDoc — UTF-8 🔐 日本語".encode("utf-8"),
        bytes(range(256)),
        b"A" * (1024 * 1024),
    ]
    for data in samples:
        assert c.sha1_digest(data) == hashlib.sha1(data).hexdigest()
        assert c.sha256_digest(data) == hashlib.sha256(data).hexdigest()


def test_aes_round_trip_variants_and_unique_keys_nonces():
    pkg1 = c.aes_encrypt(b"confidential")
    pkg2 = c.aes_encrypt(b"confidential")
    assert pkg1["algorithm"] == "AES-256-GCM"
    assert len(base64.b64decode(pkg1["key"])) == 32
    assert len(base64.b64decode(pkg1["nonce"])) == 12
    assert pkg1["key"] != pkg2["key"]
    assert pkg1["nonce"] != pkg2["nonce"]
    assert pkg1["ciphertext"] != pkg2["ciphertext"]

    for payload in [b"", b"confidential", "Unicode 🔐 text".encode("utf-8"), bytes(range(256)), b"B" * 200_000]:
        pkg = c.aes_encrypt(payload)
        assert c.aes_decrypt(pkg["key"], pkg["nonce"], pkg["ciphertext"]) == payload


def test_aes_invalid_inputs_and_tamper():
    package = c.aes_encrypt(b"confidential")
    bad_ct = bytearray(base64.b64decode(package["ciphertext"]))
    bad_ct[-1] ^= 1
    with pytest.raises(ValueError, match="Authentication failed"):
        c.aes_decrypt(package["key"], package["nonce"], base64.b64encode(bad_ct).decode())

    other = c.aes_encrypt(b"other")
    with pytest.raises(ValueError, match="Authentication failed"):
        c.aes_decrypt(other["key"], package["nonce"], package["ciphertext"])

    with pytest.raises(ValueError, match="32-byte key and 12-byte nonce"):
        c.aes_decrypt(c.b64e(b"short-16-bytes!!"), package["nonce"], package["ciphertext"])

    with pytest.raises(ValueError, match="32-byte key and 12-byte nonce"):
        c.aes_decrypt(package["key"], c.b64e(b"badnonce"), package["ciphertext"])

    with pytest.raises(ValueError, match="Ciphertext is required"):
        c.aes_decrypt(package["key"], package["nonce"], "")

    with pytest.raises(ValueError, match="Invalid Base64"):
        c.aes_decrypt("not-base64!!!", package["nonce"], package["ciphertext"])


def test_rsa_encrypt_decrypt_boundary_and_signatures():
    pair = c.rsa_generate()
    pub = c.load_public(pair["public_key"])
    priv = c.load_private(pair["private_key"])
    assert pub.key_size == 2048
    assert priv.key_size == 2048

    for msg in [b"", b"short", "UTF-8 🔐".encode("utf-8"), b"x" * c.MAX_RSA_MESSAGE]:
        cipher = c.rsa_encrypt(pair["public_key"], msg)
        assert c.rsa_decrypt(pair["private_key"], cipher) == msg

    with pytest.raises(ValueError, match="up to 190 bytes"):
        c.rsa_encrypt(pair["public_key"], b"x" * (c.MAX_RSA_MESSAGE + 1))

    doc = "Signed document content — 📄".encode("utf-8")
    sig = c.rsa_sign(pair["private_key"], doc)
    assert c.rsa_verify(pair["public_key"], doc, sig) is True
    assert c.rsa_verify(pair["public_key"], b"modified", sig) is False
    assert c.rsa_verify(pair["public_key"], doc, "") is False


def test_rsa_rejects_weak_non_rsa_and_invalid_keys_safely():
    pair_a = c.rsa_generate()
    pair_b = c.rsa_generate()
    cipher = c.rsa_encrypt(pair_a["public_key"], b"secret")

    # Wrong private key and corrupt ciphertext produce safe message without leaking internals
    with pytest.raises(ValueError, match="RSA decryption failed"):
        c.rsa_decrypt(pair_b["private_key"], cipher)
    with pytest.raises(ValueError, match="RSA decryption failed"):
        c.rsa_decrypt(pair_a["private_key"], c.b64e(b"short"))
    with pytest.raises(ValueError, match="Ciphertext is required"):
        c.rsa_decrypt(pair_a["private_key"], "")

    # Reject weak 1024-bit RSA key
    weak_priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_priv_pem = weak_priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    weak_pub_pem = weak_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    with pytest.raises(ValueError, match="at least 2048 bits"):
        c.load_public(weak_pub_pem)
    with pytest.raises(ValueError, match="at least 2048 bits"):
        c.load_private(weak_priv_pem)

    # Reject non-RSA (EC) key
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub_pem = ec_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    with pytest.raises(ValueError, match="RSA public key"):
        c.load_public(ec_pub_pem)


def test_hmac_generation_and_constant_time_verification(monkeypatch):
    generated = c.hmac_generate(b"hello world")
    raw_key = base64.b64decode(generated["key"])
    assert len(raw_key) == 32
    expected_hex = stdlib_hmac.new(raw_key, b"hello world", hashlib.sha256).hexdigest()
    assert generated["tag"] == expected_hex

    assert c.hmac_verify(generated["key"], b"hello world", generated["tag"]) is True
    assert c.hmac_verify(generated["key"], b"hello world", f"  {generated['tag'].upper()} \n") is True
    assert c.hmac_verify(generated["key"], b"changed", generated["tag"]) is False
    assert c.hmac_verify(generated["key"], b"hello world", "0" * 64) is False
    assert c.hmac_verify(generated["key"], b"hello world", "short") is False

    # Verify hmac.compare_digest is actually invoked
    called = {"count": 0}
    real_compare = stdlib_hmac.compare_digest

    def spy_compare(a, b):
        called["count"] += 1
        return real_compare(a, b)

    monkeypatch.setattr(stdlib_hmac, "compare_digest", spy_compare)
    assert c.hmac_verify(generated["key"], b"hello world", generated["tag"]) is True
    assert called["count"] == 1

    with pytest.raises(ValueError, match="at least 32 bytes"):
        c.hmac_sha256(c.b64e(b"short"), b"doc")
