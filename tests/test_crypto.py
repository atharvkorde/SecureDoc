import base64
import pytest
from app import create_app
from app import crypto_service as c

@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "MAX_CONTENT_LENGTH": 1024 * 1024})
    return app.test_client()

def test_hashes_are_stable():
    assert c.sha1_digest(b"hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert c.sha256_digest(b"hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

def test_aes_round_trip_and_tamper():
    package = c.aes_encrypt(b"confidential")
    assert c.aes_decrypt(package["key"], package["nonce"], package["ciphertext"]) == b"confidential"
    bad = bytearray(base64.b64decode(package["ciphertext"])); bad[-1] ^= 1
    with pytest.raises(ValueError):
        c.aes_decrypt(package["key"], package["nonce"], base64.b64encode(bad).decode())

def test_rsa_encrypt_and_signature():
    pair = c.rsa_generate()
    cipher = c.rsa_encrypt(pair["public_key"], b"short")
    assert c.rsa_decrypt(pair["private_key"], cipher) == b"short"
    sig = c.rsa_sign(pair["private_key"], b"document")
    assert c.rsa_verify(pair["public_key"], b"document", sig)
    assert not c.rsa_verify(pair["public_key"], b"modified", sig)

def test_hmac_constant_time_verification_path():
    key = c.b64e(b"x" * 32)
    tag = c.hmac_sha256(key, b"doc")
    assert c.hmac_verify(key, b"doc", tag)
    assert not c.hmac_verify(key, b"changed", tag)

def test_api_hash_endpoint(client):
    response = client.post("/api/hash", json={"document": "hello"})
    assert response.status_code == 200
    assert response.json["sha256"] == c.sha256_digest(b"hello")

def test_invalid_hmac_key_rejected(client):
    response = client.post("/api/hmac/create", json={"document": "hello", "key": "YWJj"})
    assert response.status_code == 400
