import base64
import pytest

from app import create_app
from app import crypto_service as c


@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "MAX_CONTENT_LENGTH": 1024 * 1024})
    return app.test_client()


def test_index_health_and_security_headers(client):
    home = client.get("/")
    assert home.status_code == 200
    assert b"SecureDoc" in home.data
    assert home.headers["X-Content-Type-Options"] == "nosniff"
    assert home.headers["X-Frame-Options"] == "DENY"
    assert home.headers["Referrer-Policy"] == "no-referrer"
    csp = home.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp

    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json() == {"status": "ok", "service": "SecureDoc"}


def test_app_config_guards_placeholder_secret_and_bad_max_length(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "replace-with-a-long-random-secret")
    app = create_app({"TESTING": True})
    assert app.config["SECRET_KEY"] != "replace-with-a-long-random-secret"
    assert len(app.config["SECRET_KEY"]) >= 32

    monkeypatch.setenv("MAX_CONTENT_LENGTH", "not-an-int")
    with pytest.raises(ValueError, match="MAX_CONTENT_LENGTH"):
        create_app()

    monkeypatch.setenv("MAX_CONTENT_LENGTH", "-5")
    with pytest.raises(ValueError, match="MAX_CONTENT_LENGTH"):
        create_app()


def test_api_hash_text_empty_unicode_binary_and_errors(client):
    res_empty = client.post("/api/hash", json={"document": ""})
    assert res_empty.status_code == 200
    assert res_empty.get_json()["bytes"] == 0
    assert res_empty.headers["Cache-Control"] == "no-store, max-age=0"

    unicode_text = "Confidential — 🔐 日本語"
    res_uni = client.post("/api/hash", json={"document": unicode_text})
    assert res_uni.status_code == 200
    assert res_uni.get_json()["sha256"] == c.sha256_digest(unicode_text.encode("utf-8"))

    raw = b"\x00\xff\x10\x20binary"
    res_bin = client.post("/api/hash", json={"document_base64": base64.b64encode(raw).decode()})
    assert res_bin.status_code == 200
    assert res_bin.get_json()["bytes"] == len(raw)
    assert res_bin.get_json()["sha256"] == c.sha256_digest(raw)

    assert client.post("/api/hash", json={"document_base64": "!!!bad!!!"}).status_code == 400
    assert client.post("/api/hash", json={}).status_code == 400
    assert client.post("/api/hash", json={"document": 12345}).status_code == 400


def test_removed_aes_endpoints_return_404(client):
    for method in ("post", "get"):
        for path in ("/api/aes/encrypt", "/api/aes/decrypt"):
            res = getattr(client, method)(path, json={"document": "hello"}) if method == "post" else client.get(path)
            assert res.status_code == 404
            assert res.is_json


def test_api_rsa_full_workflow_and_validation(client):
    keys_res = client.post("/api/rsa/keys", json={})
    assert keys_res.status_code == 200
    keys = keys_res.get_json()
    assert "BEGIN PUBLIC KEY" in keys["public_key"]
    assert "BEGIN PRIVATE KEY" in keys["private_key"]

    enc_res = client.post("/api/rsa/encrypt", json={"public_key": keys["public_key"], "document": "Hello RSA 🔐"})
    assert enc_res.status_code == 200
    cipher = enc_res.get_json()["ciphertext"]

    dec_res = client.post("/api/rsa/decrypt", json={"private_key": keys["private_key"], "ciphertext": cipher})
    assert dec_res.status_code == 200
    assert dec_res.get_json()["document"] == "Hello RSA 🔐"

    too_long = client.post("/api/rsa/encrypt", json={"public_key": keys["public_key"], "document": "a" * 191})
    assert too_long.status_code == 400

    sign_res = client.post("/api/rsa/sign", json={"private_key": keys["private_key"], "document": "Contract v1"})
    assert sign_res.status_code == 200
    sig = sign_res.get_json()["signature"]

    ok = client.post(
        "/api/rsa/verify",
        json={"public_key": keys["public_key"], "document": "Contract v1", "signature": sig},
    )
    assert ok.status_code == 200
    assert ok.get_json()["valid"] is True

    tampered = client.post(
        "/api/rsa/verify",
        json={"public_key": keys["public_key"], "document": "Contract v2", "signature": sig},
    )
    assert tampered.status_code == 200
    assert tampered.get_json()["valid"] is False

    missing_sig = client.post(
        "/api/rsa/verify",
        json={"public_key": keys["public_key"], "document": "Contract v1", "signature": ""},
    )
    assert missing_sig.status_code == 400


def test_api_hmac_full_workflow_and_validation(client):
    gen = client.post("/api/hmac/generate", json={"document": "Invoice #104"})
    assert gen.status_code == 200
    data = gen.get_json()

    created = client.post("/api/hmac/create", json={"document": "Invoice #104", "key": data["key"]})
    assert created.status_code == 200
    assert created.get_json()["tag"] == data["tag"]

    ok = client.post("/api/hmac/verify", json={"document": "Invoice #104", "key": data["key"], "tag": data["tag"]})
    assert ok.status_code == 200
    assert ok.get_json()["valid"] is True

    bad = client.post("/api/hmac/verify", json={"document": "Invoice #105", "key": data["key"], "tag": data["tag"]})
    assert bad.status_code == 200
    assert bad.get_json()["valid"] is False

    missing_tag = client.post("/api/hmac/verify", json={"document": "Invoice #104", "key": data["key"], "tag": "   "})
    assert missing_tag.status_code == 400

    weak_key = client.post("/api/hmac/create", json={"document": "hello", "key": "YWJj"})
    assert weak_key.status_code == 400


def test_api_malformed_json_http_methods_404_and_413(client):
    bad_json = client.post("/api/hash", data="{not-json", content_type="application/json")
    assert bad_json.status_code == 400
    assert "error" in bad_json.get_json()

    json_list = client.post("/api/hash", json=["not", "an", "object"])
    assert json_list.status_code == 400

    wrong_method = client.get("/api/hash")
    assert wrong_method.status_code == 405
    assert wrong_method.is_json
    assert "error" in wrong_method.get_json()

    missing_route = client.get("/api/does-not-exist")
    assert missing_route.status_code == 404
    assert missing_route.is_json
    assert "error" in missing_route.get_json()

    oversized = client.post("/api/hash", data=b"x" * (1024 * 1024 + 100), content_type="application/json")
    assert oversized.status_code == 413
    assert oversized.is_json
    assert "Maximum upload size" in oversized.get_json()["error"]


def test_api_metrics_activity_config_hash_compare_and_filename_safety(client):
    initial = client.get("/api/metrics")
    assert initial.status_code == 200
    assert initial.get_json()["total_processed"] == 0

    cfg = client.get("/api/config")
    assert cfg.status_code == 200
    cfg_json = cfg.get_json()
    assert cfg_json["max_file_bytes"] == 10 * 1024 * 1024
    assert cfg_json["rsa_min_bits"] == 2048
    assert "aes_algorithm" not in cfg_json

    # Path traversal in optional filename metadata is rejected
    bad_name = client.post("/api/hash", json={"document": "hi", "filename": "../../etc/passwd"})
    assert bad_name.status_code == 400
    assert "path" in bad_name.get_json()["error"].lower()

    # Perform real operations and verify metrics & activity update
    keys = client.post("/api/rsa/keys", json={}).get_json()
    sig = client.post("/api/rsa/sign", json={"private_key": keys["private_key"], "document": "secret", "filename": "report.txt"}).get_json()["signature"]
    ver_bad = client.post("/api/rsa/verify", json={"public_key": keys["public_key"], "document": "tampered", "signature": sig})
    assert ver_bad.status_code == 200
    assert ver_bad.get_json()["valid"] is False

    digest = c.sha256_digest(b"hello")
    cmp_ok = client.post("/api/hash/compare", json={"document": "hello", "algorithm": "sha256", "expected_hash": digest})
    assert cmp_ok.status_code == 200
    assert cmp_ok.get_json()["match"] is True

    cmp_bad = client.post("/api/hash/compare", json={"document": "hello!", "algorithm": "sha256", "expected_hash": digest})
    assert cmp_bad.status_code == 200
    assert cmp_bad.get_json()["match"] is False

    bad_hex = client.post("/api/hash/compare", json={"document": "hello", "algorithm": "sha256", "expected_hash": "xyz"})
    assert bad_hex.status_code == 400

    act = client.get("/api/activity").get_json()
    assert act["metrics"]["total_processed"] == 5
    assert act["metrics"]["signatures_created"] == 1
    assert act["metrics"]["verified_documents"] == 1
    assert act["metrics"]["integrity_failures"] == 2
    assert len(act["events"]) == 5
    # Ensure secrets/keys/plaintexts are never stored in activity events
    serialized = str(act["events"])
    assert keys["private_key"] not in serialized
    assert "secret" not in serialized

    cleared = client.post("/api/activity/clear", json={})
    assert cleared.status_code == 200
    assert cleared.get_json()["metrics"]["total_processed"] == 0
    assert cleared.get_json()["events"] == []
