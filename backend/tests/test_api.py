import json

from app import create_app

client = create_app({"TESTING": True}).test_client()


def post_json(payload):
    return client.post("/api/scan", json=payload)


def test_root_endpoint():
    data = client.get("/").get_json()
    assert data["name"] == "PhishGuard" and data["version"] and data["description"]
    assert "running" in data["message"].lower()


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200 and resp.get_json()["status"] == "ok"


def test_scan_success_structure():
    resp = post_json({"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    for key in ("success", "url", "normalized_url", "risk_score", "risk_level", "summary",
                "indicators", "recommendations", "checks", "limitations"):
        assert key in data
    assert data["success"] is True
    assert data["url"] == "https://example.com"
    assert isinstance(data["risk_score"], int) and 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ("Low", "Medium", "High")
    assert len(data["checks"]) == 7
    for check in data["checks"]:
        assert {"name", "passed", "severity", "message"} <= set(check)
    assert data["limitations"]


def test_scan_http_url():
    data = post_json({"url": "http://example.com"}).get_json()
    assert data["risk_score"] > 0 and data["indicators"][0]["name"] == "https_usage"


def assert_error(resp, status, code):
    assert resp.status_code == status
    data = resp.get_json()
    assert data["success"] is False and data["error"]["code"] == code
    assert data["error"]["message"] and "Traceback" not in json.dumps(data)


def test_missing_body():
    assert_error(client.post("/api/scan"), 400, "missing_body")


def test_invalid_json():
    resp = client.post("/api/scan", data="{not json", content_type="application/json")
    assert_error(resp, 400, "invalid_json")


def test_wrong_content_type():
    resp = client.post("/api/scan", data='{"url": "https://example.com"}', content_type="text/plain")
    assert_error(resp, 415, "unsupported_media_type")


def test_json_body_not_an_object():
    assert_error(post_json(["https://example.com"]), 400, "invalid_body")


def test_missing_url_field():
    assert_error(post_json({"link": "https://example.com"}), 400, "missing_url")


def test_empty_url():
    assert_error(post_json({"url": ""}), 400, "empty_url")


def test_non_string_url():
    assert_error(post_json({"url": 42}), 400, "invalid_url_type")
    assert_error(post_json({"url": None}), 400, "invalid_url_type")


def test_unsupported_protocol():
    assert_error(post_json({"url": "ftp://example.com"}), 400, "unsupported_scheme")


def test_credentials_rejected():
    assert_error(post_json({"url": "https://admin:pw@example.com"}), 400, "credentials_not_allowed")


def test_malformed_url():
    assert_error(post_json({"url": "https://"}), 400, "malformed_url")


def test_long_url_rejected():
    assert_error(post_json({"url": "https://example.com/" + "a" * 3000}), 400, "url_too_long")


def test_huge_body_rejected():
    resp = client.post("/api/scan", data="x" * 20000, content_type="application/json")
    assert_error(resp, 413, "payload_too_large")


def test_unknown_route_and_wrong_method_return_json():
    assert_error(client.get("/nope"), 404, "not_found")
    resp = client.get("/api/scan")
    assert_error(resp, 405, "method_not_allowed")
    assert "POST" in resp.headers["Allow"]


def test_unexpected_error_hides_details():
    import app as app_module
    original = app_module.scan_url

    def boom(_):
        raise RuntimeError("secret internal detail /home/user/file.py")

    app_module.scan_url = boom
    try:
        local = app_module.create_app({"TESTING": False, "PROPAGATE_EXCEPTIONS": False}).test_client()
        resp = local.post("/api/scan", json={"url": "https://example.com"})
    finally:
        app_module.scan_url = original
    assert_error(resp, 500, "internal_error")
    assert "secret" not in resp.get_data(as_text=True)


def test_cors_headers_and_preflight():
    resp = client.options("/api/scan", headers={"Origin": "https://frontend.example"})
    assert resp.status_code == 200
    assert resp.headers["Access-Control-Allow-Origin"] == "*"
    assert "Content-Type" in resp.headers["Access-Control-Allow-Headers"]


def test_cors_restricted_origin():
    restricted = create_app({"TESTING": True, "CORS_ALLOWED_ORIGINS": "https://good.example"}).test_client()
    ok = restricted.get("/health", headers={"Origin": "https://good.example"})
    bad = restricted.get("/health", headers={"Origin": "https://evil.example"})
    assert ok.headers["Access-Control-Allow-Origin"] == "https://good.example"
    assert "Access-Control-Allow-Origin" not in bad.headers
