import copy
from io import BytesIO
from unittest.mock import Mock

import pytest
from pypdf import PdfReader

import app as api
from scanners import xss_reflected as xss

USER = "bc1f8079-49c3-4081-9a8e-2511e80c1a64"
TARGET_ID = "54d36993-9b22-40c3-bd88-872cf67918a2"
SCAN_ID = "54d36993-9b22-40c3-bd88-872cf67918a3"
HEADERS = {"Authorization": "Bearer test-jwt"}
TARGET = {"id": TARGET_ID, "name": "Website A <lab>", "url": "http://127.0.0.1:5001"}


@pytest.fixture
def actual_result(monkeypatch):
    # Exercise the real result builder; mock only HTTP and browser proof.
    from test_xss_reflected import configure_scan
    configure_scan(monkeypatch, alerts=[xss.EXPECTED_ALERT])
    return xss.run_scan(TARGET["url"])


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(api, "CONFIGURED", True)
    monkeypatch.setattr(api.requests, "get", Mock(return_value=Mock(status_code=200, json=lambda: {"id": USER})))
    return api.app.test_client()


@pytest.mark.parametrize("method,path", [
    ("post", "/api/scans/xss"), ("get", "/api/scans"), ("get", "/api/findings"),
    ("get", f"/api/scans/{SCAN_ID}/report.pdf"),
])
def test_scan_endpoints_require_auth(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_other_users_target_is_not_scanned(client, monkeypatch):
    database = Mock(return_value=[])
    scanner = Mock()
    monkeypatch.setattr(api, "table_request", database)
    monkeypatch.setattr(api, "run_scan", scanner)
    response = client.post("/api/scans/xss", headers=HEADERS, json={"target_id": TARGET_ID})
    assert response.status_code == 404
    assert database.call_args.kwargs["params"]["user_id"] == f"eq.{USER}"
    scanner.assert_not_called()


@pytest.mark.parametrize("url", ["https://example.com", "http://127.0.0.1:5000", "http://127.0.0.1:5001/admin"])
def test_unsafe_registered_target_is_rejected(client, monkeypatch, url):
    monkeypatch.setattr(api, "table_request", Mock(return_value=[{**TARGET, "url": url}]))
    scanner = Mock()
    monkeypatch.setattr(api, "run_scan", scanner)
    assert client.post("/api/scans/xss", headers=HEADERS, json={"target_id": TARGET_ID}).status_code == 400
    scanner.assert_not_called()


@pytest.mark.parametrize("data", [None, [], {"url": "http://127.0.0.1:5001"}, {"target_id": "invalid"}, {"target_id": TARGET_ID, "url": "http://127.0.0.1:5002"}])
def test_requires_only_registered_target_id(client, data):
    assert client.post("/api/scans/xss", headers=HEADERS, json=data).status_code == 400


def test_scan_persists_and_reload_reads_saved_results(client, monkeypatch, actual_result):
    saved_runs = []
    saved_findings = []
    calls = []

    def database(method, table, **kwargs):
        calls.append((method, table, kwargs))
        assert api.g.access_token == "test-jwt"
        if table == "targets":
            return [TARGET]
        if method == "POST" and table == "rpc/save_scan_run":
            assert kwargs["payload"]["p_target_id"] == TARGET_ID
            result = copy.deepcopy(kwargs["payload"]["p_result"])
            scan = {"id": SCAN_ID, "user_id": USER, "target_id": TARGET_ID, "target_snapshot": TARGET,
                    "result": result, "completed_at": result["completed_at"], "module": result["module"], "status": "completed"}
            saved_runs.append(scan)
            saved_findings.append({"scan_id": SCAN_ID, "detection_status": result["status"]})
            return scan
        if table == "scan_runs":
            assert kwargs["params"]["user_id"] == f"eq.{USER}"
            return saved_runs
        if table == "security_findings":
            return saved_findings
        return []

    monkeypatch.setattr(api, "table_request", database)
    monkeypatch.setattr(api, "run_scan", Mock(return_value=actual_result))
    response = client.post("/api/scans/xss", headers=HEADERS, json={"target_id": TARGET_ID})
    assert response.status_code == 201
    assert response.json["persisted"] is True
    assert client.get("/api/scans", headers=HEADERS).json["scans"][0]["result"] == actual_result
    assert client.get("/api/findings", headers=HEADERS).json["findings"][0]["detection_status"] == "confirmed"
    assert any(table == "activity_events" for _, table, _ in calls)
    report = client.get(f"/api/scans/{SCAN_ID}/report.pdf", headers=HEADERS)
    assert report.status_code == 200
    assert report.mimetype == "application/pdf"
    assert report.headers["Cache-Control"] == "private, no-store"
    text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(report.data)).pages)
    for expected in ["WebGuard", TARGET["name"], SCAN_ID, TARGET_ID, "confirmed", "high", "/search", xss.EXPECTED_ALERT, "Recommended mitigation"]:
        assert expected in text


def test_pdf_rejects_other_users_scan(client, monkeypatch):
    db = Mock(return_value=[])
    monkeypatch.setattr(api, "table_request", db)
    assert client.get(f"/api/scans/{SCAN_ID}/report.pdf", headers=HEADERS).status_code == 404
    assert db.call_args.kwargs["params"]["user_id"] == f"eq.{USER}"


def test_database_failure_does_not_claim_persistence(client, monkeypatch, actual_result):
    def database(method, table, **kwargs):
        if table == "targets":
            return [TARGET]
        if table == "rpc/save_scan_run":
            raise api.ApiError("Migration missing.", 502)
        return []
    monkeypatch.setattr(api, "table_request", database)
    monkeypatch.setattr(api, "run_scan", Mock(return_value=actual_result))
    response = client.post("/api/scans/xss", headers=HEADERS, json={"target_id": TARGET_ID})
    assert response.status_code == 502
    assert response.json["persisted"] is False
    assert response.json["scan"]["result"] == actual_result
    assert "id" not in response.json["scan"]


def test_missing_migration_stops_scan_before_testing(client, monkeypatch):
    def database(method, table, **kwargs):
        if table == "targets":
            return [TARGET]
        raise api.ApiError("Migration missing.", 502)
    monkeypatch.setattr(api, "table_request", database)
    scanner = Mock()
    monkeypatch.setattr(api, "run_scan", scanner)
    assert client.post("/api/scans/xss", headers=HEADERS, json={"target_id": TARGET_ID}).status_code == 502
    scanner.assert_not_called()


def test_concurrent_scan_returns_retryable_error(client, monkeypatch):
    monkeypatch.setattr(api, "table_request", Mock(return_value=[TARGET]))
    assert api.SCAN_SLOT.acquire(blocking=False)
    try:
        assert client.post("/api/scans/xss", headers=HEADERS, json={"target_id": TARGET_ID}).status_code == 429
    finally:
        api.SCAN_SLOT.release()
