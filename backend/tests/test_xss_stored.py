"""Persistence, execution attribution, cleanup, and local network boundaries."""
import html
import json
from unittest.mock import MagicMock

import pytest
import requests

from scanners import xss_stored as xss

ORIGIN = "http://127.0.0.1:5001"


def response(body, status=200, content_type="text/html"):
    return {"status": status, "headers": {"content-type": content_type, "content-security-policy": "script-src 'self'"},
            "body": body.encode()}


def configure_scan(monkeypatch, *, escaped=False, execute=False, stored=True, cleanup=True):
    state = {"saved": None, "calls": [], "instances": [], "cleanup": cleanup}

    class FakeHTTP:
        def __init__(self, origin):
            self.origin, self.count = origin, 0
            state["instances"].append(self)

        def get(self, url):
            self.count += 1
            state["calls"].append(("GET", url))
            body = '<form data-webguard-comments="v1" action="/comments" method="post"><input name="csrf_token" value="csrf"></form>'
            if state["saved"] and stored:
                payload = state["saved"]["body"]
                body += f'<article data-comment-id="7"><div data-comment-body>{html.escape(payload) if escaped else payload}</div></article>'
            return response(body)

        def request(self, method, url, data):
            self.count += 1
            state["calls"].append((method, url))
            if url.endswith("/cleanup"):
                state["cleanup_attempted"] = True
                assert data["cleanup_token"] == state["saved"]["cleanup_token"]
                if state["cleanup"]:
                    state["saved"] = None
                return response(json.dumps({"deleted": state["cleanup"]}), content_type="application/json")
            state["saved"] = data
            return response(json.dumps({"id": 7, "marker": data["scanner_marker"]}), 201, "application/json")

        def close(self):
            pass

    def verify(http, baseline_url, baseline, url, retrieved, **kwargs):
        assert baseline_url == url == ORIGIN + "/comments"
        assert kwargs["demo_path"] == xss.DEMO_PATH
        marker = state["saved"]["scanner_marker"]
        proof = {"baseline_alerts": [], "test_alerts": [xss.ALERT_PREFIX + marker] if execute else [],
                 "demo_requested": execute, "demo_status": 200 if execute else None,
                 "blocked_requests": 0, "errors": []}
        proof.update(state.get("proof_override", {}))
        if state.get("baseline_current"):
            proof["baseline_alerts"] = [xss.ALERT_PREFIX + marker]
        return proof

    monkeypatch.setattr(xss, "StoredHTTP", FakeHTTP)
    monkeypatch.setattr(xss, "browser_verify", verify)
    return state


@pytest.mark.parametrize("escaped,execute,expected", [(False, True, "confirmed"), (True, False, "not_detected"),
                                                       (False, False, "not_detected"), (True, True, "inconclusive")])
def test_storage_and_execution_are_separate_requirements(monkeypatch, escaped, execute, expected):
    state = configure_scan(monkeypatch, escaped=escaped, execute=execute)
    result = xss.run_scan(ORIGIN)
    assert result["status"] == expected
    assert result["evidence"]["stored_comment_verified"] is True
    assert result["evidence"]["cleanup"]["status"] == "removed"
    assert result["severity"] == ("high" if expected == "confirmed" else None)
    assert state["saved"] is None
    assert result["started_at"] <= result["completed_at"]
    assert "cleanup_token" not in json.dumps(result)
    assert len(state["instances"]) == 3  # submission, independent read, cleanup


def test_post_receipt_alone_does_not_prove_persistence(monkeypatch):
    state = configure_scan(monkeypatch, execute=True, stored=False)
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert not result["evidence"]["stored_comment_verified"]
    assert state["cleanup_attempted"]


def test_old_comment_alert_cannot_confirm_current_scan(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    state["proof_override"] = {"test_alerts": [xss.ALERT_PREFIX + "webguard-stored-" + "0" * 32]}
    first = xss.run_scan(ORIGIN)
    second = xss.run_scan(ORIGIN)
    assert first["status"] == second["status"] == "not_detected"
    assert first["evidence"]["marker"] != second["evidence"]["marker"]


def test_baseline_current_marker_is_inconclusive(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    state["baseline_current"] = True
    assert xss.run_scan(ORIGIN)["status"] == "inconclusive"


@pytest.mark.parametrize("error", [ImportError("missing"), OSError("chrome"), requests.ConnectionError("offline")])
def test_failed_browser_is_inconclusive_and_comment_is_cleaned(monkeypatch, error):
    state = configure_scan(monkeypatch, execute=True)
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(xss, "browser_verify", fail)
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert result["evidence"]["cleanup"]["status"] == "removed"
    assert state["saved"] is None


def test_cleanup_failure_preserves_execution_result_and_reports_remaining_comment(monkeypatch):
    configure_scan(monkeypatch, execute=True, cleanup=False)
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "confirmed"
    assert result["evidence"]["cleanup"]["status"] == "failed"


def test_submission_timeout_after_commit_still_attempts_precise_cleanup(monkeypatch):
    state = configure_scan(monkeypatch)
    send = xss.StoredHTTP.request
    def timeout_after_commit(self, method, url, data):
        reply = send(self, method, url, data)
        if not url.endswith("/cleanup"):
            raise requests.Timeout()
        return reply
    monkeypatch.setattr(xss.StoredHTTP, "request", timeout_after_commit)
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert state["saved"] is None
    assert result["evidence"]["cleanup"]["status"] == "removed"


@pytest.mark.parametrize("value", ["not json", "[]", '{"id": 7, "marker": "wrong"}'])
def test_bad_submission_receipt_cannot_confirm_and_is_cleaned(monkeypatch, value):
    state = configure_scan(monkeypatch, execute=True)
    send = xss.StoredHTTP.request
    def bad_receipt(self, method, url, data):
        reply = send(self, method, url, data)
        return reply if url.endswith("/cleanup") else response(value, 201, "application/json")
    monkeypatch.setattr(xss.StoredHTTP, "request", bad_receipt)
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert state["saved"] is None


def test_browser_request_errors_are_inconclusive(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    state["proof_override"] = {"errors": ["Demo script did not return HTTP 200."]}
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert result["evidence"]["cleanup"]["status"] == "removed"


def test_missing_comments_is_meaningful_inconclusive(monkeypatch):
    monkeypatch.setattr(xss.StoredHTTP, "get", lambda *args: response("missing", 404))
    result = xss.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert "Install/restart" in result["evidence"]["outcome"]
    assert result["evidence"]["cleanup"]["status"] == "not_needed"


@pytest.mark.parametrize("url", ["https://example.com", "http://127.0.0.1:5000", "http://127.0.0.1:5003",
                                  "http://127.0.0.1:5001/comments", "http://127.0.0.1:5001/?x=1"])
def test_target_scope_is_checked_before_http(url):
    with pytest.raises(xss.ScanBlocked):
        xss.run_scan(url)


@pytest.mark.parametrize("method,url", [("POST", "http://127.0.0.1:5002/comments"),
    ("POST", ORIGIN + "/login"), ("GET", ORIGIN + "/comments?body=test"), ("DELETE", ORIGIN + "/comments"),
    ("GET", "https://example.com/comments"), ("GET", ORIGIN + "/static/xss_demo.js")])
def test_request_scope_is_checked_before_network(monkeypatch, method, url):
    post = MagicMock()
    monkeypatch.setattr(requests.Session, "post", post)
    http = xss.StoredHTTP(ORIGIN)
    try:
        with pytest.raises(xss.ScanBlocked):
            http.request(method, url)
    finally:
        http.close()
    post.assert_not_called()


def test_submission_redirect_is_blocked_without_following(monkeypatch):
    reply = MagicMock()
    reply.__enter__.return_value = reply
    reply.status_code = 302
    reply.headers = {"Location": "http://example.com/comments"}
    post = MagicMock(return_value=reply)
    monkeypatch.setattr(requests.Session, "post", post)
    http = xss.StoredHTTP(ORIGIN)
    try:
        with pytest.raises(xss.ScanIncomplete, match="redirect blocked"):
            http.request("POST", ORIGIN + "/comments", {"body": "test"})
        assert post.call_count == 1
        assert post.call_args.kwargs["allow_redirects"] is False
        assert http.session.trust_env is False
    finally:
        http.close()
