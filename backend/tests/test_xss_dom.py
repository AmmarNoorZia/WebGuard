"""DOM attribution, false positives, failure outcomes, and network scope."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from scanners import xss_dom as dom

ORIGIN = "http://127.0.0.1:5001"


def response(body=None, status=200, content_type="text/html"):
    if body is None:
        body = '<section data-webguard-dom="v1"><script src="/static/dom_xss_lab.js"></script></section>'
    return {"status": status, "headers": {"content-type": content_type, "content-security-policy": "script-src 'self'"},
            "body": body.encode()}


def configure_scan(monkeypatch, *, execute=False):
    state = {"calls": [], "execute": execute, "proof": None}

    def get(self, url):
        self.count += 1
        state["calls"].append(url)
        return state.get("response", response())

    def verify(http, endpoint, captured, payload, marker):
        observation = {"driver_requested": True, "driver_status": 200, "ready": True,
                       "marker_in_output": False, "script_in_output": False,
                       "fragment_preserved": True, "text_matches_input": True}
        proof = {"baseline_alerts": [], "test_alerts": [dom.ALERT_PREFIX + marker] if state["execute"] else [],
                 "demo_requested": state["execute"], "demo_status": 200 if state["execute"] else None,
                 "blocked_requests": 0, "errors": [], "contexts": {
                     "baseline": dict(observation),
                     "test": {**observation, "marker_in_output": True, "script_in_output": state["execute"]}}}
        proof.update(state.get("proof_override", {}))
        for label in ("baseline", "test"):
            proof["contexts"][label].update(state.get(label + "_override", {}))
        if state.get("baseline_current"):
            proof["baseline_alerts"] = [dom.ALERT_PREFIX + marker]
        state["proof"] = proof
        return proof

    monkeypatch.setattr(dom.DOMHTTP, "get", get)
    monkeypatch.setattr(dom, "browser_verify", verify)
    return state


@pytest.mark.parametrize("execute,expected", [(True, "confirmed"), (False, "not_detected")])
def test_execution_and_safe_dom_outcomes(monkeypatch, execute, expected):
    state = configure_scan(monkeypatch, execute=execute)
    result = dom.run_scan(ORIGIN)
    assert result["status"] == expected
    assert result["severity"] == ("high" if execute else None)
    assert result["evidence"]["fragment_sent_to_server"] is False
    assert result["evidence"]["server_response_contains_marker"] is False
    assert state["calls"] == [ORIGIN + dom.PAGE_PATH]
    assert "#" not in state["calls"][0]
    assert result["started_at"] <= result["completed_at"]


@pytest.mark.parametrize("override", [
    {"script_in_output": True},  # HTML alone is not execution.
    {},
])
def test_dom_insertion_without_alert_does_not_confirm(monkeypatch, override):
    state = configure_scan(monkeypatch)
    state["test_override"] = override
    assert dom.run_scan(ORIGIN)["status"] == "not_detected"


def test_expected_alert_without_script_evidence_is_inconclusive(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    state["test_override"] = {"script_in_output": False}
    assert dom.run_scan(ORIGIN)["status"] == "inconclusive"


def test_old_marker_cannot_confirm_current_test(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    state["proof_override"] = {"test_alerts": [dom.ALERT_PREFIX + "webguard-dom-" + "0" * 32]}
    a, b = dom.run_scan(ORIGIN), dom.run_scan(ORIGIN)
    assert a["status"] == b["status"] == "not_detected"
    assert a["evidence"]["marker"] != b["evidence"]["marker"]


@pytest.mark.parametrize("baseline_current,baseline_override", [(True, {}), (False, {"marker_in_output": True})])
def test_baseline_current_marker_is_ambiguous(monkeypatch, baseline_current, baseline_override):
    state = configure_scan(monkeypatch, execute=True)
    state.update(baseline_current=baseline_current, baseline_override=baseline_override)
    assert dom.run_scan(ORIGIN)["status"] == "inconclusive"


@pytest.mark.parametrize("override", [{"ready": False}, {"driver_requested": False}, {"driver_status": 404},
                                    {"fragment_preserved": False}, {"marker_in_output": False}])
def test_incomplete_dom_test_is_not_a_negative_result(monkeypatch, override):
    state = configure_scan(monkeypatch, execute=True)
    state["test_override"] = override
    assert dom.run_scan(ORIGIN)["status"] == "inconclusive"


def test_server_marker_prevents_dom_only_confirmation(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    monkeypatch.setattr(dom.uuid, "uuid4", lambda: SimpleNamespace(hex="1" * 32))
    state["response"] = response('webguard-dom-' + '1' * 32)
    result = dom.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert result["evidence"]["server_response_contains_marker"]
    assert state["proof"] is None


@pytest.mark.parametrize("captured", [response(status=404), response(content_type="application/json"), response("unrelated page")])
def test_missing_dom_lab_is_inconclusive(monkeypatch, captured):
    state = configure_scan(monkeypatch)
    state["response"] = captured
    result = dom.run_scan(ORIGIN)
    assert result["status"] == "inconclusive"
    assert "Install/restart" in result["evidence"]["outcome"]


@pytest.mark.parametrize("error", [ImportError("missing"), OSError("Chrome missing"), requests.Timeout()])
def test_browser_and_request_failures_are_inconclusive(monkeypatch, error):
    configure_scan(monkeypatch)
    def fail(*args):
        raise error
    monkeypatch.setattr(dom, "browser_verify", fail)
    assert dom.run_scan(ORIGIN)["status"] == "inconclusive"


def test_browser_errors_are_inconclusive(monkeypatch):
    state = configure_scan(monkeypatch, execute=True)
    state["proof_override"] = {"errors": ["DOM driver failed"]}
    assert dom.run_scan(ORIGIN)["status"] == "inconclusive"


@pytest.mark.parametrize("url", ["https://example.com", "http://127.0.0.1:5000", "http://localhost.evil:5001",
    "http://127.0.0.2:5001", "http://user:pass@localhost:5001", "http://localhost:5001/#test", "http://localhost:5001/admin"])
def test_target_scope_is_checked_before_http(monkeypatch, url):
    get = MagicMock()
    monkeypatch.setattr(requests.Session, "get", get)
    with pytest.raises(dom.ScanBlocked):
        dom.run_scan(url)
    get.assert_not_called()


def test_external_dns_resolution_is_blocked(monkeypatch):
    from scanners import xss_reflected
    monkeypatch.setattr(xss_reflected.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 5001))])
    with pytest.raises(dom.ScanBlocked):
        dom.run_scan("http://localhost:5001")


@pytest.mark.parametrize("method,url", [("GET", "https://example.com/dom-xss"), ("GET", "http://127.0.0.1:5002/dom-xss"),
    ("GET", ORIGIN + "/dom-xss#test"), ("GET", ORIGIN + "/dom-xss?input=test"), ("POST", ORIGIN + "/dom-xss"),
    ("GET", ORIGIN + "/static/xss_demo.js"), ("GET", ORIGIN + "/admin")])
def test_http_allowlist_blocks_before_network(monkeypatch, method, url):
    get = MagicMock()
    monkeypatch.setattr(requests.Session, "get", get)
    http = dom.DOMHTTP(ORIGIN)
    try:
        with pytest.raises(dom.ScanBlocked):
            http.request(method, url)
        get.assert_not_called()
        assert http.session.trust_env is False
    finally:
        http.close()


def test_redirect_is_never_followed(monkeypatch):
    captured = MagicMock()
    captured.__enter__.return_value = captured
    captured.status_code = 302
    captured.headers = {"Location": "https://example.com"}
    get = MagicMock(return_value=captured)
    monkeypatch.setattr(requests.Session, "get", get)
    http = dom.DOMHTTP(ORIGIN)
    try:
        with pytest.raises(dom.ScanIncomplete, match="redirect blocked"):
            http.get(ORIGIN + dom.PAGE_PATH)
        assert get.call_count == 1
        assert get.call_args.kwargs["allow_redirects"] is False
    finally:
        http.close()
