import html
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from scanners import xss_reflected as xss


@pytest.mark.parametrize("url", [
    "https://example.com", "http://localhost.evil:5001", "http://127.0.0.1:5000",
    "http://127.0.0.1:5003", "https://127.0.0.1:5001", "http://127.0.0.2:5001",
    "http://user:pass@localhost:5001", "http://127.0.0.1:5001/admin",
    "http://127.0.0.1:5001/?q=x", "http://127.0.0.1:5001/#x", "file:///test",
    "http://127.0.0.1:bad", "http://127.0.0.1:5001\\@example.com", None,
])
def test_rejects_unauthorized_destinations(url):
    with pytest.raises(xss.ScanBlocked):
        xss.validate_target(url)


def test_localhost_dns_must_only_resolve_to_loopback(monkeypatch):
    monkeypatch.setattr(xss.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 5001))])
    with pytest.raises(xss.ScanBlocked):
        xss.validate_target("http://localhost:5001")


def test_localhost_is_pinned_to_numeric_loopback(monkeypatch):
    monkeypatch.setattr(xss.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 5001))])
    assert xss.validate_target("http://localhost:5001/search") == "http://127.0.0.1:5001"


def response_for(url, escaped=False):
    q = parse_qs(urlsplit(url).query)["q"][0]
    return {"status": 200, "headers": {"content-type": "text/html", "content-security-policy": "script-src 'self'"},
            "body": f"<html><body>{html.escape(q) if escaped else q}</body></html>".encode()}


def configure_scan(monkeypatch, escaped=False, alerts=None):
    monkeypatch.setattr(xss.LocalHTTP, "get", lambda self, url: response_for(url, escaped))
    proof = {"baseline_alerts": [], "test_alerts": alerts or [], "demo_requested": bool(alerts), "demo_status": 200 if alerts else None, "errors": [], "blocked_requests": 0}
    monkeypatch.setattr(xss, "browser_verify", lambda *a: proof)
    return proof


def test_browser_proof_confirms_reflected_xss(monkeypatch):
    configure_scan(monkeypatch, alerts=[xss.EXPECTED_ALERT])
    result = xss.run_scan("http://127.0.0.1:5001")
    assert result["status"] == "confirmed"
    assert result["severity"] == "high"
    assert result["evidence"]["html_script_reflected"] is True
    assert len(result["tests"]) == 3
    assert result["started_at"] <= result["completed_at"]


def test_escaped_site_not_confirmed_even_if_an_alert_occurs(monkeypatch):
    configure_scan(monkeypatch, escaped=True, alerts=[xss.EXPECTED_ALERT])
    assert xss.run_scan("http://127.0.0.1:5002")["status"] == "inconclusive"


def test_escaped_site_not_detected_without_alert(monkeypatch):
    configure_scan(monkeypatch, escaped=True)
    result = xss.run_scan("http://127.0.0.1:5002")
    assert result["status"] == "not_detected"
    assert result["severity"] is None
    assert result["evidence"]["html_script_reflected"] is False


def test_reflection_alone_is_not_confirmation(monkeypatch):
    configure_scan(monkeypatch)
    assert xss.run_scan("http://127.0.0.1:5001")["status"] == "not_detected"


def test_baseline_alert_cannot_prove_injection(monkeypatch):
    proof = configure_scan(monkeypatch, alerts=[xss.EXPECTED_ALERT])
    proof["baseline_alerts"] = [xss.EXPECTED_ALERT]
    assert xss.run_scan("http://127.0.0.1:5001")["status"] == "inconclusive"


@pytest.mark.parametrize("error", [ImportError("missing"), OSError("missing executable")])
def test_missing_browser_is_inconclusive(monkeypatch, error):
    configure_scan(monkeypatch)
    def unavailable(*args):
        raise error
    monkeypatch.setattr(xss, "browser_verify", unavailable)
    result = xss.run_scan("http://127.0.0.1:5001")
    assert result["status"] == "inconclusive"
    assert "installed Google Chrome" in result["evidence"]["outcome"]


def test_network_failure_is_inconclusive(monkeypatch):
    def unavailable(*args):
        raise requests.ConnectionError()
    monkeypatch.setattr(xss.LocalHTTP, "get", unavailable)
    result = xss.run_scan("http://127.0.0.1:5001")
    assert result["status"] == "inconclusive"
    assert result["http_status"] is None


def test_playwright_launch_error_is_inconclusive(monkeypatch):
    from playwright.sync_api import Error
    configure_scan(monkeypatch)
    def unavailable(*args):
        raise Error("Executable doesn't exist")
    monkeypatch.setattr(xss, "browser_verify", unavailable)
    result = xss.run_scan("http://127.0.0.1:5001")
    assert result["status"] == "inconclusive"
    assert "installed Google Chrome" in result["evidence"]["outcome"]


@pytest.mark.parametrize("redirect", ["https://example.com", "http://127.0.0.1:5000/private", "/search?q=redirect"])
def test_redirect_is_never_followed(monkeypatch, redirect):
    response = MagicMock()
    response.__enter__.return_value = response
    response.status_code = 302
    response.headers = {"Location": redirect}
    get = MagicMock(return_value=response)
    monkeypatch.setattr(requests.Session, "get", get)
    http = xss.LocalHTTP("http://127.0.0.1:5001")
    try:
        with pytest.raises(xss.ScanIncomplete, match="redirect blocked"):
            http.get(http.origin + "/search?q=test")
        assert get.call_count == 1
        assert get.call_args.kwargs["allow_redirects"] is False
        assert http.session.trust_env is False
    finally:
        http.close()


def test_browser_fetch_gate_rejects_other_origins_before_network(monkeypatch):
    get = MagicMock()
    monkeypatch.setattr(requests.Session, "get", get)
    http = xss.LocalHTTP("http://127.0.0.1:5001")
    for url in ["https://example.com/search", "http://127.0.0.1:5002/static/xss_demo.js", "http://127.0.0.1:5001/admin"]:
        with pytest.raises(xss.ScanBlocked):
            http.get(url)
    get.assert_not_called()
    http.close()


def test_request_limit_and_response_limit(monkeypatch):
    http = xss.LocalHTTP("http://127.0.0.1:5001")
    http.count = http.MAX_REQUESTS
    with pytest.raises(xss.ScanIncomplete, match="limit"):
        http.get(http.origin + "/search?q=test")
    http.count = 0
    response = MagicMock()
    response.__enter__.return_value = response
    response.status_code = 200
    response.headers = {}
    response.iter_content.return_value = [b"x" * (http.MAX_BYTES + 1)]
    monkeypatch.setattr(http.session, "get", lambda *a, **k: response)
    with pytest.raises(xss.ScanIncomplete, match="size or time"):
        http.get(http.origin + "/search?q=test")
    http.close()
