"""Opt-in Chrome checks against disposable fixtures or the actual team labs."""
import pytest
from pypdf import PdfReader

from reporting.pdf import build_report
from scanners.xss_stored import run_scan, ALERT_PREFIX
from test_xss_browser import lab_sites


def verify_pair(tmp_path, origins=None):
    origins = origins or {port: f"http://127.0.0.1:{port}" for port in (5001, 5002)}
    for port, expected in [(5001, "confirmed"), (5002, "not_detected")]:
        result = run_scan(origins[port])
        assert result["status"] == expected, result
        evidence = result["evidence"]
        assert evidence["stored_comment_verified"]
        assert evidence["retrieval_uses_fresh_http_session"]
        assert evidence["cleanup"]["status"] == "removed"
        alert = ALERT_PREFIX + evidence["marker"]
        assert (alert in evidence["browser"]["test_alerts"]) is (expected == "confirmed")
        assert alert not in evidence["browser"]["baseline_alerts"]
        report = build_report({"id": f"local-{port}", "target_snapshot": {"id": str(port),
                              "name": f"Website on {port}", "url": origins[port]}, "result": result})
        text = "\n".join(page.extract_text() for page in PdfReader(report).pages)
        for value in ["Stored Cross-Site", "/comments", result["completed_at"], expected.replace("_", " "), evidence["marker"], "Recommended mitigation"]:
            assert value in text
        report.seek(0)
        (tmp_path / f"stored-{port}.pdf").write_bytes(report.read())


@pytest.mark.browser
def test_stored_vulnerable_and_protected_with_chrome(lab_sites, tmp_path):
    verify_pair(tmp_path, lab_sites)


@pytest.mark.live
def test_stored_team_websites_with_chrome(tmp_path, live_origins):
    verify_pair(tmp_path, live_origins)


@pytest.mark.browser
def test_old_executing_comment_cannot_confirm_escaped_new_comment(monkeypatch):
    from test_xss_stored import configure_scan, response, ORIGIN
    from scanners import xss_stored as stored
    from scanners.xss_reflected import browser_verify
    from pathlib import Path

    state = configure_scan(monkeypatch, escaped=True)
    original_get = stored.StoredHTTP.get
    old_marker = "webguard-stored-" + "0" * 32
    old_script = f'<script data-webguard-marker="{old_marker}" src="{stored.DEMO_PATH}"></script>'
    script_body = (Path(__file__).parents[2] / "tools/stored_xss_lab/xss_stored_demo.js").read_text()

    def get(self, url):
        if url.endswith(stored.DEMO_PATH):
            return response(script_body, content_type="application/javascript")
        captured = original_get(self, url)
        captured["body"] += old_script.encode()
        return captured

    monkeypatch.setattr(stored.StoredHTTP, "get", get)
    monkeypatch.setattr(stored, "browser_verify", browser_verify)
    result = stored.run_scan(ORIGIN)
    assert result["status"] == "not_detected", result
    assert result["evidence"]["browser"]["test_alerts"] == [ALERT_PREFIX + old_marker]
    assert state["saved"] is None
