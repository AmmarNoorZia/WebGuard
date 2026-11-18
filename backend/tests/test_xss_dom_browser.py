"""Installed Chrome, real DOM execution, CSP, attribution and browser isolation."""
from pathlib import Path

import pytest
from pypdf import PdfReader

from scanners import xss_dom as dom
from reporting.pdf import build_report
from test_xss_browser import lab_sites
from test_xss_dom import ORIGIN, response

SUPPORT = Path(__file__).parents[2] / "tools/dom_xss_lab"


def verify_pair(tmp_path, origins=None):
    origins = origins or {port: f"http://127.0.0.1:{port}" for port in (5001, 5002)}
    for port, expected in [(5001, "confirmed"), (5002, "not_detected")]:
        result = dom.run_scan(origins[port])
        assert result["status"] == expected, result
        evidence = result["evidence"]
        assert evidence["server_response_contains_marker"] is False
        assert evidence["fragment_sent_to_server"] is False
        assert evidence["browser"]["contexts"]["test"]["marker_in_output"]
        assert evidence["browser"]["baseline_alerts"] == []
        assert (evidence["expected_alert"] in evidence["browser"]["test_alerts"]) is (expected == "confirmed")
        if expected == "not_detected":
            assert evidence["browser"]["contexts"]["test"]["text_matches_input"]
            assert not evidence["browser"]["contexts"]["test"]["script_in_output"]
        report = build_report({"id": f"local-dom-{port}", "target_snapshot": {"id": str(port),
                              "name": f"DOM validation site {port}", "url": origins[port]}, "result": result})
        text = "\n".join(p.extract_text() for p in PdfReader(report).pages)
        for value in ["DOM-Based Cross-Site", "/dom-xss", result["completed_at"], expected.replace("_", " "), evidence["marker"], "Recommended mitigation"]:
            assert value in text
        report.seek(0)
        (tmp_path / f"dom-{port}.pdf").write_bytes(report.read())


@pytest.mark.browser
def test_dom_execution_on_vulnerable_and_protected_fixtures(lab_sites, tmp_path):
    verify_pair(tmp_path, lab_sites)


@pytest.mark.live
def test_dom_execution_on_team_websites(tmp_path, live_origins):
    verify_pair(tmp_path, live_origins)


@pytest.mark.browser
@pytest.mark.parametrize("csp", ["script-src 'self'", "script-src 'none'"])
def test_browser_stays_local_and_honors_csp(monkeypatch, csp):
    http = dom.DOMHTTP(ORIGIN)
    contacted = []
    driver = (SUPPORT / "dom_xss_lab.js").read_text()
    def get(url):
        contacted.append(url)
        assert url == ORIGIN + dom.DRIVER_PATH
        return response(driver, content_type="application/javascript")
    monkeypatch.setattr(http, "get", get)
    captured = response('<section data-webguard-dom="v1" data-rendering="safe"><form id="dom-form"><input id="dom-input"></form><div id="dom-output"></div>'
                        '<script src="/static/dom_xss_lab.js"></script><script src="http://127.0.0.1:5002/static/xss_dom_demo.js"></script>'
                        '<img src="http://127.0.0.1:5000/blocked"></section>')
    captured["headers"]["content-security-policy"] = csp
    try:
        proof = dom.browser_verify(http, ORIGIN + dom.PAGE_PATH, captured, "webguard-dom-" + "1" * 32, "webguard-dom-" + "1" * 32)
        assert proof["test_alerts"] == []
        if csp == "script-src 'none'":
            assert contacted == []
            assert proof["contexts"]["test"]["driver_requested"] is False
        else:
            assert contacted == [ORIGIN + dom.DRIVER_PATH] * 2
            assert proof["blocked_requests"] >= 2
    finally:
        http.close()


@pytest.mark.browser
@pytest.mark.parametrize("mode", ["old_alert", "demo_blocked_by_csp"])
def test_alerts_and_script_tags_alone_do_not_confirm(monkeypatch, mode):
    old_marker = "webguard-dom-" + "0" * 32
    old_script = f'<script data-webguard-marker="{old_marker}" src="{dom.DEMO_PATH}"></script>' if mode == "old_alert" else ""
    rendering = "safe" if mode == "old_alert" else "unsafe"
    captured = response(f'<section data-webguard-dom="v1" data-rendering="{rendering}"><form id="dom-form"><input id="dom-input"></form>'
                        f'<div id="dom-output"></div><script src="{dom.DRIVER_PATH}"></script>{old_script}</section>')
    if mode == "demo_blocked_by_csp":
        captured["headers"]["content-security-policy"] = "script-src " + ORIGIN + dom.DRIVER_PATH

    def get(self, url):
        self.count += 1
        if url.endswith(dom.PAGE_PATH):
            return captured
        script = "dom_xss_lab.js" if url.endswith(dom.DRIVER_PATH) else "xss_dom_demo.js"
        assert url in {ORIGIN + dom.DRIVER_PATH, ORIGIN + dom.DEMO_PATH}
        return response((SUPPORT / script).read_text(), content_type="application/javascript")

    monkeypatch.setattr(dom.DOMHTTP, "get", get)
    result = dom.run_scan(ORIGIN)
    assert result["status"] == "not_detected", result
    proof = result["evidence"]["browser"]
    if mode == "old_alert":
        assert proof["baseline_alerts"] == proof["test_alerts"] == [dom.ALERT_PREFIX + old_marker]
        assert not proof["contexts"]["test"]["script_in_output"]
    else:
        assert proof["contexts"]["test"]["script_in_output"]
        assert not proof["demo_requested"]
        assert proof["test_alerts"] == []
