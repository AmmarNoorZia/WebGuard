"""Explicit opt-in real-browser tests; never import/run discovery.py.

Fixtures represent the documented behavior and reuse the comments lab module.
The live tests never start or modify an existing website.
"""
import socket
import importlib.util
import sqlite3
from pathlib import Path
from threading import Thread

import pytest
from flask import Flask, Response, render_template_string, request, g, send_file
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader
from werkzeug.serving import make_server

from scanners.xss_reflected import EXPECTED_ALERT, LocalHTTP, browser_verify, run_scan


@pytest.fixture
def lab_sites(tmp_path):
    # Refuse to replace or interfere with a contributor's running website.
    host = None
    for candidate, family in [("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)]:
        try:
            for port in (5001, 5002):
                with socket.socket(family) as check:
                    check.bind((candidate, port))
            host = candidate
            break
        except OSError:
            continue
    if host is None:
        pytest.skip("Lab ports occupied on both loopback families; existing sites will not be replaced.")
    origins = {port: f"http://{'[::1]' if host == '::1' else host}:{port}" for port in (5001, 5002)}
    servers = []
    try:
        for port, vulnerable in [(5001, True), (5002, False)]:
            lab = Flask(f"fixture-{port}")
            lab.secret_key = "disposable-fixture-only"
            support = Path(__file__).parents[2] / "tools" / "stored_xss_lab"
            spec = importlib.util.spec_from_file_location("lab_comments_support", support / "stored_xss_lab.py")
            comments_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(comments_module)
            lab.jinja_loader = ChoiceLoader([FileSystemLoader(str(support)),
                                            DictLoader({"base.html": "<html><body>{% block content %}{% endblock %}</body></html>"})])

            def get_db(path=tmp_path / f"fixture-{port}.db"):
                if "db" not in g:
                    g.db = sqlite3.connect(path)
                    g.db.row_factory = sqlite3.Row
                return g.db

            @lab.teardown_appcontext
            def close_db(_error):
                db = g.pop("db", None)
                if db is not None:
                    db.close()

            comments_module.register_comments(lab, get_db, vulnerable=vulnerable)
            dom_support = Path(__file__).parents[2] / "tools" / "dom_xss_lab"
            spec = importlib.util.spec_from_file_location("lab_dom_support", dom_support / "dom_xss_lab.py")
            dom_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(dom_module)
            lab.jinja_loader.loaders.insert(0, FileSystemLoader(str(dom_support)))
            dom_module.register_dom_page(lab, vulnerable=vulnerable)
            lab.add_url_rule("/static/dom_xss_lab.js", "dom_driver", lambda: send_file(dom_support / "dom_xss_lab.js", mimetype="application/javascript"))
            lab.add_url_rule("/static/xss_dom_demo.js", "dom_demo", lambda: send_file(dom_support / "xss_dom_demo.js", mimetype="application/javascript"))

            def search(vulnerable=vulnerable):
                template = "<html><body><h1>Lab fixture</h1>{{ q|safe }}</body></html>" if vulnerable else "<html><body><h1>Lab fixture</h1>{{ q }}</body></html>"
                response = Response(render_template_string(template, q=request.args.get("q", "")), content_type="text/html")
                response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
                return response

            lab.add_url_rule("/search", view_func=search)
            lab.add_url_rule("/static/xss_demo.js", "demo", lambda: Response(f'alert("{EXPECTED_ALERT}");', content_type="application/javascript"))
            lab.add_url_rule("/static/xss_stored_demo.js", "stored_demo", lambda: send_file(support / "xss_stored_demo.js", mimetype="application/javascript"))
            @lab.after_request
            def csp(response):
                response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
                return response
            server = make_server(host, port, lab, threaded=True)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append((server, thread))
        yield origins
    finally:
        for server, thread in servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


@pytest.mark.browser
def test_real_chromium_vulnerable_and_protected_fixtures(lab_sites, tmp_path):
    from reporting.pdf import build_report
    a = run_scan(lab_sites[5001])
    b = run_scan(lab_sites[5002])
    assert a["status"] == "confirmed", a
    assert a["evidence"]["browser"]["test_alerts"] == [EXPECTED_ALERT]
    assert a["evidence"]["browser"]["baseline_alerts"] == []
    assert b["status"] == "not_detected", b
    assert not b["evidence"]["html_script_reflected"]
    assert b["evidence"]["browser"]["test_alerts"] == []
    for label, result, port in [("a", a, 5001), ("b", b, 5002)]:
        scan = {"id": f"browser-fixture-{label}", "target_snapshot": {"id": f"fixture-{label}", "name": f"Disposable Website {label.upper()} fixture", "url": lab_sites[port]}, "result": result}
        (tmp_path / f"fixture-{label}.pdf").write_bytes(build_report(scan).getvalue())


@pytest.mark.live
@pytest.mark.parametrize("port,expected", [(5001, "confirmed"), (5002, "not_detected")])
def test_team_websites(port, expected, live_origins):
    result = run_scan(live_origins[port])
    assert result["status"] == expected, result


@pytest.mark.browser
def test_browser_blocks_other_origin_resources(monkeypatch):
    http = LocalHTTP("http://127.0.0.1:5001")
    contacted = []
    monkeypatch.setattr(http, "get", lambda url: contacted.append(url))
    baseline = {"status": 200, "headers": {"content-type": "text/html"}, "body": b"<html><body>normal</body></html>"}
    tested = {**baseline, "body": b'<html><body><script src="http://127.0.0.1:5002/static/xss_demo.js"></script><img src="http://127.0.0.1:5000/blocked"></body></html>'}
    try:
        proof = browser_verify(http, http.origin + "/search?q=normal", baseline, http.origin + "/search?q=test", tested)
        assert proof["blocked_requests"] >= 2
        assert contacted == []
        assert proof["test_alerts"] == []
    finally:
        http.close()


@pytest.mark.browser
def test_browser_keeps_restrictive_csp(monkeypatch):
    http = LocalHTTP("http://127.0.0.1:5001")
    contacted = []
    monkeypatch.setattr(http, "get", lambda url: contacted.append(url))
    baseline = {"status": 200, "headers": {"content-type": "text/html", "content-security-policy": "script-src 'none'"}, "body": b"<html><body>normal</body></html>"}
    tested = {**baseline, "body": b'<html><body><script src="/static/xss_demo.js"></script></body></html>'}
    try:
        proof = browser_verify(http, http.origin + "/search?q=normal", baseline, http.origin + "/search?q=test", tested)
        assert proof["demo_requested"] is False
        assert contacted == []
        assert proof["test_alerts"] == []
    finally:
        http.close()
