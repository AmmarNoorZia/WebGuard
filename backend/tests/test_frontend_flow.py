"""Real React -> Flask -> Chromium -> PDF flow; Supabase is mocked, not migrated."""
import base64
import copy
import json
import socket
import time
import uuid
from pathlib import Path
from threading import Thread

import pytest
from dotenv import dotenv_values
from playwright.sync_api import sync_playwright
from pypdf import PdfReader
from werkzeug.serving import make_server

import app as api
from test_xss_browser import lab_sites


@pytest.mark.ui
@pytest.mark.browser
@pytest.mark.parametrize("kind", ["Reflected", "Stored"])
def test_react_scan_findings_refresh_and_pdf(lab_sites, monkeypatch, tmp_path, kind):
    for port in [5000]:
        with socket.socket() as check:
            if check.connect_ex(("127.0.0.1", port)) == 0:
                pytest.skip("Port 5000 occupied; disposable API will not replace it.")
    config = dotenv_values(Path(__file__).parents[2] / "frontend" / ".env")
    supabase_url = config.get("VITE_SUPABASE_URL", "")
    if not supabase_url.startswith("https://"):
        pytest.skip("Frontend needs its existing Supabase URL for auth initialization.")
    user_id = str(uuid.uuid4())
    targets = [{"id": str(uuid.uuid4()), "name": f"UI Website {letter}", "url": f"http://127.0.0.1:{port}"} for letter, port in [("A", 5001), ("B", 5002)]]
    scans, findings, events = [], [], []
    monkeypatch.setattr(api, "CONFIGURED", True)

    def authenticate_request(*args, **kwargs):
        class Verified:
            status_code = 200
            def json(self):
                return {"id": user_id}
        return Verified()
    monkeypatch.setattr(api.requests, "get", authenticate_request)

    def database(method, table, **kwargs):
        if table == "targets":
            selected = kwargs.get("params", {}).get("id")
            return [t for t in targets if not selected or selected == f"eq.{t['id']}"]
        if table == "activity_events":
            if method == "POST":
                events.append({"id": str(uuid.uuid4()), "created_at": "2026-11-14T12:00:00Z", **kwargs["payload"]})
            return events
        if table == "rpc/save_scan_run":
            target = next(t for t in targets if t["id"] == kwargs["payload"]["p_target_id"])
            result = copy.deepcopy(kwargs["payload"]["p_result"])
            saved = {"id": str(uuid.uuid4()), "target_id": target["id"], "target_snapshot": target, "result": result,
                     "completed_at": result["completed_at"], "status": "inconclusive" if result["status"] == "inconclusive" else "completed"}
            scans.insert(0, saved)
            findings.insert(0, {"id": str(uuid.uuid4()), "scan_id": saved["id"], "detection_status": result["status"],
                                "scan_runs": {"target_snapshot": target, "result": result}})
            return saved
        if table == "scan_runs":
            selected = kwargs.get("params", {}).get("id")
            return [s for s in scans if not selected or selected == f"eq.{s['id']}"]
        if table == "security_findings":
            return findings
        raise AssertionError(table)

    monkeypatch.setattr(api, "table_request", database)
    server = make_server("127.0.0.1", 5000, api.app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        user = {"id": user_id, "email": "fixture@example.test", "aud": "authenticated", "role": "authenticated", "app_metadata": {}, "user_metadata": {}}
        encode = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        access_token = encode({"alg": "HS256", "typ": "JWT"}) + "." + encode({"sub": user_id, "exp": int(time.time()) + 3600, "role": "authenticated"}) + ".fixture"
        session = {"access_token": access_token, "refresh_token": "fixture", "token_type": "bearer", "expires_in": 3600, "expires_at": int(time.time()) + 3600, "user": user}
        project = supabase_url.split("//")[1].split(".")[0]
        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel="chrome", headless=True)
            try:
                context = browser.new_context(accept_downloads=True)
                context.route(supabase_url + "/**", lambda route: route.fulfill(json=user, headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "authorization,apikey,content-type,x-client-info,x-supabase-api-version",
                    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                }))
                context.add_init_script(f"localStorage.setItem({json.dumps('sb-' + project + '-auth-token')}, {json.dumps(json.dumps(session))});")
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto("http://127.0.0.1:5173/scans")
                page.get_by_label("Scan type").select_option(kind.lower())
                page.get_by_role("button", name=f"Run {kind} XSS Scan").wait_for()
                page.get_by_label("Registered target").select_option(targets[0]["id"])
                page.get_by_role("button", name=f"Run {kind} XSS Scan").click()
                page.locator(".detection-status.confirmed").first.wait_for(timeout=45000)
                with page.expect_download() as download:
                    page.get_by_role("button", name="Download PDF").first.click()
                download.value.save_as(tmp_path / "ui-confirmed.pdf")
                confirmed_text = "\n".join(p.extract_text() for p in PdfReader(tmp_path / "ui-confirmed.pdf").pages)
                assert f"{kind} Cross-Site" in confirmed_text
                assert "Detection: confirmed" in confirmed_text
                page.get_by_label("Registered target").select_option(targets[1]["id"])
                page.get_by_role("button", name=f"Run {kind} XSS Scan").click()
                page.locator(".detection-status.not_detected").first.wait_for(timeout=45000)
                with page.expect_download() as download:
                    page.get_by_role("button", name="Download PDF").first.click()
                download.value.save_as(tmp_path / "ui-not-detected.pdf")
                safe_text = "\n".join(p.extract_text() for p in PdfReader(tmp_path / "ui-not-detected.pdf").pages)
                assert f"{kind} Cross-Site" in safe_text
                assert "Detection: not detected" in safe_text
                page.reload()
                page.locator(".detection-status.confirmed").wait_for()
                page.locator(".detection-status.not_detected").wait_for()
                page.screenshot(path=str(tmp_path / "scans-dark.png"), full_page=True)
                page.get_by_role("link", name="Findings", exact=True).click()
                page.locator(".detection-status.confirmed").wait_for()
                page.locator(".detection-status.not_detected").wait_for()
                page.get_by_role("link", name="Reports", exact=True).click()
                page.get_by_role("button", name="Download PDF").nth(1).wait_for()
                page.screenshot(path=str(tmp_path / "reports-dark.png"), full_page=True)
                page.get_by_role("button", name="Toggle theme").click()
                page.screenshot(path=str(tmp_path / "reports-light.png"), full_page=True)
                assert len(scans) == 2
                assert errors == []
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
