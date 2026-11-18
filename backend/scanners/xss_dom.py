"""Controlled fragment -> DOM execution test for the two loopback labs.

The server sees only GET /dom-xss. Both fresh Chrome contexts receive the same
captured HTML; fragments are browser-only. The scanner observes application
execution and never injects executable code via evaluate or a browser binding.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from .xss_reflected import LocalHTTP, ScanBlocked, ScanIncomplete, validate_target

MODULE = "xss_dom"
PAGE_PATH = "/dom-xss"
DRIVER_PATH = "/static/dom_xss_lab.js"
DEMO_PATH = "/static/xss_dom_demo.js"
ALERT_PREFIX = "WebGuard DOM XSS: "
LIMITATION = "This controlled fragment-to-DOM test covers /dom-xss only. Not detected does not prove a website is free of XSS; other DOM sources and sinks are not tested."
REMEDIATION = "Treat location.hash and other browser-side input as untrusted. Replace document.write and HTML-parsing sinks with textContent or safe DOM construction. If rich HTML is necessary, use a maintained allowlist sanitizer. Keep restrictive CSP as defense in depth; same-origin scripts can execute through an unsafe HTML sink."


class DOMHTTP(LocalHTTP):
    ALLOWED_REQUESTS = {"GET": {PAGE_PATH, DRIVER_PATH, DEMO_PATH}}

    def __init__(self, origin):
        super().__init__(validate_target(origin))

    def request(self, method, url, data=None):
        parts = urlsplit(url)
        if parts.query or parts.fragment:
            raise ScanBlocked("DOM lab HTTP requests cannot contain query parameters or fragments.")
        return super().request(method, url, data)


def without_fragment(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def browser_verify(http, endpoint, captured, payload, marker):
    """Replay identical HTML with different hashes; fetch only two fixed scripts."""
    from playwright.sync_api import sync_playwright

    proof = {"baseline_alerts": [], "test_alerts": [], "demo_requested": False,
             "demo_status": None, "blocked_requests": 0, "errors": [], "contexts": {}}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True, timeout=10000, args=[
            "--disable-background-networking", "--dns-prefetch-disable",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ])
        try:
            for label, value in [("baseline", "WebGuard normal DOM input"), ("test", payload)]:
                page_url = endpoint + "#" + quote(value, safe="")
                observed = {"driver_requested": False, "driver_status": None,
                            "ready": False, "marker_in_output": False, "script_in_output": False}
                proof["contexts"][label] = observed
                with browser.new_context(service_workers="block", accept_downloads=False, offline=True) as context:
                    context.route_web_socket("**/*", lambda ws: ws.close())
                    page = context.new_page()
                    served = False

                    def intercept(route):
                        nonlocal served
                        req = route.request
                        try:
                            if (not served and without_fragment(req.url) == endpoint and req.method == "GET"
                                    and req.is_navigation_request() and req.frame == page.main_frame):
                                served = True
                                route.fulfill(status=captured["status"], headers=captured["headers"], body=captured["body"])
                            elif (req.url in {http.origin + DRIVER_PATH, http.origin + DEMO_PATH}
                                  and req.method == "GET" and req.resource_type == "script" and req.frame == page.main_frame):
                                resource = http.get(req.url)
                                if req.url == http.origin + DRIVER_PATH:
                                    observed.update(driver_requested=True, driver_status=resource["status"])
                                elif label == "test":
                                    proof.update(demo_requested=True, demo_status=resource["status"])
                                if resource["status"] != 200 or "javascript" not in resource["headers"].get("content-type", "").lower():
                                    proof["errors"].append("A required DOM lab script did not return HTTP 200 JavaScript.")
                                route.fulfill(status=resource["status"], headers=resource["headers"], body=resource["body"])
                            else:
                                proof["blocked_requests"] += 1
                                route.abort()
                        except (requests.RequestException, ScanBlocked, ScanIncomplete):
                            proof["errors"].append("A DOM lab script request failed or was blocked.")
                            route.abort()

                    def dialog_seen(dialog):
                        if dialog.type == "alert":
                            proof[f"{label}_alerts"].append(dialog.message[:200])
                        dialog.dismiss()

                    context.route("**/*", intercept)
                    page.on("dialog", dialog_seen)
                    page.on("pageerror", lambda error: proof["errors"].append(str(error)[:200]))
                    page.goto(page_url, wait_until="load", timeout=6000)
                    page.wait_for_timeout(350)
                    observed["ready"] = page.locator('[data-webguard-dom="v1"][data-webguard-dom-ready="true"]').count() == 1
                    output = page.locator("#dom-result")
                    if output.count() == 1:
                        markup = output.inner_html()
                        observed.update(marker_in_output=marker in markup,
                                        text_matches_input=output.text_content() == value,
                                        response_excerpt=markup[:1200],
                                        script_in_output=output.locator(f'script[id="{marker}"][data-webguard-marker="{marker}"][src="{DEMO_PATH}"]').count() == 1)
                    observed["fragment_preserved"] = page.url == page_url
        finally:
            browser.close()
    return proof


def run_scan(target_url: str) -> dict:
    origin = validate_target(target_url)
    endpoint = origin + PAGE_PATH
    marker = "webguard-dom-" + uuid.uuid4().hex
    payload = f'<script id="{marker}" data-webguard-marker="{marker}" src="{DEMO_PATH}"></script>'
    evidence = {"source": "window.location.hash", "marker": marker, "payload": payload,
                "request_url": endpoint, "browser_test_url": endpoint + "#" + quote(payload, safe=""),
                "expected_alert": ALERT_PREFIX + marker}
    result = {"module": MODULE, "status": "inconclusive", "title": "DOM-Based Cross-Site Scripting (XSS)",
              "severity": None, "affected_url": endpoint, "started_at": datetime.now(timezone.utc).isoformat(),
              "http_status": None, "tests": [], "evidence": evidence, "remediation": REMEDIATION,
              "impact": None, "limitation": LIMITATION}
    http = DOMHTTP(origin)
    try:
        captured = http.get(endpoint)
        result["http_status"] = captured["status"]
        if captured["status"] != 200 or "text/html" not in captured["headers"].get("content-type", "").lower():
            raise ScanIncomplete("DOM lab did not return HTTP 200 HTML. Install/restart the /dom-xss lab feature.")
        raw = captured["body"].decode("utf-8", errors="replace")
        evidence.update(server_response_contains_marker=marker in raw,
                        server_response_sha256=hashlib.sha256(captured["body"]).hexdigest(),
                        identical_html_for_baseline_and_test=True,
                        fragment_sent_to_server=False,
                        content_security_policy=captured["headers"].get("content-security-policy", "Not supplied"))
        if marker in raw:
            raise ScanIncomplete("Marker is present in the server response; DOM-only attribution is not reliable.")
        document = BeautifulSoup(raw, "html.parser")
        if not document.find(attrs={"data-webguard-dom": "v1"}) or not document.find("script", src=DRIVER_PATH):
            raise ScanIncomplete("Known DOM lab page/driver is unavailable. Install/restart the /dom-xss lab feature.")
        result["tests"].append("marker_free_server_response_and_known_dom_page")
        proof = browser_verify(http, endpoint, captured, payload, marker)
        evidence["browser"] = proof
        result["tests"].append("fresh_chrome_baseline_and_fragment_execution_with_csp")
        baseline, tested = proof["contexts"]["baseline"], proof["contexts"]["test"]
        if proof["errors"]:
            raise ScanIncomplete("DOM browser verification failed: " + " ".join(proof["errors"]))
        if any(not observation["ready"] or not observation["fragment_preserved"]
               or not observation["driver_requested"] or observation["driver_status"] != 200
               for observation in (baseline, tested)):
            raise ScanIncomplete("The DOM lab driver did not complete reliably in both fresh browser contexts.")
        if baseline["marker_in_output"] or evidence["expected_alert"] in proof["baseline_alerts"]:
            raise ScanIncomplete("Current marker also appeared in the clean baseline; refusing ambiguous attribution.")
        if not baseline.get("text_matches_input") or not tested["marker_in_output"]:
            raise ScanIncomplete("The DOM lab did not display the controlled baseline and current fragment reliably.")
        if (tested["script_in_output"] and proof["demo_requested"] and proof["demo_status"] == 200
                and evidence["expected_alert"] in proof["test_alerts"]):
            result.update(status="confirmed", severity="high",
                          impact="Browser-side URL fragment input reached an unsafe HTML sink and executed same-origin JavaScript without server reflection.")
            evidence["outcome"] = "The unique browser-only fragment created a script in the DOM and produced its expected alert; the identical server HTML and clean baseline contained no current marker."
        elif evidence["expected_alert"] in proof["test_alerts"]:
            raise ScanIncomplete("Alert observed without all required DOM-side injection evidence.")
        else:
            result["status"] = "not_detected"
            evidence["outcome"] = "The DOM driver displayed the controlled fragment, but its JavaScript did not execute during this test."
    except (requests.RequestException, ScanIncomplete, ScanBlocked) as error:
        evidence["outcome"] = "Cannot reach the authorized local DOM lab within the request timeout." if isinstance(error, requests.RequestException) else str(error)
    except (ImportError, OSError):
        evidence["outcome"] = "DOM browser verification unavailable. Check installed Google Chrome and Python requirements."
    except Exception as error:
        if type(error).__module__.startswith("playwright"):
            evidence["outcome"] = "Google Chrome DOM verification unavailable or timed out. Check installed Chrome and restart the DOM lab, then retry."
        else:
            raise
    finally:
        evidence["local_http_requests"] = http.count
        http.close()
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    return result
