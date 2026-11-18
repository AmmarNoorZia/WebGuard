"""One harmless reflected-XSS test for the team's two loopback Flask labs.

HTTP responses are replayed into Chromium at their original URL. Every browser
request is intercepted; only the demo script can be fetched through LocalHTTP.
This preserves CSP while keeping Chromium from following network redirects.
"""
from __future__ import annotations

import html
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit

import requests
from bs4 import BeautifulSoup

MODULE = "xss_reflected"
EXPECTED_ALERT = "XSS demo - WebGuard Dummy Site A"
DEMO_PATH = "/static/xss_demo.js"
LIMITATION = "Not detected means this controlled /search?q test did not demonstrate execution; it does not prove the website is free of XSS."
REMEDIATION = "Remove Jinja's |safe filter for untrusted input and retain contextual HTML escaping ({{ q }}). Use an HTML sanitizer only when rich HTML is required. Keep a restrictive Content Security Policy as defense in depth."


class ScanBlocked(ValueError):
    """An address or request falls outside the explicit lab scope."""


class ScanIncomplete(RuntimeError):
    pass


def validate_target(value: str) -> str:
    """Resolve localhost once, then pin all traffic to a numeric loopback IP.

    Only HTTP ports 5001/5002 are authorized. No custom host names, credentials,
    alternate paths or arbitrary port overrides can expand this allowlist.
    """
    try:
        if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 for c in value):
            raise ValueError()
        parts = urlsplit(value)
        if (parts.scheme != "http" or parts.hostname not in {"localhost", "127.0.0.1", "::1"}
                or parts.port not in {5001, 5002} or parts.username is not None
                or parts.password is not None or parts.path not in {"", "/", "/search"}
                or parts.query or parts.fragment or "\\" in value):
            raise ValueError()
        host = parts.hostname
        if host == "localhost":
            addresses = {r[4][0] for r in socket.getaddrinfo(host, parts.port, type=socket.SOCK_STREAM)}
            if not addresses or not addresses <= {"127.0.0.1", "::1"}:
                raise ValueError()
            host = "127.0.0.1" if "127.0.0.1" in addresses else "::1"
        host = f"[{host}]" if host == "::1" else host
        return f"http://{host}:{parts.port}"
    except (ValueError, OSError):
        raise ScanBlocked("XSS scans allow only http://127.0.0.1:5001 or :5002 (localhost / ::1 equivalents), at the root or /search without a query.")


class LocalHTTP:
    MAX_REQUESTS = 6
    MAX_BYTES = 512 * 1024
    ALLOWED_REQUESTS = {"GET": {"/search", DEMO_PATH}}

    def __init__(self, origin):
        self.origin = origin
        self.count = 0
        self.deadline = time.monotonic() + 25
        self.session = requests.Session()
        self.session.trust_env = False  # Ignore HTTP_PROXY and ambient credentials.

    def get(self, url):
        return self.request("GET", url)

    def request(self, method, url, data=None):
        parts = urlsplit(url)
        base = urlsplit(self.origin)
        if ((parts.scheme, parts.netloc) != (base.scheme, base.netloc)
                or parts.path not in self.ALLOWED_REQUESTS.get(method, set()) or parts.fragment):
            raise ScanBlocked("Blocked request outside the permitted local endpoint and demo script.")
        self.count += 1
        remaining = self.deadline - time.monotonic()
        if self.count > self.MAX_REQUESTS or remaining <= 0:
            raise ScanIncomplete("Local request or time limit reached.")
        send = self.session.get if method == "GET" else self.session.post
        options = {"data": data} if method == "POST" else {}
        with send(url, **options, allow_redirects=False, timeout=min(4, remaining), stream=True,
                              headers={"User-Agent": "WebGuard-Local-XSS/1.0", "Accept-Encoding": "identity"}) as response:
            if 300 <= response.status_code < 400:
                raise ScanIncomplete(f"HTTP {response.status_code} redirect blocked; no redirect destination was contacted.")
            body = bytearray()
            for chunk in response.iter_content(8192):
                body.extend(chunk)
                if len(body) > self.MAX_BYTES or time.monotonic() > self.deadline:
                    raise ScanIncomplete("Response exceeded the size or time limit.")
            # Requests decoded transfer compression; do not replay stale lengths.
            headers = {k.lower(): v for k, v in response.headers.items()
                       if k.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}}
            return {"status": response.status_code, "headers": headers, "body": bytes(body)}

    def close(self):
        self.session.close()


def browser_verify(http, baseline_url, baseline, test_url, tested, *, demo_path=DEMO_PATH):
    """Keep CSP enabled; only an observed alert can prove execution."""
    from playwright.sync_api import sync_playwright

    proof = {"baseline_alerts": [], "test_alerts": [], "demo_requested": False,
             "demo_status": None, "blocked_requests": 0, "errors": []}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True, timeout=10000, args=[
            "--disable-background-networking", "--dns-prefetch-disable",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ])
        try:
            for label, page_url, captured in [("baseline", baseline_url, baseline), ("test", test_url, tested)]:
                # Chromium itself stays offline. Intercepted responses are
                # fulfilled locally; only Python's bounded client accesses labs.
                with browser.new_context(service_workers="block", accept_downloads=False, offline=True) as context:
                    context.route_web_socket("**/*", lambda ws: ws.close())
                    page = context.new_page()
                    navigation_served = False

                    def intercept(route):
                        nonlocal navigation_served
                        req = route.request
                        try:
                            if (not navigation_served and req.url == page_url and req.method == "GET"
                                    and req.is_navigation_request() and req.frame == page.main_frame):
                                navigation_served = True
                                route.fulfill(status=captured["status"], headers=captured["headers"], body=captured["body"])
                            elif (req.url == http.origin + demo_path and req.method == "GET"
                                  and req.resource_type == "script" and req.frame == page.main_frame):
                                script = http.get(req.url)
                                if label == "test":
                                    proof["demo_requested"] = True
                                    proof["demo_status"] = script["status"]
                                if script["status"] != 200:
                                    proof["errors"].append("Demo script did not return HTTP 200.")
                                route.fulfill(status=script["status"], headers=script["headers"], body=script["body"])
                            else:
                                proof["blocked_requests"] += 1
                                route.abort()
                        except (requests.RequestException, ScanBlocked, ScanIncomplete):
                            proof["errors"].append("A browser demo request failed or was blocked.")
                            route.abort()

                    def dialog_seen(dialog):
                        if dialog.type == "alert":
                            proof[f"{label}_alerts"].append(dialog.message[:200])
                        dialog.dismiss()

                    context.route("**/*", intercept)
                    page.on("dialog", dialog_seen)
                    page.goto(page_url, wait_until="load", timeout=6000)
                    page.wait_for_timeout(350)
        finally:
            browser.close()
    return proof


def run_scan(target_url: str) -> dict:
    origin = validate_target(target_url)
    marker = "webguard-" + uuid.uuid4().hex
    payload = f'<script id="{marker}" src="{DEMO_PATH}"></script>'
    endpoint = origin + "/search"
    baseline_url = endpoint + "?" + urlencode({"q": "WebGuard normal search"})
    test_url = endpoint + "?" + urlencode({"q": payload})
    started = datetime.now(timezone.utc).isoformat()
    result = {
        "module": MODULE, "status": "inconclusive", "title": "Reflected Cross-Site Scripting (XSS)",
        "severity": None, "affected_url": endpoint, "started_at": started,
        "http_status": None, "tests": [], "evidence": {"parameter": "q", "payload": payload,
        "request_url": test_url, "expected_alert": EXPECTED_ALERT},
        "remediation": REMEDIATION, "impact": None, "limitation": LIMITATION,
    }
    http = LocalHTTP(origin)
    try:
        baseline = http.get(baseline_url)
        result["http_status"] = baseline["status"]
        result["tests"].append("normal_search_request")
        result["evidence"]["baseline_http_status"] = baseline["status"]
        if baseline["status"] != 200:
            raise ScanIncomplete("Normal /search request did not return HTTP 200.")
        result["http_status"] = None
        tested = http.get(test_url)
        result["http_status"] = tested["status"]
        result["tests"].append("controlled_reflection_request")
        if tested["status"] != 200 or "text/html" not in tested["headers"].get("content-type", "").lower():
            raise ScanIncomplete("Controlled search did not return an HTTP 200 HTML document.")
        document = tested["body"].decode("utf-8", errors="replace")
        script = BeautifulSoup(document, "html.parser").find("script", id=marker, src=DEMO_PATH)
        result["evidence"].update({"html_script_reflected": bool(script),
            "escaped_payload_reflected": not bool(script) and payload in html.unescape(document),
            "response_excerpt": document[max(0, document.find(marker) - 100):document.find(marker) + len(payload) + 100] if marker in document else "Marker not present in response.",
            "content_security_policy": tested["headers"].get("content-security-policy", "Not supplied")})
        proof = browser_verify(http, baseline_url, baseline, test_url, tested)
        result["tests"].append("chromium_baseline_and_payload_execution")
        result["evidence"]["browser"] = proof
        if EXPECTED_ALERT in proof["baseline_alerts"]:
            raise ScanIncomplete("Expected alert also occurred in the normal page; execution cannot be attributed to the injection.")
        if proof["errors"]:
            raise ScanIncomplete("Browser verification could not complete reliably: " + " ".join(proof["errors"]))
        if script and proof["demo_requested"] and proof["demo_status"] == 200 and EXPECTED_ALERT in proof["test_alerts"]:
            result.update(status="confirmed", severity="high",
                          impact="Attacker-controlled HTML executed same-origin JavaScript in the search response.")
            result["evidence"]["outcome"] = "Injected script element and the expected browser alert verified; baseline did not produce that alert."
        elif EXPECTED_ALERT in proof["test_alerts"]:
            raise ScanIncomplete("Alert observed without all required injection evidence.")
        else:
            result["status"] = "not_detected"
            result["evidence"]["outcome"] = "The expected alert was not observed during the controlled browser test."
    except (requests.RequestException, ScanIncomplete) as error:
        result["evidence"]["outcome"] = str(error) if isinstance(error, ScanIncomplete) else "Cannot reach the local test website within the request timeout."
    except (ImportError, OSError) as error:
        result["evidence"]["outcome"] = "Browser verification unavailable. Check the installed Google Chrome and Python requirements."
    except Exception as error:
        # Playwright's Error/TimeoutError are optional until dependencies load.
        if type(error).__module__.startswith("playwright"):
            result["evidence"]["outcome"] = "Google Chrome verification unavailable or timed out. Check the installed Google Chrome and local site, then retry."
        else:
            raise
    finally:
        http.close()
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    result["evidence"]["local_http_requests"] = http.count
    return result
