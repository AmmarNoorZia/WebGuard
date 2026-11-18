"""One bounded, marker-specific stored-XSS test against the team's comments lab.

The POST response is never rendered. A separate HTTP session retrieves /comments
without a query; Chromium then replays that response in a fresh offline context.
Only execution of the current marker's harmless same-origin script proves XSS.
"""
from __future__ import annotations

import hashlib
import html
import json
import secrets
import uuid
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

from .xss_reflected import LocalHTTP, ScanBlocked, ScanIncomplete, browser_verify, validate_target

MODULE = "xss_stored"
DEMO_PATH = "/static/xss_stored_demo.js"
ALERT_PREFIX = "WebGuard stored XSS: "
LIMITATION = "This controlled /comments test covers stored XSS only. Not detected does not prove the website is free of XSS; DOM-based XSS and cookie testing are outside this test."
REMEDIATION = "Render saved comments with contextual HTML escaping ({{ comment.body }}), without Jinja's |safe filter. If rich HTML is required, use a maintained allowlist sanitizer. Keep a restrictive CSP as defense in depth; same-origin scripts can still execute when attacker-controlled script elements are accepted."


class StoredHTTP(LocalHTTP):
    MAX_REQUESTS = 12
    ALLOWED_REQUESTS = {"GET": {"/comments", DEMO_PATH}, "POST": {"/comments", "/comments/cleanup"}}

    def __init__(self, origin):
        super().__init__(validate_target(origin))

    def request(self, method, url, data=None):
        # Unlike reflected search, the comments protocol never needs query input.
        from urllib.parse import urlsplit
        if urlsplit(url).query:
            raise ScanBlocked("Comments testing does not allow query parameters.")
        return super().request(method, url, data)


def document(response):
    if response["status"] != 200 or "text/html" not in response["headers"].get("content-type", "").lower():
        raise ScanIncomplete("Comments endpoint did not return an HTTP 200 HTML document. Install/restart the comments lab feature.")
    return BeautifulSoup(response["body"].decode("utf-8", errors="replace"), "html.parser")


def receipt(response, expected_status):
    if response["status"] != expected_status:
        raise ScanIncomplete(f"Comments operation returned HTTP {response['status']}; expected {expected_status}.")
    try:
        value = json.loads(response["body"])
    except (ValueError, UnicodeError):
        raise ScanIncomplete("Comments endpoint returned an invalid JSON receipt.")
    if not isinstance(value, dict):
        raise ScanIncomplete("Comments endpoint returned an invalid JSON receipt.")
    return value


def run_scan(target_url: str) -> dict:
    origin = validate_target(target_url)
    endpoint = origin + "/comments"
    marker = "webguard-stored-" + uuid.uuid4().hex
    cleanup_token = secrets.token_hex(32)  # Never persisted in evidence or reports.
    payload = f'<script id="{marker}" data-webguard-marker="{marker}" src="{DEMO_PATH}"></script>'
    expected_alert = ALERT_PREFIX + marker
    evidence = {"marker": marker, "payload": payload, "request_url": endpoint,
                "expected_alert": expected_alert, "stored_comment_verified": False,
                "cleanup": {"status": "not_needed"}}
    result = {"module": MODULE, "status": "inconclusive", "title": "Stored Cross-Site Scripting (XSS)",
              "severity": None, "affected_url": endpoint, "started_at": datetime.now(timezone.utc).isoformat(),
              "http_status": None, "tests": [], "evidence": evidence,
              "remediation": REMEDIATION, "impact": None, "limitation": LIMITATION}
    http = StoredHTTP(origin)
    reader = StoredHTTP(origin)
    submitted = False
    comment_id = None
    try:
        baseline = http.get(endpoint)
        result["http_status"] = baseline["status"]
        soup = document(baseline)
        form = soup.find("form", attrs={"data-webguard-comments": "v1"})
        token = form.find("input", attrs={"name": "csrf_token"}) if form else None
        if (not form or form.get("action") != "/comments" or form.get("method", "").lower() != "post"
                or not token or not token.get("value")):
            raise ScanIncomplete("Known comments form is unavailable or incompatible. Install/restart the comments lab feature.")
        if marker in str(soup):
            raise ScanIncomplete("Current marker already exists in the baseline; refusing ambiguous verification.")
        result["tests"].append("comments_form_and_csrf_discovery")
        evidence["baseline_http_status"] = baseline["status"]
        # Mark before sending: a timeout may occur after the server has committed.
        submitted = True
        posted = http.request("POST", endpoint, {"body": payload, "scanner_marker": marker,
                              "cleanup_token": cleanup_token, "csrf_token": token["value"]})
        result["http_status"] = posted["status"]
        evidence["submission_http_status"] = posted["status"]
        saved = receipt(posted, 201)
        comment_id = saved.get("id")
        if type(comment_id) is not int or comment_id <= 0 or saved.get("marker") != marker:
            raise ScanIncomplete("Submission receipt does not identify the current test comment.")
        evidence["comment_id"] = comment_id
        result["tests"].append("unique_test_comment_submission")
        retrieved = reader.get(endpoint)
        result["http_status"] = retrieved["status"]
        soup = document(retrieved)
        entry = soup.find("article", attrs={"data-comment-id": str(comment_id)})
        body = entry.find(attrs={"data-comment-body": True}) if entry else None
        # Ignore the POST body and receipt: require the full payload in the saved
        # record on a subsequent GET made with a separate session and no query.
        canonical_payload = str(BeautifulSoup(payload, "html.parser").find("script"))
        stored = body is not None and (payload in html.unescape(body.decode_contents())
                                      or canonical_payload in body.decode_contents())
        evidence["stored_comment_verified"] = stored
        if not stored:
            raise ScanIncomplete("The current test comment was not found in an independent comments-page retrieval.")
        script = body.find("script", id=marker, src=DEMO_PATH, attrs={"data-webguard-marker": marker})
        evidence.update({"html_script_stored": bool(script), "escaped_payload_displayed": not bool(script),
                         "response_excerpt": str(body)[:1200],
                         "retrieval_body_sha256": hashlib.sha256(retrieved["body"]).hexdigest(),
                         "retrieval_uses_fresh_http_session": True,
                         "content_security_policy": retrieved["headers"].get("content-security-policy", "Not supplied")})
        result["tests"].append("independent_saved_comment_retrieval")
        proof = browser_verify(reader, endpoint, baseline, endpoint, retrieved, demo_path=DEMO_PATH)
        evidence["browser"] = proof
        result["tests"].append("fresh_chrome_context_stored_execution_with_csp")
        if proof["errors"] or expected_alert in proof["baseline_alerts"]:
            raise ScanIncomplete("Browser verification failed or the current marker also executed in the baseline.")
        if script and proof["demo_requested"] and proof["demo_status"] == 200 and expected_alert in proof["test_alerts"]:
            result.update(status="confirmed", severity="high",
                          impact="A saved untrusted comment executed same-origin JavaScript when a subsequent visitor loaded the comments page.")
            evidence["outcome"] = "Stored comment retrieved independently; its unique marker executed JavaScript in a fresh Chrome context with CSP enabled."
        elif expected_alert in proof["test_alerts"]:
            raise ScanIncomplete("Current-marker alert observed without the required stored script evidence.")
        else:
            result["status"] = "not_detected"
            evidence["outcome"] = "The current comment was stored and retrieved, but its JavaScript did not execute in the controlled browser test."
    except (requests.RequestException, ScanIncomplete, ScanBlocked) as error:
        evidence["outcome"] = "Cannot reach the local comments lab within the request timeout." if isinstance(error, requests.RequestException) else str(error)
    except (ImportError, OSError):
        evidence["outcome"] = "Browser verification unavailable. Check installed Google Chrome and Python requirements."
    except Exception as error:
        if type(error).__module__.startswith("playwright"):
            evidence["outcome"] = "Google Chrome verification unavailable or timed out. Check installed Google Chrome, then retry."
        else:
            raise
    finally:
        cleanup_count = 0
        if submitted:
            # Independent quota/deadline ensures cleanup is attempted even after
            # a failed browser or an HTTP timeout. Token+marker match one row only.
            cleaner = StoredHTTP(origin)
            try:
                cleaned = receipt(cleaner.request("POST", origin + "/comments/cleanup",
                                  {"scanner_marker": marker, "cleanup_token": cleanup_token}), 200)
                if cleaned.get("deleted") is not True:
                    raise ScanIncomplete("No matching scanner comment was removed; inspect the comments page.")
                remaining = document(cleaner.get(endpoint))
                if marker in str(remaining):
                    raise ScanIncomplete("Current marker remains on the comments page after cleanup.")
                evidence["cleanup"] = {"status": "removed", "marker": marker, "comment_id": comment_id}
                result["tests"].append("scanner_comment_cleanup_verified")
            except (requests.RequestException, ScanIncomplete, ScanBlocked) as error:
                evidence["cleanup"] = {"status": "failed", "marker": marker,
                                       "detail": "Cleanup request failed; inspect the comments page." if isinstance(error, requests.RequestException) else str(error)}
            finally:
                cleanup_count = cleaner.count
                cleaner.close()
        evidence["local_http_requests"] = http.count + reader.count + cleanup_count
        http.close()
        reader.close()
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    return result
