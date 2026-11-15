"""Authenticated WebGuard API and restricted reflected-XSS lab scanning."""

from __future__ import annotations

import os
import uuid
from threading import BoundedSemaphore
from functools import wraps
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, send_file

from scanners.xss_reflected import ScanBlocked, run_scan, validate_target as validate_scan_target

load_dotenv()
app = Flask(__name__)
app.json.sort_keys = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY", "").strip()
CONFIGURED = bool(
    SUPABASE_URL.startswith("https://")
    and "YOUR-PROJECT" not in SUPABASE_URL.upper()
    and SUPABASE_KEY
    and "REPLACE_ME" not in SUPABASE_KEY.upper()
)
HTTP_TIMEOUT = 10
SCAN_SLOT = BoundedSemaphore(1)
ENVIRONMENTS = {
    "Local test",
    "Vulnerable / secure mix",
    "Protected test site",
    "Intentionally vulnerable lab",
}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        self.message = message
        self.status = status


@app.errorhandler(ApiError)
def custom_error(err: ApiError):
    return jsonify({"error": err.message}), err.status


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request body is too large."}), 413


def normalize_local_url(value: str) -> str:
    """Validate URL syntactically; never access the provided destination here."""
    if not isinstance(value, str) or len(value) > 512:
        raise ApiError("Enter a valid local website URL (max 512 characters).")
    if not value.strip():
        raise ApiError("Enter a local website URL, for example http://localhost:5001.")
    try:
        parts = urlsplit(value.strip())
        port = parts.port  # force validation of malformed ports
        hostname = (parts.hostname or "").lower()
    except (ValueError, AttributeError):
        raise ApiError("Enter a valid localhost URL, e.g. http://localhost:5001.")
    if (
        parts.scheme not in {"http", "https"}
        or hostname not in {"localhost", "127.0.0.1", "::1"}
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or not parts.netloc
        or (port is not None and not (1 <= port <= 65535))
    ):
        raise ApiError("Only HTTP(S) localhost / loopback test URLs are supported; credentials and fragments are not allowed.")
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc.lower(), path, parts.query, ""))


def supabase_headers(token: str) -> dict[str, str]:
    # User JWT ensures PostgreSQL RLS applies. No service-role secret is used.
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def authenticate(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not CONFIGURED:
            raise ApiError("Backend Supabase configuration missing. See backend/.env.example.", 503)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not auth[7:].strip():
            raise ApiError("Sign in to access this endpoint.", 401)
        token = auth[7:].strip()
        try:
            # Supabase Auth validates the JWT; never trust a client-supplied user ID.
            response = requests.get(
                f"{SUPABASE_URL}/auth/v1/user",
                headers=supabase_headers(token),
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException:
            raise ApiError("Authentication server is temporarily unavailable.", 503)
        if response.status_code != 200:
            raise ApiError("Your login session is invalid or expired.", 401)
        try:
            user = response.json()
        except ValueError:
            raise ApiError("Authentication returned an unexpected response.", 503)
        if not user.get("id"):
            raise ApiError("Authentication failed.", 401)
        g.user_id = user["id"]
        g.access_token = token
        return fn(*args, **kwargs)

    return wrapped


def table_request(method: str, table: str, *, params=None, payload=None, prefer=None):
    headers = supabase_headers(g.access_token)
    if prefer:
        headers["Prefer"] = prefer
    try:
        resp = requests.request(
            method,
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers=headers,
            params=params,
            json=payload,
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException:
        raise ApiError("Cannot connect to the Supabase database.", 503)
    if resp.status_code >= 400:
        # Avoid leaking database internals to the caller.
        if resp.status_code in (401, 403):
            raise ApiError("Database permission denied. Check RLS policies and authentication.", 403)
        if resp.status_code == 409:
            raise ApiError("This target is already registered.", 409)
        raise ApiError("Database operation failed. Apply supabase/schema.sql and supabase/migrations/001_scan_results.sql in SQL Editor.", 502)
    if not resp.content:
        return []
    try:
        return resp.json()
    except ValueError:
        return []


def record_event(event_type: str, description: str):
    try:
        table_request(
            "POST",
            "activity_events",
            payload={"user_id": g.user_id, "event_type": event_type, "description": description},
            prefer="return=minimal",
        )
    except ApiError:
        # Audit failures must not conceal a successful target operation;
        # production system should implement durable logging/monitoring.
        app.logger.warning("Could not record activity event")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "product": "WebGuard", "version": "0.3.0", "supabase_configured": CONFIGURED, "scanner_ready": True})


@app.get("/api/features")
def features():
    return jsonify({
        "scanner_ready": True,
        "features": [
            {"id": "sqli", "label": "SQL Injection", "status": "planned"},
            {"id": "xss", "label": "Reflected Cross-Site Scripting", "status": "implemented", "module": "xss_reflected"},
            {"id": "headers", "label": "Security Headers", "status": "planned"},
            {"id": "cookies", "label": "Insecure Cookies", "status": "planned"},
            {"id": "files", "label": "Sensitive Resources", "status": "planned"},
        ],
    })


@app.get("/api/me")
@authenticate
def me():
    return jsonify({"id": g.user_id, "authenticated": True})


@app.get("/api/targets")
@authenticate
def list_targets():
    items = table_request("GET", "targets", params={"select": "id,name,url,environment,created_at", "user_id": f"eq.{g.user_id}", "order": "created_at.desc", "limit": "100"})
    return jsonify({"targets": items})


@app.post("/api/targets")
@authenticate
def create_target():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Expected a JSON object.")
    name = str(data.get("name", "")).strip()
    environment = data.get("environment") or "Local test"
    if not name or len(name) > 80:
        raise ApiError("Target name must be 1 to 80 characters.")
    if environment not in ENVIRONMENTS:
        raise ApiError("Unknown environment type.")
    url = normalize_local_url(data.get("url"))
    created = table_request(
        "POST", "targets",
        payload={"user_id": g.user_id, "name": name, "url": url, "environment": environment},
        prefer="return=representation",
    )
    record_event("target_added", f"Added target: {name}")
    return jsonify({"target": created[0] if created else None}), 201


@app.delete("/api/targets/<target_id>")
@authenticate
def delete_target(target_id):
    try:
        uuid.UUID(target_id)
    except (ValueError, TypeError):
        raise ApiError("Invalid target ID.")
    rows = table_request("GET", "targets", params={"select": "id,name", "id": f"eq.{target_id}", "user_id": f"eq.{g.user_id}", "limit": "1"})
    if not rows:
        raise ApiError("Target not found.", 404)
    table_request("DELETE", "targets", params={"id": f"eq.{target_id}", "user_id": f"eq.{g.user_id}"})
    record_event("target_removed", f"Removed target: {rows[0]['name']}")
    return jsonify({"deleted": True})


@app.get("/api/activity")
@authenticate
def list_activity():
    items = table_request("GET", "activity_events", params={"select": "id,event_type,description,created_at", "user_id": f"eq.{g.user_id}", "order": "created_at.desc", "limit": "50"})
    return jsonify({"activity": items})


@app.post("/api/targets/validate")
@authenticate
def validate_target():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Expected a JSON object.")
    # Does not perform an HTTP request to the target.
    return jsonify({"accepted": True, "url": normalize_local_url(data.get("url")), "connected": False})


def require_uuid(value, label):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ApiError(f"Invalid {label} ID.")


@app.post("/api/scans/xss")
@authenticate
def scan_xss():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"target_id"}:
        raise ApiError("Send only the registered target_id in a JSON object.")
    target_id = require_uuid(data["target_id"], "target")
    rows = table_request("GET", "targets", params={"select": "id,name,url", "id": f"eq.{target_id}", "user_id": f"eq.{g.user_id}", "limit": "1"})
    if not rows:
        raise ApiError("Target not found.", 404)
    target = rows[0]
    try:
        validate_scan_target(target["url"])
    except ScanBlocked as error:
        raise ApiError(str(error))
    # Fail before testing if the required migration/table is not available.
    table_request("GET", "scan_runs", params={"select": "id", "user_id": f"eq.{g.user_id}", "limit": "1"})
    if not SCAN_SLOT.acquire(blocking=False):
        raise ApiError("A local scan is already running. Retry when it finishes.", 429)
    try:
        try:
            result = run_scan(target["url"])
        except ScanBlocked as error:
            raise ApiError(str(error))
        try:
            saved = table_request("POST", "rpc/save_scan_run", payload={"p_target_id": target_id, "p_result": result})
            if not isinstance(saved, dict) or not saved.get("id"):
                raise ApiError("Database did not return the saved scan.", 502)
        except ApiError as error:
            return jsonify({"error": f"Test ran, but results were NOT saved. {error.message}",
                            "scan": {"target_snapshot": target, "result": result}, "persisted": False}), error.status
        record_event("scan_completed", f"Reflected XSS: {target['name']} - {result['status']}")
        return jsonify({"scan": saved, "persisted": True}), 201
    finally:
        SCAN_SLOT.release()


@app.get("/api/scans")
@authenticate
def list_scans():
    rows = table_request("GET", "scan_runs", params={"select": "*", "user_id": f"eq.{g.user_id}", "order": "created_at.desc", "limit": "100"})
    return jsonify({"scans": rows})


@app.get("/api/findings")
@authenticate
def list_findings():
    rows = table_request("GET", "security_findings", params={"select": "*,scan_runs(target_snapshot,result,completed_at)", "user_id": f"eq.{g.user_id}", "order": "created_at.desc", "limit": "100"})
    return jsonify({"findings": rows})


@app.get("/api/scans/<scan_id>/report.pdf")
@authenticate
def download_report(scan_id):
    from reporting.pdf import build_report

    scan_id = require_uuid(scan_id, "scan")
    rows = table_request("GET", "scan_runs", params={"select": "*", "id": f"eq.{scan_id}", "user_id": f"eq.{g.user_id}", "limit": "1"})
    if not rows:
        raise ApiError("Scan not found.", 404)
    response = send_file(build_report(rows[0]), mimetype="application/pdf", as_attachment=True,
                         download_name=f"webguard-{scan_id}.pdf", max_age=0)
    response.headers["Cache-Control"] = "private, no-store"
    return response


if __name__ == "__main__":
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", "5000")), debug=False)
