"""WebGuard foundation API.

Contains authenticated target CRUD and audit history, NOT vulnerability scanners.
This development service binds to loopback. Never accept arbitrary external URLs.
"""

from __future__ import annotations

import os
import uuid
from functools import wraps
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request

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
        raise ApiError("Database operation failed. Ensure supabase/schema.sql has been applied.", 502)
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
    return jsonify({"status": "ok", "product": "WebGuard", "version": "0.2.0", "supabase_configured": CONFIGURED, "scanner_ready": False})


@app.get("/api/features")
def features():
    return jsonify({
        "scanner_ready": False,
        "features": [
            {"id": "sqli", "label": "SQL Injection", "status": "planned"},
            {"id": "xss", "label": "Cross-Site Scripting", "status": "planned"},
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


if __name__ == "__main__":
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", "5000")), debug=False)
