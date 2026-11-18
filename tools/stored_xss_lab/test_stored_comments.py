import secrets
import uuid
import re


def submit(client, body, **extra):
    page = client.get("/comments").get_data(as_text=True)
    csrf = re.search(r'name="csrf_token" value="([a-f0-9]+)"', page).group(1)
    return client.post("/comments", data={"body": body, "csrf_token": csrf, **extra})


def test_comments_persist_and_escape_according_to_lab(client):
    import app as site
    marker = uuid.uuid4().hex
    payload = f'<script id="{marker}" src="/static/xss_stored_demo.js"></script>'
    assert submit(client, payload).status_code == 303
    with site.app.test_client() as other:
        saved = other.get("/comments")
    assert marker.encode() in saved.data
    vulnerable = "site_a" in site.app.config["DATABASE"] or "site_a" in str(site.BASE_DIR)
    assert (f'<script id="{marker}"'.encode() in saved.data) is vulnerable


def test_cleanup_requires_matching_capability_and_preserves_other_comments(client):
    ordinary = "keep-" + uuid.uuid4().hex
    submit(client, ordinary)
    marker = "webguard-stored-" + uuid.uuid4().hex
    token = secrets.token_hex(32)
    assert submit(client, marker, scanner_marker=marker, cleanup_token=token).status_code == 201
    assert client.post("/comments/cleanup", data={"scanner_marker": marker, "cleanup_token": "0" * 64}).json == {"deleted": False}
    assert marker.encode() in client.get("/comments").data
    assert client.post("/comments/cleanup", data={"scanner_marker": marker, "cleanup_token": token}).json == {"deleted": True}
    page = client.get("/comments").data
    assert marker.encode() not in page
    assert ordinary.encode() in page
    assert client.post("/comments/cleanup", data={"scanner_marker": "", "cleanup_token": token}).status_code == 400


def test_comment_validation_and_csrf(client):
    assert client.post("/comments", data={"body": "without csrf"}).status_code == 400
    assert client.post("/comments", data={"body": "bad csrf", "csrf_token": "\u2603"}).status_code == 400
    assert submit(client, "").status_code == 400
    assert submit(client, "x" * 2001).status_code == 400
    assert submit(client, "test", scanner_marker="wrong", cleanup_token="x").status_code == 400
