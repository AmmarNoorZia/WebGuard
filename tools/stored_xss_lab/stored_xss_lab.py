"""Local-only comments exercise shared by the two WebGuard dummy sites.

Only A deliberately renders unescaped comment HTML. Cleanup requires a private
capability and a unique scanner marker, so it cannot delete ordinary comments.
"""
import hashlib
import re
import secrets

from flask import abort, jsonify, redirect, render_template, request, session

MARKER = re.compile(r"webguard-stored-[a-f0-9]{32}\Z")
TOKEN = re.compile(r"[a-f0-9]{64}\Z")


def register_comments(app, get_db, *, vulnerable):
    with app.app_context():
        get_db().execute("""CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            body TEXT NOT NULL,
            scanner_marker TEXT UNIQUE,
            cleanup_hash TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        get_db().commit()

    @app.route("/comments", methods=["GET", "POST"])
    def comments():
        if request.method == "POST":
            csrf = request.form.get("csrf_token", "")
            if not TOKEN.fullmatch(csrf) or not secrets.compare_digest(csrf, session.get("comments_csrf", "")):
                abort(400)
            body = request.form.get("body", "")
            if not body.strip() or len(body) > 2000:
                abort(400)
            marker = request.form.get("scanner_marker")
            token = request.form.get("cleanup_token", "")
            if marker is not None and (not MARKER.fullmatch(marker) or not TOKEN.fullmatch(token)):
                abort(400)
            db = get_db()
            # Parameterization protects SQL even on the intentionally unsafe A page.
            if marker and db.execute("SELECT id FROM comments WHERE scanner_marker = ?", (marker,)).fetchone():
                abort(409)
            saved = db.execute("INSERT INTO comments(body, scanner_marker, cleanup_hash) VALUES (?, ?, ?)",
                               (body, marker, hashlib.sha256(token.encode()).hexdigest() if marker else None))
            db.commit()
            if marker:
                return jsonify(id=saved.lastrowid, marker=marker), 201
            return redirect("/comments", code=303)
        if "comments_csrf" not in session:
            session["comments_csrf"] = secrets.token_hex(32)
        response = app.make_response(render_template("comments.html", comments=get_db().execute(
            "SELECT id, body, created_at FROM comments ORDER BY id DESC").fetchall(),
            csrf_token=session["comments_csrf"], vulnerable=vulnerable))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/comments/cleanup")
    def cleanup_scanner_comment():
        marker = request.form.get("scanner_marker", "")
        token = request.form.get("cleanup_token", "")
        if not MARKER.fullmatch(marker) or not TOKEN.fullmatch(token):
            abort(400)
        db = get_db()
        removed = db.execute("DELETE FROM comments WHERE scanner_marker = ? AND cleanup_hash = ?",
                             (marker, hashlib.sha256(token.encode()).hexdigest()))
        db.commit()
        return jsonify(deleted=removed.rowcount == 1)
