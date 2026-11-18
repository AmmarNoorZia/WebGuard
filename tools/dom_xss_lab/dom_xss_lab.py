"""Additive, loopback-only DOM XSS exercise; existing lab hooks still apply."""
from flask import abort, render_template, request


def register_dom_page(app, *, vulnerable):
    @app.get("/dom-xss")
    def dom_xss():
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            abort(403)
        # Fragments never reach Flask. Do not interpolate request input here.
        response = app.make_response(render_template("dom_xss.html", vulnerable=vulnerable))
        response.headers["Cache-Control"] = "no-store"
        return response
