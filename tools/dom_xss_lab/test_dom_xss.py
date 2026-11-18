def test_dom_page_does_not_reflect_server_input(client):
    import app as site
    marker = "server-input-must-not-appear-42"
    page = client.get("/dom-xss?value=" + marker)
    assert page.status_code == 200
    assert marker.encode() not in page.data
    assert b'data-webguard-dom="v1"' in page.data
    assert b'/static/dom_xss_lab.js' in page.data
    assert page.headers["Cache-Control"] == "no-store"
    vulnerable = "site_a" in str(site.BASE_DIR)
    assert (b'data-rendering="unsafe"' in page.data) is vulnerable
    if vulnerable:
        assert "script-src 'self'" in page.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in page.headers["Content-Security-Policy"]


def test_dom_assets_and_local_guard(client):
    for path in ("/static/dom_xss_lab.js", "/static/xss_dom_demo.js"):
        response = client.get(path)
        assert response.status_code == 200
        assert "javascript" in response.content_type
    assert client.get("/dom-xss", environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code == 403
