"""Install additive comments support into the two explicitly named Desktop labs.

Run with WebGuard's Python. Existing app.py/base.html content is preserved except
for one route registration and one navigation link. No databases are reset.
"""
from pathlib import Path
import shutil

SOURCE = Path(__file__).resolve().parent / "stored_xss_lab"
DESKTOP = Path.home() / "Desktop"


def main():
    for letter in ("a", "b"):
        root = (DESKTOP / f"webguard_dummy_site_{letter}").resolve()
        if root.parent != DESKTOP.resolve() or not (root / "app.py").is_file():
            raise SystemExit(f"Expected lab is unavailable: {root}")
        app_path = root / "app.py"
        app_source = app_path.read_text(encoding="utf-8")
        anchor = 'if __name__ == "__main__":'
        if anchor not in app_source:
            raise SystemExit(f"Cannot locate startup block: {app_path}")
        registration = ("from stored_xss_lab import register_comments\n"
                        f"register_comments(app, get_db, vulnerable={letter == 'a'})\n\n\n")
        if "from stored_xss_lab import register_comments" not in app_source:
            app_path.write_text(app_source.replace(anchor, registration + anchor, 1), encoding="utf-8")
        for source, destination in [("stored_xss_lab.py", "stored_xss_lab.py"),
                                    ("comments.html", "templates/comments.html"),
                                    ("xss_stored_demo.js", "static/xss_stored_demo.js"),
                                    ("test_stored_comments.py", "tests/test_stored_comments.py")]:
            shutil.copyfile(SOURCE / source, root / destination)
        if letter == "a":
            # Preserve the existing strict static-file allowlist regression test
            # while acknowledging the one new harmless local script.
            test_path = root / "tests" / "test_site_a.py"
            test_source = test_path.read_text(encoding="utf-8")
            updated = test_source.replace('{"style.css", "xss_demo.js"}',
                                          '{"style.css", "xss_demo.js", "xss_stored_demo.js"}')
            if updated != test_source:
                test_path.write_text(updated, encoding="utf-8")
        base = root / "templates" / "base.html"
        template = base.read_text(encoding="utf-8")
        if 'href="/comments"' not in template:
            template = template.replace('<a href="{{ url_for(\'search\') }}">Search</a>',
                                        '<a href="{{ url_for(\'search\') }}">Search</a>\n    <a href="/comments">Comments</a>', 1)
            base.write_text(template, encoding="utf-8")
        print(f"Installed comments support: {root}. Restart this lab to create its comments table.")


if __name__ == "__main__":
    main()
