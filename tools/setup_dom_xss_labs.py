"""Install DOM lab support into the two explicitly authorized Desktop sites.

Preserves existing security hooks, comments, search, and database contents.
Safe to repeat; restart the sites after installation.
"""
from pathlib import Path
import shutil

SOURCE = Path(__file__).resolve().parent / "dom_xss_lab"
DESKTOP = Path.home() / "Desktop"


def main():
    for letter in ("a", "b"):
        root = (DESKTOP / f"webguard_dummy_site_{letter}").resolve()
        if root.parent != DESKTOP.resolve() or not (root / "app.py").is_file():
            raise SystemExit(f"Expected lab is unavailable: {root}")
        app_path = root / "app.py"
        source = app_path.read_text(encoding="utf-8")
        anchor = 'if __name__ == "__main__":'
        if anchor not in source:
            raise SystemExit(f"Cannot find startup block: {app_path}")
        for name, destination in [("dom_xss_lab.py", "dom_xss_lab.py"),
                                  ("dom_xss.html", "templates/dom_xss.html"),
                                  ("dom_xss_lab.js", "static/dom_xss_lab.js"),
                                  ("xss_dom_demo.js", "static/xss_dom_demo.js"),
                                  ("test_dom_xss.py", "tests/test_dom_xss.py")]:
            shutil.copyfile(SOURCE / name, root / destination)
        if "from dom_xss_lab import register_dom_page" not in source:
            registration = ("from dom_xss_lab import register_dom_page\n"
                            f"register_dom_page(app, vulnerable={letter == 'a'})\n\n\n")
            app_path.write_text(source.replace(anchor, registration + anchor, 1), encoding="utf-8")
        base = root / "templates/base.html"
        template = base.read_text(encoding="utf-8")
        if 'href="/dom-xss"' not in template:
            template = template.replace('<a href="/comments">Comments</a>',
                                        '<a href="/comments">Comments</a>\n    <a href="/dom-xss">DOM input</a>', 1)
            base.write_text(template, encoding="utf-8")
        if letter == "a":
            test_path = root / "tests/test_site_a.py"
            original = test_path.read_text(encoding="utf-8")
            updated = original.replace('{"style.css", "xss_demo.js", "xss_stored_demo.js"}',
                                       '{"style.css", "xss_demo.js", "xss_stored_demo.js", "dom_xss_lab.js", "xss_dom_demo.js"}')
            if updated != original:
                test_path.write_text(updated, encoding="utf-8")
        print(f"Installed /dom-xss in {root}; restart the website.")


if __name__ == "__main__":
    main()
