import pytest


def pytest_addoption(parser):
    parser.addoption("--run-browser-fixtures", action="store_true", help="Start disposable A/B test fixtures on free ports 5001/5002")
    parser.addoption("--run-live-labs", action="store_true", help="Scan existing authorized A/B websites on 5001/5002")
    parser.addoption("--run-ui", action="store_true", help="Test React with a running Vite frontend and a disposable API/database")


def pytest_collection_modifyitems(config, items):
    for item in items:
        for marker, option in [("browser", "--run-browser-fixtures"), ("live", "--run-live-labs"), ("ui", "--run-ui")]:
            if marker in item.keywords and not config.getoption(option):
                item.add_marker(pytest.mark.skip(reason=f"Opt in with {option}"))
