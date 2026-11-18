import pytest


def pytest_addoption(parser):
    parser.addoption("--run-browser-fixtures", action="store_true", help="Start disposable A/B test fixtures on free ports 5001/5002")
    parser.addoption("--run-live-labs", action="store_true", help="Scan existing authorized A/B websites on 5001/5002")
    parser.addoption("--live-lab-host", choices=["127.0.0.1", "::1"], default="127.0.0.1", help="Loopback address used by the opt-in actual lab tests")
    parser.addoption("--run-ui", action="store_true", help="Test React with a running Vite frontend and a disposable API/database")


def pytest_collection_modifyitems(config, items):
    for item in items:
        for marker, option in [("browser", "--run-browser-fixtures"), ("live", "--run-live-labs"), ("ui", "--run-ui")]:
            if marker in item.keywords and not config.getoption(option):
                item.add_marker(pytest.mark.skip(reason=f"Opt in with {option}"))


@pytest.fixture
def live_origins(request):
    host = request.config.getoption("--live-lab-host")
    authority = "[::1]" if host == "::1" else host
    return {port: f"http://{authority}:{port}" for port in (5001, 5002)}
