
from pathlib import Path
from streamlit.testing.v1 import AppTest


# Resolve app.py from the project root
APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def run_dashboard():
    return AppTest.from_file(
        str(APP_PATH),
        default_timeout=15
    ).run()


def test_dashboard_loads_without_errors():
    app = run_dashboard()
    assert not app.exception


def test_dashboard_displays_main_title():
    app = run_dashboard()

    assert not app.exception
    assert any(
        "Mini SOC" in title.value
        for title in app.title
    )


def test_windows_authentication_page_loads():
    app = run_dashboard()
    app.radio[0].set_value("Windows Authentication").run()
    assert not app.exception


def test_security_alerts_page_loads():
    app = run_dashboard()
    app.radio[0].set_value("Security Alerts").run()
    assert not app.exception


def test_ml_detection_page_loads():
    app = run_dashboard()
    app.radio[0].set_value("ML Detection").run()
    assert not app.exception


def test_overview_page_loads():
    app = run_dashboard()
    app.radio[0].set_value("Overview").run()
    assert not app.exception

