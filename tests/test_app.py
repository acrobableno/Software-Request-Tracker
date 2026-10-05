"""Smoke test the Streamlit pages end-to-end with mocked sources."""
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from streamlit.testing.v1 import AppTest
from utils import db
from tests.test_check import mock, fake_get  # noqa: F401  (autouse fixture)

def test_submit_and_review(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
    at.secrets["APP_PASSWORD"] = "pw"
    at.run()
    at.text_input(key="password").input("wrong").run()
    assert "incorrect" in at.error[0].value
    at.text_input(key="password").input("pw").run()
    ti = at.text_input
    ti[0].input("Alice"); ti[3].input("Python"); ti[4].input("3.8.10"); at.text_area[0].input("data scripts")
    at.button[0].click().run()
    assert not at.exception, at.exception
    assert any("Request #1 recorded" in s.value for s in at.success)
    assert "High" in at.metric[0].value
    row = db.get_request(1)
    assert row["risk_level"] == "High" and row["latest_version"] == "3.13.7"

    rv = AppTest.from_file(str(ROOT / "pages/1_Review_Requests.py"), default_timeout=30)
    rv.secrets["APP_PASSWORD"] = "pw"; rv.session_state["password_correct"] = True
    rv.run()
    assert not rv.exception, rv.exception
    rv.selectbox[1].select("Approved with Conditions"); rv.text_area[0].input("upgrade to 3.13")
    rv.button[0].click().run()   # "Save decision"
    assert db.get_request(1)["status"] == "Approved with Conditions"

    rv.button[1].click().run()   # "Re-run check"
    assert not rv.exception, rv.exception

    ab = AppTest.from_file(str(ROOT / "pages/2_About.py")); ab.secrets["APP_PASSWORD"] = "pw"
    ab.session_state["password_correct"] = True; ab.run(); assert not ab.exception
