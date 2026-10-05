"""Smoke test the Streamlit app end-to-end with mocked sources: login, roles, submit, review."""
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from streamlit.testing.v1 import AppTest
from utils import db
from tests.test_check import mock, fake_get  # noqa: F401  (autouse fixture)

USERS = {"user": {"password": "u-pw", "role": "user"}, "admin": {"password": "a-pw", "role": "admin"}}


def app(role=None):
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
    at.secrets["users"] = USERS
    if role:
        at.session_state["user"] = {"username": role, "role": role}
    return at


def page(path, role):
    at = AppTest.from_file(str(ROOT / path), default_timeout=30)
    at.session_state["user"] = {"username": role, "role": role}
    return at


def test_login_and_role_navigation(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    at = app(); at.run()
    at.text_input[0].input("user"); at.text_input[1].input("wrong"); at.button[0].click().run()
    assert "incorrect" in at.error[0].value
    at.text_input[0].input("admin"); at.text_input[1].input("a-pw"); at.button[0].click().run()
    assert not at.exception, at.exception
    assert at.session_state["user"] == {"username": "admin", "role": "admin"}
    assert at.title[0].value == "📋 Review Requests"          # admin lands on the review queue

    u = app("user"); u.run()
    assert not u.exception, u.exception
    assert u.title[0].value == "🧾 Software Request"          # user lands on the request form


def test_user_cannot_open_admin_pages(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    for path in ("pages/1_Review_Requests.py", "pages/4_Knowledge_Base.py"):
        at = page(path, "user"); at.run()
        assert "don't have access" in at.error[0].value and not at.title
    anon = AppTest.from_file(str(ROOT / "pages/0_Submit_Request.py")); anon.run()
    assert "log in" in anon.warning[0].value


def test_submit_track_and_review(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    at = page("pages/0_Submit_Request.py", "user"); at.run()
    ti = at.text_input
    ti[0].input("Alice"); ti[3].input("Python"); ti[4].input("3.8.10"); at.text_area[0].input("data scripts")
    at.button[0].click().run()
    assert not at.exception, at.exception
    assert any("Request #1 recorded" in s.value for s in at.success)
    assert "High" in at.metric[0].value
    row = db.get_request(1)
    assert row["risk_level"] == "High" and row["latest_version"] == "3.13.7" and row["submitted_by"] == "user"

    mine = page("pages/5_My_Requests.py", "user"); mine.run()
    assert not mine.exception and mine.dataframe[0].value["software_name"].tolist() == ["Python"]
    other = page("pages/5_My_Requests.py", "admin"); other.run()
    assert "haven't submitted" in other.info[0].value        # only your own requests

    rv = page("pages/1_Review_Requests.py", "admin"); rv.run()
    assert not rv.exception, rv.exception
    rv.selectbox[0].select("Approved with Conditions"); rv.text_area[0].input("upgrade to 3.13")
    rv.button[0].click().run()   # "Save decision"
    assert db.get_request(1)["status"] == "Approved with Conditions"
    rv.button[1].click().run()   # "Re-run check"
    assert not rv.exception, rv.exception

    mine.run()
    assert mine.dataframe[0].value["status"].tolist() == ["Approved with Conditions"]

    ab = page("pages/2_About.py", "user"); ab.run(); assert not ab.exception
