"""Entry point: login, then role-based navigation (user / admin)."""
import streamlit as st

from utils import db
from utils.utility import current_user, login_form, logout

st.set_page_config(page_title="Software Request Portal", page_icon="🧾", layout="wide")
db.init_db()

user = current_user()
if not user:
    st.title("🧾 Software Request Portal")
    login_form()
    st.stop()

with st.sidebar:
    st.markdown(f"Signed in as **{user['username']}** · {user['role']}")
    if st.button("Log out"):
        logout()
        st.rerun()

submit = st.Page("pages/0_Submit_Request.py", title="Submit Request", icon="🧾")
mine = st.Page("pages/5_My_Requests.py", title="My Requests", icon="📨")
approved = st.Page("pages/6_Approved_Software.py", title="Approved Software", icon="✅")
review = st.Page("pages/1_Review_Requests.py", title="Review Requests", icon="📋")
knowledge = st.Page("pages/4_Knowledge_Base.py", title="Policies", icon="📚")
ask = st.Page("pages/3_Ask_IT.py", title="Ask IT", icon="💬")
about = st.Page("pages/2_About.py", title="About", icon="ℹ️")

if user["role"] == "admin":
    pages = {"Admin": [review, knowledge], "Requests": [submit, mine, approved], "Help": [ask, about]}
else:
    pages = {"Requests": [submit, mine, approved], "Help": [ask, about]}

st.navigation(pages).run()
