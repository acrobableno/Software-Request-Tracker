import streamlit as st

from utils import db
from utils.assess import run_check
from utils.llm import llm_available
from utils.ui import render_findings
from utils.utility import require_role

user = require_role()  # any logged-in account
db.init_db()

st.title("🧾 Software Request")
st.write("All software is **not allowed by default** — request it here. We'll check the latest official "
         "version and known vulnerabilities, and an admin will review your request.")
if not llm_available():
    st.info("OPENAI_API_KEY not set — running without AI identification/summary (lookups still work).")

with st.form("request_form", clear_on_submit=False):
    col1, col2 = st.columns(2)
    requester_name = col1.text_input("Your name *")
    requester_email = col2.text_input("Email")
    department = st.text_input("Department / team")
    col3, col4 = st.columns(2)
    software_name = col3.text_input("Software name *", placeholder="e.g. 7-Zip, Notepad++, Python")
    requested_version = col4.text_input("Version (blank = latest)", placeholder="e.g. 23.01")
    platform = st.selectbox("Platform", ["Windows", "macOS", "Linux", "Web / SaaS", "Other"])
    purpose = st.text_area("Business justification *", height=100)
    submitted = st.form_submit_button("Submit request", type="primary")

if submitted:
    if not (requester_name.strip() and software_name.strip() and purpose.strip()):
        st.error("Please fill in all fields marked *.")
        st.stop()
    request_id = db.add_request(requester_name.strip(), requester_email.strip(), department.strip(),
                                software_name.strip(), requested_version.strip(), platform, purpose.strip(),
                                submitted_by=user["username"])
    request = db.get_request(request_id)
    with st.status("Checking official sources…", expanded=True) as status:
        findings = run_check(request, progress=st.write)
        db.save_check(request_id, findings)
        status.update(label="Check complete", state="complete", expanded=False)
    st.success(f"Request #{request_id} recorded and sent for review.")
    render_findings(findings)
