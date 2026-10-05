import json

import pandas as pd
import streamlit as st

from utils import db
from utils.assess import run_check
from utils.ui import RISK_BADGE, render_findings
from utils.utility import check_password

st.set_page_config(layout="wide", page_title="Review Requests")
if not check_password():
    st.stop()

db.init_db()
st.title("📋 Review Requests")

requests_ = db.list_requests()
if not requests_:
    st.info("No requests yet.")
    st.stop()

df = pd.DataFrame(requests_)
status_filter = st.multiselect("Status", db.STATUSES, default=db.STATUSES)
view = df[df["status"].isin(status_filter)]
cols = ["id", "created_at", "requester_name", "department", "software_name", "requested_version",
        "latest_version", "risk_level", "status"]
st.dataframe(view[cols], hide_index=True, use_container_width=True)
st.download_button("Download CSV", view.drop(columns=["check_json"]).to_csv(index=False),
                   file_name="software_requests.csv", mime="text/csv")

st.divider()
request_id = st.selectbox(
    "Open request", view["id"].tolist(),
    format_func=lambda i: f"#{i} — {df.loc[df.id == i, 'software_name'].iloc[0]} "
                          f"({df.loc[df.id == i, 'requester_name'].iloc[0]})")
if request_id is None:
    st.stop()

req = db.get_request(int(request_id))
left, right = st.columns([2, 1])

with right:
    st.subheader(f"Request #{req['id']}")
    st.markdown(f"**{req['software_name']}** {req['requested_version'] or '(latest)'} · {req['platform']}  \n"
                f"By {req['requester_name']} {('<' + req['requester_email'] + '>') if req['requester_email'] else ''}"
                f" · {req['department'] or '-'}  \nSubmitted {req['created_at']}")
    st.markdown(f"**Justification:** {req['purpose']}")

    with st.form("decision"):
        status = st.selectbox("Decision", db.STATUSES, index=db.STATUSES.index(req["status"]))
        notes = st.text_area("Reviewer notes", value=req["reviewer_notes"] or "")
        if st.form_submit_button("Save decision", type="primary"):
            db.update_status(req["id"], status, notes)
            st.success("Saved.")
            st.rerun()

    with st.expander("Re-run check (optionally correct identifiers)"):
        st.caption("Leave blank to let the AI identify the product again.")
        ov = {
            "cpe_vendor": st.text_input("NVD CPE vendor", placeholder="e.g. 7-zip"),
            "cpe_product": st.text_input("NVD CPE product", placeholder="e.g. 7-zip"),
            "endoflife_slug": st.text_input("endoflife.date slug", placeholder="e.g. python"),
            "github_repo": st.text_input("GitHub repo (owner/repo)"),
            "package_ecosystem": st.selectbox("Package ecosystem", ["", "PyPI", "npm"]),
            "package_name": st.text_input("Package name"),
            "homebrew_cask": st.text_input("Homebrew cask"),
        }
        if st.button("Re-run check"):
            with st.status("Checking official sources…", expanded=True) as s:
                findings = run_check(req, overrides=ov, progress=st.write)
                db.save_check(req["id"], findings)
                s.update(label="Check complete", state="complete", expanded=False)
            st.rerun()

with left:
    if req["check_json"]:
        render_findings(json.loads(req["check_json"]))
    else:
        st.info("No check has been run for this request yet.")
