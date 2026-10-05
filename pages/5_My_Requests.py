import pandas as pd
import streamlit as st

from utils import db
from utils.utility import require_role

user = require_role()
st.title("📨 My Requests")

rows = db.list_requests(submitted_by=user["username"])
if not rows:
    st.info("You haven't submitted any requests yet.")
    st.stop()

df = pd.DataFrame(rows)[["id", "created_at", "software_name", "requested_version", "platform",
                         "latest_version", "status", "reviewer_notes"]]
st.dataframe(df, hide_index=True, use_container_width=True,
             column_config={"reviewer_notes": st.column_config.TextColumn("admin notes", width="large")})
pending = (df["status"] == "Pending Review").sum()
st.caption(f"{pending} request(s) waiting for admin review. Only software with status Approved "
           "(or Approved with Conditions) may be installed.")
