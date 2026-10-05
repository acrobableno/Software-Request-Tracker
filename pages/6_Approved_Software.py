import pandas as pd
import streamlit as st

from utils import approvals
from utils.utility import require_role

require_role()
st.title("✅ Approved Software")
st.write("There is no pre-approved software. Software on this list was approved by an admin and "
         "may be installed by **everyone**, following any conditions in the notes. "
         "Anything not listed needs a software request.")

entries = approvals.register()
approved = [e for e in entries if approvals.is_approved(e)]
rejected = [e for e in entries if not approvals.is_approved(e)]
cols = ["software", "status", "version", "platform", "notes", "request_id", "date"]

if approved:
    st.dataframe(pd.DataFrame(approved)[cols], hide_index=True, use_container_width=True)
else:
    st.info("No software has been approved yet.")

if rejected:
    st.subheader("Rejected")
    st.dataframe(pd.DataFrame(rejected)[cols], hide_index=True, use_container_width=True)
