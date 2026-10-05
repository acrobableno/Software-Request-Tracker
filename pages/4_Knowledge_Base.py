from pathlib import Path

import streamlit as st

from utils import rag
from utils.ui import render_chunks
from utils.utility import require_role

require_role("admin")

st.title("📚 Policies")
st.write("Policy documents used by the AI assessment and the Ask IT chatbot. "
         "Past review decisions are indexed automatically.")
st.warning("Files uploaded here are lost when the app restarts on Streamlit Community Cloud. "
           "To keep them, add them to the `policies/` folder in GitHub and push.")

# ---- documents
files = rag.policy_files()
st.subheader(f"Documents ({len(files)})")
for path in files:
    col1, col2 = st.columns([5, 1])
    col1.markdown(f"📄 **{path.name}** · {path.stat().st_size / 1024:.1f} KB")
    if col2.button("Remove", key=f"rm_{path.name}"):
        path.unlink()
        st.rerun()

uploads = st.file_uploader("Add policy documents", type=["pdf", "md", "txt"], accept_multiple_files=True)
if uploads and st.button("Save and re-index", type="primary"):
    for f in uploads:
        (rag.POLICY_DIR / Path(f.name).name).write_bytes(f.getvalue())  # basename only
    st.success(f"Saved {len(uploads)} file(s). The index rebuilds automatically.")
    st.rerun()

# ---- edit text policies in place
editable = [p for p in files if p.suffix.lower() in (".md", ".txt")]
if editable:
    st.subheader("Edit a policy")
    target = st.selectbox("Document", editable, format_func=lambda p: p.name)
    text = st.text_area("Content (Markdown)", target.read_text(encoding="utf-8"), height=400,
                        key=f"edit_{target.name}")
    if st.button("Save changes"):
        target.write_text(text, encoding="utf-8")
        st.success(f"Saved {target.name}. The index rebuilds automatically.")

if not rag.rag_available():
    st.info("Indexing needs OPENAI_API_KEY in the app secrets.")
    st.stop()

# ---- index status + retrieval test (useful for checking retrieval quality, Topic 4.5)
policy_store, decision_store = rag.policy_store(), rag.decision_store()
c1, c2 = st.columns(2)
c1.metric("Policy chunks indexed", policy_store._collection.count() if policy_store else 0)
c2.metric("Past decisions indexed", decision_store._collection.count() if decision_store else 0)

st.subheader("Test retrieval")
query = st.text_input("Search the knowledge base", placeholder="e.g. remote access tools")
if query:
    render_chunks(rag.retrieve_policy(query, k=4), rag.retrieve_precedents(query, k=3))
