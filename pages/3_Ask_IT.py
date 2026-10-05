import streamlit as st

from utils import approvals, rag
from utils.llm import chat_stream
from utils.ui import render_chunks
from utils.utility import require_role

require_role()

st.title("💬 Ask IT")
st.write("Ask about the software policy — e.g. *Can I install Zoom?*, *Which software is approved?* or *What do I need to use TeamViewer?*")

if not rag.rag_available():
    st.info("This chatbot needs OPENAI_API_KEY in the app secrets.")
    st.stop()

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []

with st.sidebar:
    if st.button("Clear conversation"):
        st.session_state.chat_messages = []
        st.rerun()

for message in st.session_state.chat_messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if question := st.chat_input("Ask a question about software policy"):
    st.session_state.chat_messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    # Context: the full approved-software register (exact, from the database) + relevant policy chunks (RAG)
    register = approvals.register()
    policy = rag.retrieve_policy(question, k=5)

    with st.chat_message("assistant"):
        try:
            history = st.session_state.chat_messages[-6:]  # last few turns keep the prompt small
            stream = chat_stream(history, rag.format_policy(policy), approvals.format_register(register))
            answer = st.write_stream(stream)
        except Exception as e:
            answer = f"Error: {e}"
            st.error(answer)
        with st.expander("Sources"):
            related = [e for e in register if approvals.names_match(e["software"], question)]
            if related:
                st.markdown("**Approved-software register**")
                st.markdown(approvals.format_register(related))
            render_chunks(policy, None)
    st.session_state.chat_messages.append({"role": "assistant", "content": answer})
