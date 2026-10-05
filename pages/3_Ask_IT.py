import streamlit as st

from utils import rag
from utils.llm import chat_stream
from utils.ui import render_chunks
from utils.utility import require_role

require_role()

st.title("💬 Ask IT")
st.write("Ask about the software policy — e.g. *Can I install TeamViewer?* or *What do I need to use Dropbox?*")

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

    # Retrieve: policy chunks + similar past decisions for this question
    policy = rag.retrieve_policy(question, k=5)
    precedents = rag.retrieve_precedents(question, k=3)

    with st.chat_message("assistant"):
        try:
            history = st.session_state.chat_messages[-6:]  # last few turns keep the prompt small
            stream = chat_stream(history, rag.format_policy(policy), rag.format_precedents(precedents))
            answer = st.write_stream(stream)
        except Exception as e:
            answer = f"Error: {e}"
            st.error(answer)
        with st.expander("Sources"):
            render_chunks(policy, precedents)
    st.session_state.chat_messages.append({"role": "assistant", "content": answer})
