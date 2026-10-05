"""Shared helpers: secrets access and password protection (AI Bootcamp 8.2)."""
import hmac

import streamlit as st


def get_secret(key, default=None):
    """Read a value from .streamlit/secrets.toml without crashing if it is missing."""
    try:
        return st.secrets.get(key, default)
    except Exception:  # no secrets.toml at all
        return default


def check_password():
    """Returns True if the user has entered the correct APP_PASSWORD."""
    expected = get_secret("APP_PASSWORD")
    if not expected:
        st.error("APP_PASSWORD is not set in .streamlit/secrets.toml.")
        return False

    def password_entered():
        if hmac.compare_digest(st.session_state["password"], expected):
            st.session_state["password_correct"] = True
            del st.session_state["password"]  # don't keep the password around
        else:
            st.session_state["password_correct"] = False

    if st.session_state.get("password_correct", False):
        return True

    st.text_input("Password", type="password", on_change=password_entered, key="password")
    if "password_correct" in st.session_state:
        st.error("😕 Password incorrect")
    return False
