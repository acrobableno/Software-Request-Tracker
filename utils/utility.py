"""Shared helpers: secrets access and password protection (AI Bootcamp 8.2)."""
import hmac

import streamlit as st


def get_secret(key, default=None):
    """Read a value from .streamlit/secrets.toml without crashing if it is missing."""
    try:
        return st.secrets.get(key, default)
    except Exception:  # no secrets.toml at all
        return default


def _users():
    """Accounts from secrets.toml:  [users.<name>] password = "..."  role = "user" | "admin"."""
    users = get_secret("users", {}) or {}
    return {name: dict(cfg) for name, cfg in users.items()}


def login_form():
    """Username + password login (extends AI Bootcamp 8.2 check_password with roles)."""
    users = _users()
    if not users:
        st.error("No accounts configured. Add [users.user] and [users.admin] to .streamlit/secrets.toml.")
        return
    with st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Log in", type="primary"):
            account = users.get(username.strip())
            if account and hmac.compare_digest(password.encode(), str(account.get("password", "")).encode()):
                st.session_state["user"] = {"username": username.strip(), "role": account.get("role", "user")}
                st.rerun()
            st.error("😕 Username or password incorrect")


def current_user():
    return st.session_state.get("user")


def logout():
    st.session_state.pop("user", None)


def require_role(*roles):
    """Stop the page unless someone is logged in (and has one of `roles`, if given)."""
    user = current_user()
    if not user:
        st.warning("Please log in from the home page.")
        st.stop()
    if roles and user["role"] not in roles:
        st.error("You don't have access to this page.")
        st.stop()
    return user
