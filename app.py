import streamlit as st

from minihub.config import load_css
from minihub.ui.views import dashboard_page, init_session, login_page, repo_page

st.set_page_config(page_title="MiniHub Cloud", layout="wide", page_icon="☁️")


def main():
    """Main application entry point."""
    load_css()
    init_session()

    view = st.session_state.view
    if view == "login":
        login_page()
    elif view == "dashboard":
        dashboard_page()
    elif view == "repo":
        repo_page()
    else:
        st.error("Unknown view state")


if __name__ == "__main__":
    main()
