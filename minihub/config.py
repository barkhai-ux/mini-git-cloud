import streamlit as st
from supabase import Client, create_client

SUPABASE_URL = "https://sqxeokcvxwkwomhokfpk.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNxeGVva2N2eHdrd29taG9rZnBrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjM1OTUwNTIsImV4cCI6MjA3OTE3MTA1Mn0.I_TZVz_d3ruo2byvU-IQih6aumLRtdSRbPaCfHo91Qw"

STORAGE_BUCKET = "repos"
MAX_FILE_SIZE = 10 * 1024 * 1024  
ALLOWED_FILENAME_PATTERN = r"^[a-zA-Z0-9_.\/-]+$"


@st.cache_resource(show_spinner=False)
def init_supabase_client() -> Client:
    """Initialize and cache the Supabase client."""
    try:
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as exc: 
        st.error(f"Supabase connection failed: {exc}")
        st.stop()


supabase: Client = init_supabase_client()


def load_css():
    """Apply shared Streamlit styling."""
    st.markdown(
        """
        <style>
        .stApp { background-color: #0e1117; color: #c9d1d9; }
        section[data-testid="stSidebar"] { background-color: #161b22; }
        div[data-testid="stMetric"] {
            background-color: #21262d;
            border: 1px solid #30363d;
            padding: 10px;
            border-radius: 6px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


__all__ = [
    "ALLOWED_FILENAME_PATTERN",
    "MAX_FILE_SIZE",
    "STORAGE_BUCKET",
    "SUPABASE_KEY",
    "SUPABASE_URL",
    "load_css",
    "supabase",
]

