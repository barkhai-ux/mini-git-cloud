import streamlit as st
import os
import json
import hashlib
import datetime
import uuid
import difflib
import zipfile 
import io     
from supabase import create_client, Client
from code_editor import code_editor 

st.set_page_config(page_title="MiniHub Cloud", layout="wide", page_icon="☁️")

SUPABASE_URL = "https://sqxeokcvxwkwomhokfpk.supabase.co" 
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNxeGVva2N2eHdrd29taG9rZnBrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjM1OTUwNTIsImV4cCI6MjA3OTE3MTA1Mn0.I_TZVz_d3ruo2byvU-IQih6aumLRtdSRbPaCfHo91Qw"

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except:
    st.error("Supabase connection failed. Please check your URL and Key.")
    st.stop()

def load_css():
    st.markdown("""
        <style>
        .stApp { background-color: #0e1117; color: #c9d1d9; }
        section[data-testid="stSidebar"] { background-color: #161b22; }
        div[data-testid="stMetric"] { background-color: #21262d; border: 1px solid #30363d; padding: 10px; border-radius: 6px; }
        </style>
    """, unsafe_allow_html=True)


def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def register_user(u, p):
    if supabase.table("users").select("*").eq("username", u).execute().data: return False
    supabase.table("users").insert({"username": u, "password": hash_password(p)}).execute()
    return True

def login_user(u, p):
    return len(supabase.table("users").select("*").eq("username", u).eq("password", hash_password(p)).execute().data) > 0

def init_repo(u, r):
    try: supabase.storage.from_("repos").download(f"{u}/{r}/meta.json"); return False
    except:
        supabase.storage.from_("repos").upload(f"{u}/{r}/meta.json", json.dumps({"created": str(datetime.datetime.now())}).encode("utf-8"))
        supabase.storage.from_("repos").upload(f"{u}/{r}/main/head/README.md", f"# {r}".encode("utf-8"))
        return True

def list_repos(u):
    try: return [x['name'] for x in supabase.storage.from_("repos").list(u) if x['id'] is None]
    except: return []

def list_branches(u, r):
    try: return [x['name'] for x in supabase.storage.from_("repos").list(f"{u}/{r}") if x['id'] is None]
    except: return ["main"]

def read_file(u, r, b, f):
    try: return supabase.storage.from_("repos").download(f"{u}/{r}/{b}/head/{f}").decode("utf-8")
    except: return ""

def write_file(u, r, b, f, c):
    supabase.storage.from_("repos").upload(f"{u}/{r}/{b}/head/{f}", c.encode("utf-8"), {"upsert": "true"})

def delete_file(u, r, b, f):
    supabase.storage.from_("repos").remove([f"{u}/{r}/{b}/head/{f}"])

def commit(u, r, b, msg):
    cid = str(uuid.uuid4())[:8]
    files = supabase.storage.from_("repos").list(f"{u}/{r}/{b}/head")
    for f in files:
        if f['name'] != ".empty":
            supabase.storage.from_("repos").copy(f"{u}/{r}/{b}/head/{f['name']}", f"{u}/{r}/{b}/commits/{cid}/{f['name']}")
    supabase.table("commits").insert({"id": cid, "repo_name": r, "username": u, "branch": b, "message": msg}).execute()
    return cid

def history(u, r, b):
    return supabase.table("commits").select("*").eq("username", u).eq("repo_name", r).eq("branch", b).order("timestamp", desc=True).execute().data

def get_file_at_commit(u, r, b, cid, f):
    try: return supabase.storage.from_("repos").download(f"{u}/{r}/{b}/commits/{cid}/{f}").decode("utf-8")
    except: return ""

def list_commit_files(u, r, b, cid):
    try: return [x['name'] for x in supabase.storage.from_("repos").list(f"{u}/{r}/{b}/commits/{cid}") if x['name'] != ".empty"]
    except: return []

def create_repo_zip(u, r, b):
    """Creates a zip file in memory of the current branch head."""
    buffer = io.BytesIO()
    prefix = f"{u}/{r}/{b}/head"
    
    try:
        files = supabase.storage.from_("repos").list(prefix)
        
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                if f['name'] == ".empty": continue
                file_path = f"{prefix}/{f['name']}"
                try:
                    file_data = supabase.storage.from_("repos").download(file_path)
                    zf.writestr(f['name'], file_data)
                except Exception as e:
                    print(f"Failed to download {f['name']}: {e}")
                    
    except Exception as e:
        return None

    buffer.seek(0)
    return buffer


def init_session():
    for k in ["user", "view", "current_repo", "current_branch", "editor_file"]:
        if k not in st.session_state: st.session_state[k] = None if k != "view" else "login"
    if st.session_state.current_branch is None: st.session_state.current_branch = "main"

def login_page():
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.markdown("## ☁️ MiniHub Cloud")
        tab1, tab2 = st.tabs(["Login", "Sign Up"])
        with tab1:
            u, p = st.text_input("User", key="1"), st.text_input("Pass", type="password", key="2")
            if st.button("Login") and login_user(u, p):
                st.session_state.user = u
                st.session_state.view = "dashboard"
                st.rerun()
        with tab2:
            u2, p2 = st.text_input("User", key="3"), st.text_input("Pass", type="password", key="4")
            if st.button("Register") and register_user(u2, p2): st.success("Registered!")

def dashboard_page():
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update(user=None, view="login"))
    st.title(f"Welcome, {st.session_state.user}")
    with st.expander("Create Repo"):
        name = st.text_input("Name")
        if st.button("Create") and name and init_repo(st.session_state.user, name): st.rerun()
    
    cols = st.columns(3)
    for i, r in enumerate(list_repos(st.session_state.user)):
        with cols[i%3]:
            with st.container(border=True):
                st.markdown(f"**{r}**")
                if st.button("Open", key=r):
                    st.session_state.current_repo = r
                    st.session_state.view = "repo"
                    st.rerun()

def repo_page():
    u, r = st.session_state.user, st.session_state.current_repo
    b = st.session_state.current_branch
    
    # Sidebar
    with st.sidebar:
        if st.button("⬅️ Back"): st.session_state.view = "dashboard"; st.rerun()
        st.divider()
        
        st.markdown("### Actions")
        
        zip_key = f"zip_{u}_{r}_{b}"
        
        if st.button("📦 Prepare Download"):
            with st.spinner("Zipping files from cloud..."):
                zip_buffer = create_repo_zip(u, r, b)
                if zip_buffer:
                    st.session_state[zip_key] = zip_buffer
                    st.success("Ready!")
                else:
                    st.error("Failed to zip.")

        if zip_key in st.session_state:
            st.download_button(
                label="⬇️ Download ZIP",
                data=st.session_state[zip_key],
                file_name=f"{r}-{b}.zip",
                mime="application/zip"
            )
        
        st.divider()

        new_f = st.text_input("New File Name")
        if st.button("Create File") and new_f: write_file(u, r, b, new_f, ""); st.rerun()
        
        st.divider()
        
        # File Tree
        try: files = [x['name'] for x in supabase.storage.from_("repos").list(f"{u}/{r}/{b}/head") if x['name'] != ".empty"]
        except: files = []
        
        st.markdown("### Explorer")
        for f in files:
            c1, c2 = st.columns([4, 1])
            if c1.button(f"📄 {f}", key=f"f_{f}"): st.session_state.editor_file = f
            if c2.button("🗑️", key=f"d_{f}"): 
                delete_file(u, r, b, f)
                if st.session_state.editor_file == f: st.session_state.editor_file = None
                st.rerun()

    st.title(f"{u} / {r}")
    branches = list_branches(u, r)
    sel_b = st.selectbox("Branch", branches, index=branches.index(b) if b in branches else 0)
    if sel_b != b: 
        st.session_state.current_branch = sel_b
        zip_key = f"zip_{u}_{r}_{b}"
        if zip_key in st.session_state: del st.session_state[zip_key]
        st.rerun()

    tab1, tab2 = st.tabs(["Code", "History"])
    
    with tab1:
        if st.session_state.editor_file:
            f_name = st.session_state.editor_file
            content = read_file(u, r, b, f_name)
            
            ext = f_name.split('.')[-1] if '.' in f_name else "text"
            lang_map = {"py": "python", "js": "javascript", "md": "markdown", "html": "html", "css": "css"}
            lang = lang_map.get(ext, "text")

            st.caption(f"Editing: {f_name}")
            editor_response = code_editor(
                content, lang=lang, height="500px", theme="contrast",
                buttons=[{"name": "Save", "feather": "Save", "primary": True, "hasText": True, "commands": ["submit"], "style": {"bottom": "0.44rem", "right": "0.4rem"}}]
            )

            if editor_response['type'] == "submit" and len(editor_response['text']) > 0:
                write_file(u, r, b, f_name, editor_response['text'])
                st.toast(f"Saved {f_name}!")
                zip_key = f"zip_{u}_{r}_{b}"
                if zip_key in st.session_state: del st.session_state[zip_key]

            with st.popover("Commit Changes"):
                msg = st.text_input("Message")
                if st.button("Push Commit"):
                    cid = commit(u, r, b, msg)
                    st.success(f"Committed: {cid}")
        else:
            st.info("👈 Select a file to edit")

    with tab2:
        hist = history(u, r, b)
        for h in hist:
            with st.expander(f"{h['message']} ({h['timestamp']})"):
                if st.button("Diff", key=h['id']):
                    files_here = list_commit_files(u, r, b, h['id'])
                    for f in files_here:
                        curr = get_file_at_commit(u, r, b, h['id'], f).splitlines()
                        st.markdown(f"**{f}**")
                        st.code("\n".join(curr))

def main():
    load_css()
    init_session()
    if st.session_state.view == "login": login_page()
    elif st.session_state.view == "dashboard": dashboard_page()
    elif st.session_state.view == "repo": repo_page()

if __name__ == "__main__":
    main()