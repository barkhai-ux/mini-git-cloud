import streamlit as st
import json
import hashlib
import datetime
import zipfile 
import io
import re
import difflib
import secrets
from supabase import create_client, Client
from code_editor import code_editor 

st.set_page_config(page_title="MiniHub Cloud", layout="wide", page_icon="☁️")

SUPABASE_URL = "https://sqxeokcvxwkwomhokfpk.supabase.co" 
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNxeGVva2N2eHdrd29taG9rZnBrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjM1OTUwNTIsImV4cCI6MjA3OTE3MTA1Mn0.I_TZVz_d3ruo2byvU-IQih6aumLRtdSRbPaCfHo91Qw"

STORAGE_BUCKET = "repos"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_FILENAME_PATTERN = r'^[a-zA-Z0-9_.\-/]+$'

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    st.error(f"Supabase connection failed: {e}")
    st.stop()

def load_css():
    st.markdown("""
        <style>
        .stApp { background-color: #0e1117; color: #c9d1d9; }
        section[data-testid="stSidebar"] { background-color: #161b22; }
        div[data-testid="stMetric"] { background-color: #21262d; border: 1px solid #30363d; padding: 10px; border-radius: 6px; }
        </style>
    """, unsafe_allow_html=True)


def validate_filename(filename: str) -> tuple[bool, str]:
    """Validate filename for security."""
    if not filename:
        return False, "Filename cannot be empty"
    if '..' in filename:
        return False, "Filename cannot contain '..'"
    if not re.match(ALLOWED_FILENAME_PATTERN, filename):
        return False, "Filename contains invalid characters"
    if len(filename) > 255:
        return False, "Filename too long"
    return True, ""

def validate_repo_name(name: str) -> tuple[bool, str]:
    """Validate repository name."""
    if not name:
        return False, "Repository name cannot be empty"
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Repository name can only contain letters, numbers, underscores, and hyphens"
    if len(name) > 100:
        return False, "Repository name too long"
    return True, ""


def sha256_bytes(data: bytes) -> str:
    """Compute SHA256 hash of byte data."""
    return hashlib.sha256(data).hexdigest()

def now_utc_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def object_path_for_hash(hash_str: str) -> str:
    """Get storage path for object using first 2 chars as subdirectory."""
    return f"{hash_str[:2]}/{hash_str[2:]}"

def get_repo_id(username: str, repo_name: str) -> str:
    """Get repository UUID from username and repo name."""
    try:
        result = supabase.table("repositories").select("id").eq("owner_username", username).eq("name", repo_name).execute()
        return result.data[0]["id"] if result.data else None
    except Exception as e:
        st.error(f"Error fetching repository: {e}")
        return None

def store_object(repo_id: str, branch: str, content: bytes) -> str:
    """
    Store content as a content-addressed object.
    Returns the SHA256 hash of the content.
    """
    hash_str = sha256_bytes(content)
    obj_path = object_path_for_hash(hash_str)
    storage_path = f"{repo_id}/{branch}/objects/{obj_path}"
    
    try:
        existing = supabase.table("objects").select("hash").eq("hash", hash_str).eq("repository_id", repo_id).execute()
        if existing.data:
            return hash_str
    except Exception as e:
        st.warning(f"Error checking object existence: {e}")
    
    compressed = io.BytesIO()
    try:
        with zipfile.ZipFile(compressed, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("content", content)
        compressed.seek(0)
        compressed_data = compressed.read()
    except Exception as e:
        raise Exception(f"Failed to compress content: {e}")
    
    try:
        supabase.storage.from_(STORAGE_BUCKET).upload(
            storage_path,
            compressed_data,
            {"upsert": "true", "content-type": "application/zip"}
        )
    except Exception as e:
        # Silently ignore if already exists
        if "already exists" not in str(e).lower():
            st.warning(f"Storage upload issue: {e}")
    
    try:
        supabase.table("objects").insert({
            "hash": hash_str,
            "repository_id": repo_id,
            "branch_name": branch,
            "object_type": "blob",
            "size_bytes": len(content),
            "storage_path": storage_path
        }).execute()
    except Exception as e:
        # Silently ignore duplicate key errors
        if "duplicate" not in str(e).lower():
            st.warning(f"Object metadata insert issue: {e}")
    
    return hash_str

def retrieve_object(repo_id: str, branch: str, hash_str: str) -> bytes:
    """Retrieve content from object store by hash."""
    try:
        result = supabase.table("objects").select("storage_path").eq("hash", hash_str).eq("repository_id", repo_id).execute()
        
        if not result.data:
            raise Exception(f"Object {hash_str} not found in database")
        
        storage_path = result.data[0]["storage_path"]
        
        compressed_data = supabase.storage.from_(STORAGE_BUCKET).download(storage_path)
        with zipfile.ZipFile(io.BytesIO(compressed_data), 'r') as zf:
            return zf.read("content")
    except Exception as e:
        raise Exception(f"Failed to retrieve object {hash_str}: {e}")

def load_staging_index(repo_id: str, branch: str) -> dict:
    """Load staging index from database."""
    try:
        result = supabase.table("staging_index").select("*").eq("repository_id", repo_id).eq("branch_name", branch).execute()
        
        index = {}
        for item in result.data:
            index[item["filename"]] = {
                "status": item["status"],
                "added_at": item["staged_at"],
                "hash": item["object_hash"]
            }
        return index
    except Exception as e:
        st.error(f"Error loading staging index: {e}")
        return {}

def save_staging_entry(repo_id: str, branch: str, filename: str, status: str, obj_hash: str = None):
    """Save or update a staging entry."""
    try:
        supabase.table("staging_index").upsert({
            "repository_id": repo_id,
            "branch_name": branch,
            "filename": filename,
            "status": status,
            "object_hash": obj_hash
        }, on_conflict="repository_id,branch_name,filename").execute()
    except Exception as e:
        st.error(f"Error saving staging entry: {e}")

def clear_staging_entry(repo_id: str, branch: str, filename: str):
    """Remove a file from staging."""
    try:
        supabase.table("staging_index").delete().eq("repository_id", repo_id).eq("branch_name", branch).eq("filename", filename).execute()
    except Exception as e:
        st.error(f"Error clearing staging entry: {e}")

def read_head(repo_id: str, branch: str) -> str:
    """Read current HEAD commit ID from branches table."""
    try:
        result = supabase.table("branches").select("head_commit_id").eq("repository_id", repo_id).eq("name", branch).execute()
        
        if result.data and result.data[0]["head_commit_id"]:
            return result.data[0]["head_commit_id"]
        return None
    except Exception as e:
        st.error(f"Error reading HEAD: {e}")
        return None

def stage_file(repo_id: str, branch: str, filename: str, content: str) -> dict:
    """Stage a file for commit."""
    try:
        stage_path = f"{repo_id}/{branch}/stage/{filename}"
        supabase.storage.from_(STORAGE_BUCKET).upload(
            stage_path,
            content.encode("utf-8"),
            {"upsert": "true"}
        )
        
        save_staging_entry(repo_id, branch, filename, "staged", None)
        
        return {"status": "staged", "added_at": now_utc_iso(), "hash": None}
    except Exception as e:
        st.error(f"Error staging file: {e}")
        return None

def get_staged_files(repo_id: str, branch: str) -> dict:
    """Get all files currently staged."""
    index = load_staging_index(repo_id, branch)
    return {k: v for k, v in index.items() if v.get("status") == "staged"}

def create_commit(repo_id: str, branch: str, message: str, author: str = None) -> str:
    """
    Create a commit from staged files.
    Returns commit ID (SHA256 hash).
    """
    staged = get_staged_files(repo_id, branch)
    
    if not staged:
        return None
    
    files_map = {}
    for filename in staged.keys():
        stage_path = f"{repo_id}/{branch}/stage/{filename}"
        try:
            content = supabase.storage.from_(STORAGE_BUCKET).download(stage_path)
            hash_str = store_object(repo_id, branch, content)
            files_map[filename] = hash_str
        except Exception as e:
            st.error(f"Failed to store {filename}: {e}")
            continue
    
    if not files_map:
        st.error("No files were successfully stored")
        return None
    
    parent_commit = read_head(repo_id, branch)
    
    commit_obj = {
        "parent": parent_commit,
        "timestamp": now_utc_iso(),
        "author": author or "User <user@example.com>",
        "message": message,
        "files": files_map
    }
    
    canonical = json.dumps(commit_obj, separators=(',', ':'), sort_keys=True)
    commit_id = sha256_bytes(canonical.encode("utf-8"))
    
    try:
        supabase.table("commits").insert({
            "commit_id": commit_id,
            "repository_id": repo_id,
            "branch_name": branch,
            "parent_commit_id": parent_commit,
            "author": commit_obj["author"],
            "message": message,
            "timestamp": commit_obj["timestamp"],
            "files": files_map
        }).execute()
    except Exception as e:
        st.error(f"Failed to store commit: {e}")
        return None
    
    for filename in staged.keys():
        try:
            supabase.storage.from_(STORAGE_BUCKET).remove([f"{repo_id}/{branch}/stage/{filename}"])
        except Exception as e:
            st.warning(f"Failed to clear staged file {filename}: {e}")
        clear_staging_entry(repo_id, branch, filename)
    
    return commit_id

def checkout_commit(repo_id: str, branch: str, commit_id: str) -> bool:
    """
    Checkout a commit - completely replaces working directory with commit state.
    Similar to: minigit checkout <commit_id>
    """
    try:
        result = supabase.table("commits").select("*").eq("commit_id", commit_id).eq("repository_id", repo_id).execute()
        
        if not result.data:
            st.error(f"❌ Commit not found: {commit_id[:8]}")
            return False
        
        commit_obj = result.data[0]
        files_map = commit_obj.get("files", {})
        
        st.info("🗑️ Clearing working directory...")
        try:
            file_list = supabase.storage.from_(STORAGE_BUCKET).list(f"{repo_id}/{branch}/head")
            files_to_remove = [f"{repo_id}/{branch}/head/{f['name']}" for f in file_list if f['name'] != ".empty"]
            
            if files_to_remove:
                supabase.storage.from_(STORAGE_BUCKET).remove(files_to_remove)
                st.toast(f"🗑️ Cleared {len(files_to_remove)} file(s)")
        except Exception as e:
            st.warning(f"Error clearing directory: {e}")
        
        if not files_map:
            st.warning("⚠️ This commit has no files")
            supabase.table("branches").update({
                "head_commit_id": commit_id
            }).eq("repository_id", repo_id).eq("name", branch).execute()
            return True
        
        st.info(f"📦 Restoring {len(files_map)} file(s) from commit...")
        restored_count = 0
        failed_files = []
        
        for filename, hash_str in files_map.items():
            try:
                obj_path_suffix = object_path_for_hash(hash_str)
                storage_path = f"{repo_id}/{branch}/objects/{obj_path_suffix}"
                
                compressed_data = supabase.storage.from_(STORAGE_BUCKET).download(storage_path)
                
                with zipfile.ZipFile(io.BytesIO(compressed_data), 'r') as zf:
                    if "content" in zf.namelist():
                        content = zf.read("content")
                    else:
                        content = zf.read(zf.namelist()[0])
                
                supabase.storage.from_(STORAGE_BUCKET).upload(
                    f"{repo_id}/{branch}/head/{filename}",
                    content,
                    {"upsert": "true", "content-type": "application/octet-stream"}
                )
                
                restored_count += 1
                st.toast(f"✅ Restored: {filename}")
                
            except Exception as e:
                st.error(f"❌ Failed to restore {filename}: {e}")
                failed_files.append(filename)
        
        if restored_count == 0:
            st.error("❌ Failed to restore any files from commit")
            return False
        
        try:
            supabase.table("branches").update({
                "head_commit_id": commit_id
            }).eq("repository_id", repo_id).eq("name", branch).execute()
            
            st.success(f"✅ Checked out commit {commit_id[:8]} ({restored_count}/{len(files_map)} files)")
            
            if failed_files:
                st.warning(f"⚠️ Failed files: {', '.join(failed_files)}")
            
        except Exception as e:
            st.error(f"❌ Failed to update HEAD: {e}")
            return False
        
        return True
        
    except Exception as e:
        st.error(f"❌ Checkout failed: {e}")
        return False

def get_commit_log(repo_id: str, branch: str, limit: int = 50) -> list:
    """Get commit history using database function."""
    try:
        result = supabase.rpc("get_commit_history", {
            "p_repository_id": repo_id,
            "p_branch_name": branch,
            "p_limit": limit
        }).execute()
        
        return result.data if result.data else []
    except Exception as e:
        st.error(f"Error fetching commit log: {e}")
        return []

def get_file_from_commit(repo_id: str, branch: str, commit_id: str, filename: str) -> str:
    """Get file content from a specific commit."""
    try:
        result = supabase.table("commits").select("files").eq("commit_id", commit_id).execute()
        if not result.data:
            return None
        
        files = result.data[0]["files"]
        if filename not in files:
            return None
        
        hash_str = files[filename]
        content = retrieve_object(repo_id, branch, hash_str)
        return content.decode("utf-8")
    except Exception as e:
        st.error(f"Error retrieving file from commit: {e}")
        return None

def get_commit_details(repo_id: str, commit_id: str) -> dict:
    """Get detailed information about a commit including parent comparison."""
    try:
        result = supabase.table("commits").select("*").eq("commit_id", commit_id).execute()
        if not result.data:
            return None
        
        commit = result.data[0]
        details = {
            "commit": commit,
            "files_added": [],
            "files_modified": [],
            "files_deleted": []
        }
        
        # If there's a parent commit, compare with it
        if commit.get("parent_commit_id"):
            parent_result = supabase.table("commits").select("files").eq("commit_id", commit["parent_commit_id"]).execute()
            if parent_result.data:
                parent_files = parent_result.data[0]["files"]
                current_files = commit["files"]
                
                # Find added and modified files
                for filename, hash_str in current_files.items():
                    if filename not in parent_files:
                        details["files_added"].append(filename)
                    elif parent_files[filename] != hash_str:
                        details["files_modified"].append(filename)
                
                # Find deleted files
                for filename in parent_files.keys():
                    if filename not in current_files:
                        details["files_deleted"].append(filename)
        else:
            # First commit - all files are added
            details["files_added"] = list(commit["files"].keys())
        
        return details
    except Exception as e:
        st.error(f"Error getting commit details: {e}")
        return None

def generate_diff(old_content: str, new_content: str, filename: str) -> str:
    """Generate a unified diff between two file versions."""
    old_lines = old_content.splitlines(keepends=True) if old_content else []
    new_lines = new_content.splitlines(keepends=True) if new_content else []
    
    diff = difflib.unified_diff(
        old_lines, 
        new_lines, 
        fromfile=f"a/{filename}", 
        tofile=f"b/{filename}",
        lineterm=''
    )
    
    return ''.join(diff)
    """Find all commits matching a message."""
    try:
        result = supabase.rpc("find_commits_by_message", {
            "p_repository_id": repo_id,
            "p_search_text": message
        }).execute()
        
        return result.data if result.data else []
    except Exception as e:
        st.error(f"Error searching commits: {e}")
        return []

# ============ User Management ============

def hash_password(password: str) -> str:
    """Hash password using SHA256 (basic implementation)."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(32)

def create_session(username: str) -> str:
    """Create a new session for user and return token."""
    try:
        token = generate_session_token()
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat()
        
        supabase.table("user_sessions").insert({
            "username": username,
            "token": token,
            "expires_at": expires_at
        }).execute()
        
        return token
    except Exception as e:
        st.error(f"Failed to create session: {e}")
        return None

def validate_session(token: str) -> str:
    """Validate session token and return username if valid."""
    try:
        result = supabase.table("user_sessions").select("username, expires_at").eq("token", token).execute()
        
        if not result.data:
            return None
        
        session = result.data[0]
        expires_at = datetime.datetime.fromisoformat(session["expires_at"])
        
        # Check if session expired
        if datetime.datetime.utcnow() > expires_at:
            # Delete expired session
            supabase.table("user_sessions").delete().eq("token", token).execute()
            return None
        
        return session["username"]
    except Exception as e:
        st.error(f"Session validation error: {e}")
        return None

def logout_session(token: str):
    """Delete session token on logout."""
    try:
        supabase.table("user_sessions").delete().eq("token", token).execute()
    except Exception as e:
        st.warning(f"Failed to delete session: {e}")

def register_user(username: str, password: str) -> tuple[bool, str]:
    """Register a new user. Returns (success, message)."""
    if not username or not password:
        return False, "Username and password required"
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    try:
        existing = supabase.table("users").select("*").eq("username", username).execute()
        if existing.data:
            return False, "Username already exists"
        
        supabase.table("users").insert({
            "username": username,
            "password": hash_password(password)
        }).execute()
        return True, "Registration successful"
    except Exception as e:
        return False, f"Registration failed: {e}"

def login_user(username: str, password: str) -> tuple[bool, str]:
    """Authenticate user and return (success, token)."""
    try:
        result = supabase.table("users").select("*").eq("username", username).eq("password", hash_password(password)).execute()
        
        if len(result.data) > 0:
            token = create_session(username)
            return True, token
        return False, None
    except Exception as e:
        st.error(f"Login error: {e}")
        return False, None

# ============ Repository Management ============

def init_repo(username: str, repo_name: str, description: str = "") -> tuple[bool, str]:
    """Initialize a new repository. Returns (success, message)."""
    valid, error = validate_repo_name(repo_name)
    if not valid:
        return False, error
    
    try:
        # Check if repo exists
        existing = supabase.table("repositories").select("id").eq("owner_username", username).eq("name", repo_name).execute()
        if existing.data:
            return False, "Repository already exists"
        
        # Create repository
        repo_result = supabase.table("repositories").insert({
            "name": repo_name,
            "owner_username": username,
            "description": description,
            "is_public": True,
            "default_branch": "main"
        }).execute()
        
        repo_id = repo_result.data[0]["id"]
        
        # Create main branch
        supabase.table("branches").insert({
            "repository_id": repo_id,
            "name": "main",
            "head_commit_id": None
        }).execute()
        
        # Create initial README
        readme_content = f"# {repo_name}\n\n{description or 'Initialized with MiniHub Cloud'}"
        supabase.storage.from_(STORAGE_BUCKET).upload(
            f"{repo_id}/main/head/README.md",
            readme_content.encode("utf-8")
        )
        
        return True, "Repository created successfully"
    except Exception as e:
        return False, f"Failed to create repository: {e}"

def list_repos(username: str) -> list:
    """List all repositories owned by user."""
    try:
        result = supabase.table("repositories").select("*").eq("owner_username", username).order("created_at", desc=True).execute()
        return result.data if result.data else []
    except Exception as e:
        st.error(f"Error listing repositories: {e}")
        return []

def list_branches(repo_id: str) -> list:
    """List all branches in a repository."""
    try:
        result = supabase.table("branches").select("name").eq("repository_id", repo_id).execute()
        return [b["name"] for b in result.data] if result.data else ["main"]
    except Exception as e:
        st.error(f"Error listing branches: {e}")
        return ["main"]

def read_file(repo_id: str, branch: str, filename: str) -> str:
    """Read a file from working directory."""
    try:
        data = supabase.storage.from_(STORAGE_BUCKET).download(f"{repo_id}/{branch}/head/{filename}")
        return data.decode("utf-8")
    except Exception as e:
        st.warning(f"Could not read file {filename}: {e}")
        return ""

def write_file(repo_id: str, branch: str, filename: str, content: str | bytes) -> bool:
    """Write a file to working directory. Accepts string or bytes."""
    valid, error = validate_filename(filename)
    if not valid:
        st.error(error)
        return False
    
    # Convert to bytes if string
    if isinstance(content, str):
        content_bytes = content.encode('utf-8')
    else:
        content_bytes = content
    
    if len(content_bytes) > MAX_FILE_SIZE:
        st.error(f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)")
        return False
    
    try:
        supabase.storage.from_(STORAGE_BUCKET).upload(
            f"{repo_id}/{branch}/head/{filename}",
            content_bytes,
            {"upsert": "true"}
        )
        return True
    except Exception as e:
        st.error(f"Failed to write file: {e}")
        return False

def delete_file(repo_id: str, branch: str, filename: str) -> bool:
    """Delete a file from working directory."""
    try:
        supabase.storage.from_(STORAGE_BUCKET).remove([f"{repo_id}/{branch}/head/{filename}"])
        return True
    except Exception as e:
        st.error(f"Failed to delete file: {e}")
        return False

def list_files(repo_id: str, branch: str) -> list:
    """List all files in working directory."""
    try:
        files = supabase.storage.from_(STORAGE_BUCKET).list(f"{repo_id}/{branch}/head")
        return [f['name'] for f in files if f['name'] != ".empty"]
    except Exception as e:
        st.warning(f"Error listing files: {e}")
        return []

def create_repo_zip(repo_id: str, branch: str) -> io.BytesIO:
    """Creates a zip file in memory of the current branch head."""
    buffer = io.BytesIO()
    prefix = f"{repo_id}/{branch}/head"
    
    try:
        files = supabase.storage.from_(STORAGE_BUCKET).list(prefix)
        
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                if f['name'] == ".empty":
                    continue
                file_path = f"{prefix}/{f['name']}"
                try:
                    file_data = supabase.storage.from_(STORAGE_BUCKET).download(file_path)
                    zf.writestr(f['name'], file_data)
                except Exception as e:
                    st.warning(f"Failed to add {f['name']} to archive: {e}")
        
        buffer.seek(0)
        return buffer
    except Exception as e:
        st.error(f"Failed to create archive: {e}")
        return None

# ============ UI Functions ============

def init_session():
    """Initialize session state with defaults and check for existing session."""
    defaults = {
        "user": None,
        "view": "login",
        "current_repo": None,
        "current_repo_id": None,
        "current_branch": "main",
        "editor_file": None,
        "session_token": None
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v
    
    # Check if there's a stored session token in browser cookies/query params
    if st.session_state.user is None and st.session_state.session_token:
        username = validate_session(st.session_state.session_token)
        if username:
            st.session_state.user = username
            st.session_state.view = "dashboard"
        else:
            # Invalid/expired token, clear it
            st.session_state.session_token = None
    
    # Try to restore session from URL query params (for persistent login)
    query_params = st.query_params
    if "token" in query_params and st.session_state.user is None:
        token = query_params["token"]
        username = validate_session(token)
        if username:
            st.session_state.user = username
            st.session_state.session_token = token
            st.session_state.view = "dashboard"
            # Keep token in URL for page refreshes
            st.query_params["token"] = token

def login_page():
    """Render login/registration page."""
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.markdown("##  MiniHub Cloud")
        st.caption("Git-powered cloud repository manager")
        
        tab1, tab2 = st.tabs(["Login", "Sign Up"])
        
        with tab1:
            u = st.text_input("Username", key="login_user")
            p = st.text_input("Password", type="password", key="login_pass")
            remember = st.checkbox("Keep me logged in", value=True)
            
            if st.button("Login", use_container_width=True):
                if u and p:
                    success, token = login_user(u, p)
                    if success:
                        st.session_state.user = u
                        st.session_state.session_token = token
                        st.session_state.view = "dashboard"
                        
                        # Add token to URL for persistent login
                        if remember and token:
                            st.query_params["token"] = token
                        
                        st.rerun()
                    else:
                        st.error(" Invalid credentials")
                else:
                    st.error(" Please enter username and password")
        
        with tab2:
            u2 = st.text_input("Username", key="register_user")
            p2 = st.text_input("Password", type="password", key="register_pass")
            if st.button("Register", use_container_width=True):
                success, message = register_user(u2, p2)
                if success:
                    st.success(f" {message} Please login.")
                else:
                    st.error(f" {message}")

def dashboard_page():
    """Render user dashboard."""
    def handle_logout():
        if st.session_state.session_token:
            logout_session(st.session_state.session_token)
        st.session_state.user = None
        st.session_state.session_token = None
        st.session_state.view = "login"
        # Clear token from URL
        if "token" in st.query_params:
            del st.query_params["token"]
    
    st.sidebar.button("🚪 Logout", on_click=handle_logout)
    
    st.title(f"👋 Welcome, {st.session_state.user}")
    
    with st.expander("➕ Create New Repository", expanded=False):
        col1, col2 = st.columns([2, 1])
        with col1:
            name = st.text_input("Repository Name")
        with col2:
            st.write("")  # Spacing
        desc = st.text_area("Description (optional)", height=100)
        
        if st.button("Create Repository", use_container_width=True):
            if name:
                success, message = init_repo(st.session_state.user, name, desc)
                if success:
                    st.success(f" {message}")
                    st.rerun()
                else:
                    st.error(f" {message}")
            else:
                st.error(" Repository name is required")
    
    st.markdown("---")
    st.markdown("###  Your Repositories")
    
    repos = list_repos(st.session_state.user)
    
    if not repos:
        st.info("No repositories yet. Create your first one above!")
    else:
        cols = st.columns(3)
        for i, repo in enumerate(repos):
            with cols[i % 3]:
                with st.container(border=True):
                    st.markdown(f"** {repo['name']}**")
                    if repo.get('description'):
                        st.caption(repo['description'])
                    st.caption(f"Created: {repo['created_at'][:10]}")
                    if st.button("Open →", key=repo['id'], use_container_width=True):
                        st.session_state.current_repo = repo['name']
                        st.session_state.current_repo_id = repo['id']
                        st.session_state.view = "repo"
                        st.session_state.editor_file = None
                        st.rerun()

def render_editor_tab(repo_id: str, branch: str, f_name: str):
    """Render the editor tab content."""
    content = read_file(repo_id, branch, f_name)
    
    ext = f_name.split('.')[-1] if '.' in f_name else "text"
    lang_map = {
        "py": "python", "js": "javascript", "ts": "typescript",
        "md": "markdown", "html": "html", "css": "css",
        "json": "json", "xml": "xml", "yaml": "yaml",
        "c": "c", "cpp": "cpp", "java": "java", "cs": "csharp",
        "go": "go", "rs": "rust", "php": "php", "rb": "ruby"
    }
    lang = lang_map.get(ext, "text")

    st.caption(f" Editing: **{f_name}**")
    
    editor_response = code_editor(
        content, lang=lang, height="500px", theme="contrast",
        buttons=[{
            "name": "Save",
            "feather": "Save",
            "primary": True,
            "hasText": True,
            "commands": ["submit"],
            "style": {"bottom": "0.44rem", "right": "0.4rem"}
        }]
    )

    if editor_response['type'] == "submit" and len(editor_response['text']) > 0:
        if write_file(repo_id, branch, f_name, editor_response['text']):
            st.toast(f" Saved {f_name}!")
            zip_key = f"zip_{repo_id}_{branch}"
            if zip_key in st.session_state:
                del st.session_state[zip_key]

    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("➕ Stage File", use_container_width=True):
            result = stage_file(repo_id, branch, f_name, editor_response.get('text', content))
            if result:
                st.success(f" Staged {f_name}")
                st.rerun()
    
    with col2:
        with st.popover(" Commit", use_container_width=True):
            msg = st.text_input("Commit Message")
            author = st.text_input("Author", value=f"{st.session_state.user} <{st.session_state.user}@minihub.cloud>")
            if st.button("Create Commit", use_container_width=True):
                if not msg:
                    st.error(" Message required!")
                else:
                    commit_id = create_commit(repo_id, branch, msg, author)
                    if commit_id:
                        st.success(f" Commit created: {commit_id[:8]}")
                        st.rerun()
                    else:
                        st.error(" Nothing staged or commit failed!")

def render_history_tab(repo_id: str, branch: str):
    """Render the history tab content."""
    st.markdown("### 📜 Commit History")
    
    # Get current HEAD to highlight it
    current_head = read_head(repo_id, branch)
    
    log = get_commit_log(repo_id, branch)
    
    if not log:
        st.info("No commits yet. Make your first commit! ")
    else:
        for commit in log:
            # Handle both 'timestamp' and 'commit_timestamp' keys
            timestamp = commit.get('commit_timestamp') or commit.get('timestamp', 'Unknown')
            timestamp_short = timestamp[:10] if timestamp != 'Unknown' else 'Unknown'
            
            # Check if this is the current HEAD
            is_head = (commit['commit_id'] == current_head)
            head_indicator = "  **HEAD**" if is_head else ""
            
            with st.expander(
                f"**{commit.get('message', 'No message')}** · {commit['commit_id'][:8]} · {timestamp_short}{head_indicator}",
                expanded=is_head
            ):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**Author:** {commit.get('author', 'Unknown')}")
                    st.markdown(f"**Commit ID:** `{commit['commit_id']}`")
                    parent = commit.get('parent_commit_id', 'None') or 'None'
                    st.markdown(f"**Parent:** `{parent}`")
                    st.markdown(f"**Timestamp:** {timestamp}")
                    if is_head:
                        st.success(" Currently checked out")
                
                with col2:
                    if not is_head:
                        if st.button(" Checkout", key=f"checkout_{commit['commit_id']}", use_container_width=True):
                            with st.spinner("Checking out commit..."):
                                if checkout_commit(repo_id, branch, commit['commit_id']):
                                    st.success(" Checked out successfully")
                                    st.rerun()
                                else:
                                    st.error(" Checkout failed")
                    else:
                        st.info("Current")
                    
                    if st.button(" View Details", key=f"details_{commit['commit_id']}", use_container_width=True):
                        st.session_state.viewing_commit = commit['commit_id']
                        st.rerun()
                
                # Quick file summary
                st.markdown("**Files in this commit:**")
                files = commit.get('files', {})
                if files:
                    for filename, hash_str in files.items():
                        st.code(f" {filename} ({hash_str[:8]})", language="")
                else:
                    st.info("No files")

def render_commit_details_modal():
    """Render a modal showing detailed commit information with diffs."""
    if "viewing_commit" not in st.session_state or not st.session_state.viewing_commit:
        return
    
    commit_id = st.session_state.viewing_commit
    repo_id = st.session_state.current_repo_id
    branch = st.session_state.current_branch
    
    details = get_commit_details(repo_id, commit_id)
    
    if not details:
        st.error("Failed to load commit details")
        if st.button("← Back to History"):
            del st.session_state.viewing_commit
            st.rerun()
        return
    
    commit = details["commit"]
    
    # Header
    col1, col2 = st.columns([5, 1])
    with col1:
        st.title(f" Commit Details")
        st.caption(f"Commit {commit['commit_id'][:12]}")
    with col2:
        if st.button("← Back", use_container_width=True):
            del st.session_state.viewing_commit
            st.rerun()
    
    st.divider()
    
    # Commit metadata
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Author", commit.get('author', 'Unknown').split('<')[0].strip())
    with col2:
        # Handle both 'timestamp' and 'commit_timestamp' keys
        timestamp = commit.get('commit_timestamp') or commit.get('timestamp', 'Unknown')
        if timestamp != 'Unknown':
            st.metric("Date", timestamp[:10])
        else:
            st.metric("Date", "Unknown")
    with col3:
        parent = commit.get('parent_commit_id')
        st.metric("Parent", parent[:8] if parent else "None")
    
    st.markdown(f"### Message")
    st.info(commit.get('message', 'No message'))
    
    st.divider()
    
    # File changes summary
    st.markdown("### Changes Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(" Added", len(details['files_added']))
    with col2:
        st.metric(" Modified", len(details['files_modified']))
    with col3:
        st.metric(" Deleted", len(details['files_deleted']))
    
    st.divider()
    
    # Show diffs for each changed file
    st.markdown("### 🔍 File Changes")
    
    # Added files
    if details['files_added']:
        st.markdown("#### Added Files")
        for filename in details['files_added']:
            with st.expander(f" {filename}", expanded=False):
                new_content = get_file_from_commit(repo_id, branch, commit_id, filename)
                if new_content:
                    diff = generate_diff("", new_content, filename)
                    if diff:
                        st.code(diff, language="diff")
                    else:
                        st.code(new_content, language="text")
                else:
                    st.warning("Could not load file content")
    
    # Modified files
    if details['files_modified']:
        st.markdown("#### Modified Files")
        for filename in details['files_modified']:
            with st.expander(f" {filename}", expanded=False):
                parent_id = commit.get('parent_commit_id')
                if parent_id:
                    old_content = get_file_from_commit(repo_id, branch, parent_id, filename)
                    new_content = get_file_from_commit(repo_id, branch, commit_id, filename)
                    
                    if old_content and new_content:
                        diff = generate_diff(old_content, new_content, filename)
                        if diff:
                            st.code(diff, language="diff")
                        else:
                            st.info("No differences found")
                    else:
                        st.warning("Could not load file content")
                else:
                    st.warning("No parent commit to compare with")
    
    # Deleted files
    if details['files_deleted']:
        st.markdown("#### Deleted Files")
        for filename in details['files_deleted']:
            with st.expander(f" {filename}", expanded=False):
                parent_id = commit.get('parent_commit_id')
                if parent_id:
                    old_content = get_file_from_commit(repo_id, branch, parent_id, filename)
                    if old_content:
                        diff = generate_diff(old_content, "", filename)
                        if diff:
                            st.code(diff, language="diff")
                        else:
                            st.code(old_content, language="text")
                    else:
                        st.warning("Could not load file content")
    
    # All files in commit
    st.divider()
    st.markdown("### All Files in Commit")
    files = commit.get('files', {})
    if files:
        for filename, hash_str in files.items():
            col1, col2 = st.columns([4, 1])
            with col1:
                st.text(f" {filename}")
            with col2:
                st.caption(f"{hash_str[:12]}")
    else:
        st.info("No files in this commit")


def render_advanced_tab(repo_id: str, branch: str):
    """Render the advanced operations tab."""
    st.markdown("### 🔍 Advanced Operations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        with st.container(border=True):
            st.markdown("**Find Commits**")
            search_msg = st.text_input("Search by message")
            if st.button("Search", use_container_width=True):
                if search_msg:
                    results = find_commits_by_message(repo_id, search_msg)
                    if results:
                        st.success(f" Found {len(results)} commit(s):")
                        for r in results:
                            st.code(f"{r['commit_id'][:8]} · {r['branch_name']} · {r['message']}", language="")
                    else:
                        st.info("No matches found")
                else:
                    st.warning("Please enter a search term")
    
    with col2:
        with st.container(border=True):
            st.markdown("**Repository Stats**")
            log = get_commit_log(repo_id, branch)
            files = list_files(repo_id, branch)
            head = read_head(repo_id, branch)
            
            st.metric("Commits", len(log))
            st.metric("Files", len(files))
            st.metric("HEAD", head[:8] if head else "None")

def repo_page():
    """Render repository page."""
    u = st.session_state.user
    repo_name = st.session_state.current_repo
    repo_id = st.session_state.current_repo_id
    branch = st.session_state.current_branch
    
    # Check if we're viewing commit details
    if "viewing_commit" in st.session_state and st.session_state.viewing_commit:
        render_commit_details_modal()
        return
    
    # Sidebar
    with st.sidebar:
        if st.button(" Dashboard"):
            st.session_state.view = "dashboard"
            st.rerun()
        
        st.divider()
        st.markdown("### 🔧 Actions")
        
        # Download
        zip_key = f"zip_{repo_id}_{branch}"
        if st.button(" Prepare Download", use_container_width=True):
            with st.spinner("Creating archive..."):
                zip_buffer = create_repo_zip(repo_id, branch)
                if zip_buffer:
                    st.session_state[zip_key] = zip_buffer
                    st.success(" Archive ready!")
                else:
                    st.error(" Failed to create archive")

        if zip_key in st.session_state:
            st.download_button(
                label="⬇️ Download ZIP",
                data=st.session_state[zip_key],
                file_name=f"{repo_name}-{branch}.zip",
                mime="application/zip",
                use_container_width=True
            )
        
        st.divider()
        
        # Upload Files
        with st.expander(" Upload Files", expanded=False):
            uploaded_files = st.file_uploader(
                "Drag and drop files here",
                accept_multiple_files=True,
                key="file_uploader",
                help="Upload multiple files to your repository"
            )
            
            if uploaded_files:
                st.info(f" {len(uploaded_files)} file(s) ready to upload")
                
                if st.button("Upload All", use_container_width=True, type="primary"):
                    success_count = 0
                    failed_files = []
                    
                    for uploaded_file in uploaded_files:
                        filename = uploaded_file.name
                        
                        # Validate filename
                        valid, error = validate_filename(filename)
                        if not valid:
                            st.error(f" {filename}: {error}")
                            failed_files.append(filename)
                            continue
                        
                        # Check file size
                        file_size = uploaded_file.size
                        if file_size > MAX_FILE_SIZE:
                            st.error(f" {filename}: File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)")
                            failed_files.append(filename)
                            continue
                        
                        # Read file content
                        try:
                            content = uploaded_file.read()
                            
                            # Upload to working directory
                            if write_file(repo_id, branch, filename, content.decode('utf-8', errors='ignore')):
                                success_count += 1
                                st.toast(f" Uploaded {filename}")
                            else:
                                failed_files.append(filename)
                        except Exception as e:
                            st.error(f" {filename}: {e}")
                            failed_files.append(filename)
                    
                    if success_count > 0:
                        st.success(f" Uploaded {success_count} file(s)")
                        # Clear zip cache
                        if zip_key in st.session_state:
                            del st.session_state[zip_key]
                        st.rerun()
                    
                    if failed_files:
                        st.error(f" Failed: {', '.join(failed_files)}")
        
        st.divider()
        
        # Create File
        with st.expander(" New File"):
            new_f = st.text_input("Filename")
            if st.button("Create", use_container_width=True):
                if new_f:
                    valid, error = validate_filename(new_f)
                    if valid:
                        if write_file(repo_id, branch, new_f, "# New File\n"):
                            st.success(f" Created {new_f}")
                            st.rerun()
                    else:
                        st.error(f"❌ {error}")
                else:
                    st.error("❌ Filename required")
        
        st.divider()
        
        # File Explorer
        st.markdown("### Files")
        files = list_files(repo_id, branch)
        
        if not files:
            st.info("No files")
        else:
            for f in files:
                col1, col2 = st.columns([4, 1])
                if col1.button(f" {f}", key=f"f_{f}", use_container_width=True):
                    st.session_state.editor_file = f
                    st.rerun()
                if col2.button("🗑️", key=f"d_{f}"):
                    if delete_file(repo_id, branch, f):
                        if st.session_state.editor_file == f:
                            st.session_state.editor_file = None
                        st.success(f"Deleted {f}")
                        st.rerun()
        
        st.divider()
        
        # Staging Status
        staged = get_staged_files(repo_id, branch)
        if staged:
            st.markdown("### Staged")
            for filename in staged.keys():
                st.text(f"✓ {filename}")

    # Main Content
    st.title(f"{u} / {repo_name}")
    
    branches = list_branches(repo_id)
    sel_branch = st.selectbox("Branch", branches, index=branches.index(branch) if branch in branches else 0)
    
    if sel_branch != branch:
        st.session_state.current_branch = sel_branch
        st.session_state.editor_file = None
        if zip_key in st.session_state:
            del st.session_state[zip_key]
        st.rerun()

    tab1, tab2, tab3 = st.tabs([" Editor", "History", "Advanced"])
    
    with tab1:
        if st.session_state.editor_file:
            render_editor_tab(repo_id, branch, st.session_state.editor_file)
        else:
            st.info("Select a file from the sidebar to edit")

    with tab2:
        render_history_tab(repo_id, branch)
    
    with tab3:
        render_advanced_tab(repo_id, branch)

def main():
    """Main application entry point."""
    load_css()
    init_session()
    
    if st.session_state.view == "login":
        login_page()
    elif st.session_state.view == "dashboard":
        dashboard_page()
    elif st.session_state.view == "repo":
        repo_page()

if __name__ == "__main__":
    main()
