import streamlit as st
from code_editor import code_editor

from minihub.cli import MiniHubTerminal, TerminalContext
from minihub.config import MAX_FILE_SIZE
from minihub.git_ops import (
    checkout_commit,
    create_commit,
    find_commits_by_message,
    generate_diff,
    get_commit_details,
    get_commit_log,
    get_file_from_commit,
    get_staged_files,
    read_head,
    stage_file,
)
from minihub.repo_service import (
    create_repo_zip,
    delete_file,
    init_repo,
    list_branches,
    list_files,
    list_repos,
    read_file,
    write_file,
)
from minihub.user_service import login_user, logout_session, register_user, validate_session
from minihub.validation import validate_filename


def init_session():
    """Initialize session state with defaults and check for existing session."""
    defaults = {
        "user": None,
        "view": "login",
        "current_repo": None,
        "current_repo_id": None,
        "current_branch": "main",
        "editor_file": None,
        "session_token": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    if st.session_state.user is None and st.session_state.session_token:
        username = validate_session(st.session_state.session_token)
        if username:
            st.session_state.user = username
            st.session_state.view = "dashboard"
        else:
            st.session_state.session_token = None

    query_params = st.query_params
    if "token" in query_params and st.session_state.user is None:
        token = query_params["token"]
        username = validate_session(token)
        if username:
            st.session_state.user = username
            st.session_state.session_token = token
            st.session_state.view = "dashboard"
            st.query_params["token"] = token


def login_page():
    """Render login/registration page."""
    c1, c2, _ = st.columns([1, 2, 1])
    with c2:
        st.markdown("## ☁️ MiniHub Cloud")
        st.caption("Git-powered cloud repository manager")
        tab1, tab2 = st.tabs(["Login", "Sign Up"])

        with tab1:
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            remember = st.checkbox("Keep me logged in", value=True)

            if st.button("Login", use_container_width=True):
                if username and password:
                    success, token = login_user(username, password)
                    if success:
                        st.session_state.user = username
                        st.session_state.session_token = token
                        st.session_state.view = "dashboard"
                        if remember and token:
                            st.query_params["token"] = token
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials")
                else:
                    st.error("❌ Please enter username and password")

        with tab2:
            new_user = st.text_input("Username", key="register_user")
            new_pass = st.text_input("Password", type="password", key="register_pass")
            if st.button("Register", use_container_width=True):
                success, message = register_user(new_user, new_pass)
                if success:
                    st.success(f"✅ {message} Please login.")
                else:
                    st.error(f"❌ {message}")


def dashboard_page():
    """Render user dashboard."""

    def handle_logout():
        if st.session_state.session_token:
            logout_session(st.session_state.session_token)
        st.session_state.user = None
        st.session_state.session_token = None
        st.session_state.view = "login"
        if "token" in st.query_params:
            del st.query_params["token"]

    st.sidebar.button("🚪 Logout", on_click=handle_logout)

    st.title(f"👋 Welcome, {st.session_state.user}")

    with st.expander("➕ Create New Repository", expanded=False):
        col1, col2 = st.columns([2, 1])
        with col1:
            name = st.text_input("Repository Name")
        with col2:
            st.write("")
        desc = st.text_area("Description (optional)", height=100)

        if st.button("Create Repository", use_container_width=True):
            if name:
                success, message = init_repo(st.session_state.user, name, desc)
                if success:
                    st.success(f"✅ {message}")
                    st.rerun()
                else:
                    st.error(f"❌ {message}")
            else:
                st.error("❌ Repository name is required")

    st.markdown("---")
    st.markdown("### 📦 Your Repositories")
    repos = list_repos(st.session_state.user)

    if not repos:
        st.info("No repositories yet. Create your first one above! 🚀")
    else:
        cols = st.columns(3)
        for index, repo in enumerate(repos):
            with cols[index % 3]:
                with st.container(border=True):
                    st.markdown(f"**📦 {repo['name']}**")
                    if repo.get("description"):
                        st.caption(repo["description"])
                    st.caption(f"Created: {repo['created_at'][:10]}")
                    if st.button("Open →", key=repo["id"], use_container_width=True):
                        st.session_state.current_repo = repo["name"]
                        st.session_state.current_repo_id = repo["id"]
                        st.session_state.view = "repo"
                        st.session_state.editor_file = None
                        st.rerun()


def render_editor_tab(repo_id: str, branch: str, filename: str):
    """Render the editor tab content."""
    content = read_file(repo_id, branch, filename)
    ext = filename.split(".")[-1] if "." in filename else "text"
    lang_map = {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "md": "markdown",
        "html": "html",
        "css": "css",
        "json": "json",
        "xml": "xml",
        "yaml": "yaml",
        "c": "c",
        "cpp": "cpp",
        "java": "java",
        "cs": "csharp",
        "go": "go",
        "rs": "rust",
        "php": "php",
        "rb": "ruby",
    }
    lang = lang_map.get(ext, "text")

    st.caption(f"📝 Editing: **{filename}**")
    editor_response = code_editor(
        content,
        lang=lang,
        height="500px",
        theme="contrast",
        buttons=[
            {
                "name": "Save",
                "feather": "Save",
                "primary": True,
                "hasText": True,
                "commands": ["submit"],
                "style": {"bottom": "0.44rem", "right": "0.4rem"},
            }
        ],
    )

    if editor_response["type"] == "submit" and len(editor_response["text"]) > 0:
        if write_file(repo_id, branch, filename, editor_response["text"]):
            st.toast(f"💾 Saved {filename}!")
            zip_key = f"zip_{repo_id}_{branch}"
            if zip_key in st.session_state:
                del st.session_state[zip_key]

    st.divider()
    col1, col2 = st.columns(2)

    with col1:
        if st.button("➕ Stage File", use_container_width=True):
            result = stage_file(repo_id, branch, filename, editor_response.get("text", content))
            if result:
                st.success(f"✅ Staged {filename}")
                st.rerun()

    with col2:
        with st.popover("💾 Commit", use_container_width=True):
            msg = st.text_input("Commit Message")
            author = st.text_input("Author", value=f"{st.session_state.user} <{st.session_state.user}@minihub.cloud>")
            if st.button("Create Commit", use_container_width=True):
                if not msg:
                    st.error("❌ Message required!")
                else:
                    commit_id = create_commit(repo_id, branch, msg, author)
                    if commit_id:
                        st.success(f"✅ Commit created: {commit_id[:8]}")
                        st.rerun()
                    else:
                        st.error("❌ Nothing staged or commit failed!")


def render_history_tab(repo_id: str, branch: str):
    """Render the history tab content."""
    st.markdown("### 📜 Commit History")
    current_head = read_head(repo_id, branch)
    log = get_commit_log(repo_id, branch)

    if not log:
        st.info("No commits yet. Make your first commit! 🚀")
        return

    for commit in log:
        timestamp = commit.get("commit_timestamp") or commit.get("timestamp", "Unknown")
        timestamp_short = timestamp[:10] if timestamp != "Unknown" else "Unknown"
        is_head = commit["commit_id"] == current_head
        head_indicator = " 👉 **HEAD**" if is_head else ""

        with st.expander(
            f"**{commit.get('message', 'No message')}** · {commit['commit_id'][:8]} · {timestamp_short}{head_indicator}",
            expanded=is_head,
        ):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"**Author:** {commit.get('author', 'Unknown')}")
                st.markdown(f"**Commit ID:** `{commit['commit_id']}`")
                parent = commit.get("parent_commit_id", "None") or "None"
                st.markdown(f"**Parent:** `{parent}`")
                st.markdown(f"**Timestamp:** {timestamp}")
                if is_head:
                    st.success("✅ Currently checked out")

            with col2:
                if not is_head:
                    if st.button("🔄 Checkout", key=f"checkout_{commit['commit_id']}", use_container_width=True):
                        with st.spinner("Checking out commit..."):
                            if checkout_commit(repo_id, branch, commit["commit_id"]):
                                st.success("✅ Checked out successfully")
                                st.rerun()
                            else:
                                st.error("❌ Checkout failed")
                else:
                    st.info("Current")

                if st.button("📊 View Details", key=f"details_{commit['commit_id']}", use_container_width=True):
                    st.session_state.viewing_commit = commit["commit_id"]
                    st.rerun()

            st.markdown("**Files in this commit:**")
            files = commit.get("files", {})
            if files:
                for file_name, hash_str in files.items():
                    st.code(f"📄 {file_name} ({hash_str[:8]})", language="")
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

    col1, col2 = st.columns([5, 1])
    with col1:
        st.title("📋 Commit Details")
        st.caption(f"Commit {commit['commit_id'][:12]}")
    with col2:
        if st.button("← Back", use_container_width=True):
            del st.session_state.viewing_commit
            st.rerun()

    st.divider()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Author", commit.get("author", "Unknown").split("<")[0].strip())
    with col2:
        timestamp = commit.get("commit_timestamp") or commit.get("timestamp", "Unknown")
        st.metric("Date", timestamp[:10] if timestamp != "Unknown" else "Unknown")
    with col3:
        parent = commit.get("parent_commit_id")
        st.metric("Parent", parent[:8] if parent else "None")

    st.markdown("### 💬 Message")
    st.info(commit.get("message", "No message"))
    st.divider()

    st.markdown("### 📊 Changes Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("✅ Added", len(details["files_added"]))
    with col2:
        st.metric("📝 Modified", len(details["files_modified"]))
    with col3:
        st.metric("🗑️ Deleted", len(details["files_deleted"]))

    st.divider()
    st.markdown("### 🔍 File Changes")

    if details["files_added"]:
        st.markdown("#### ✅ Added Files")
        for filename in details["files_added"]:
            new_content = get_file_from_commit(repo_id, branch, commit_id, filename)
            if new_content is not None:
                diff = generate_diff("", new_content, filename)
                _render_diff_card(
                    "added",
                    filename,
                    diff_text=diff if diff else None,
                    raw_text=new_content if not diff else None,
                    raw_language="text",
                )
            else:
                st.warning(f"Could not load file content for {filename}")

    if details["files_modified"]:
        st.markdown("#### 📝 Modified Files")
        for filename in details["files_modified"]:
            parent_id = commit.get("parent_commit_id")
            if parent_id:
                old_content = get_file_from_commit(repo_id, branch, parent_id, filename)
                new_content = get_file_from_commit(repo_id, branch, commit_id, filename)
                if old_content is not None and new_content is not None:
                    diff = generate_diff(old_content, new_content, filename)
                    _render_diff_card(
                        "modified",
                        filename,
                        diff_text=diff if diff else None,
                        raw_text="No differences found" if not diff else None,
                        raw_language="text",
                    )
                else:
                    st.warning(f"Could not load file content for {filename}")
            else:
                st.warning("No parent commit to compare with")

    if details["files_deleted"]:
        st.markdown("#### 🗑️ Deleted Files")
        for filename in details["files_deleted"]:
            parent_id = commit.get("parent_commit_id")
            if parent_id:
                old_content = get_file_from_commit(repo_id, branch, parent_id, filename)
                if old_content is not None:
                    diff = generate_diff(old_content, "", filename)
                    _render_diff_card(
                        "deleted",
                        filename,
                        diff_text=diff if diff else None,
                        raw_text=old_content if not diff else None,
                        raw_language="text",
                    )
                else:
                    st.warning(f"Could not load file content for {filename}")
            else:
                st.warning("No parent commit to compare with")

    st.divider()
    st.markdown("### 📁 All Files in Commit")
    files = commit.get("files", {})
    if files:
        for filename, hash_str in files.items():
            col1, col2 = st.columns([4, 1])
            with col1:
                st.text(f"📄 {filename}")
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
                        st.success(f"✅ Found {len(results)} commit(s):")
                        for result in results:
                            st.code(f"{result['commit_id'][:8]} · {result['branch_name']} · {result['message']}", language="")
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
    username = st.session_state.user
    repo_name = st.session_state.current_repo
    repo_id = st.session_state.current_repo_id
    branch = st.session_state.current_branch

    if "viewing_commit" in st.session_state and st.session_state.viewing_commit:
        render_commit_details_modal()
        return

    with st.sidebar:
        if st.button("⬅️ Dashboard"):
            st.session_state.view = "dashboard"
            st.rerun()

        st.divider()
        st.markdown("### 🔧 Actions")

        zip_key = f"zip_{repo_id}_{branch}"
        if st.button("📦 Prepare Download", use_container_width=True):
            with st.spinner("Creating archive..."):
                zip_buffer = create_repo_zip(repo_id, branch)
                if zip_buffer:
                    st.session_state[zip_key] = zip_buffer
                    st.success("✅ Archive ready!")
                else:
                    st.error("❌ Failed to create archive")

        if zip_key in st.session_state:
            st.download_button(
                label="⬇️ Download ZIP",
                data=st.session_state[zip_key],
                file_name=f"{repo_name}-{branch}.zip",
                mime="application/zip",
                use_container_width=True,
            )

        st.divider()

        with st.expander("📤 Upload Files", expanded=False):
            uploaded_files = st.file_uploader(
                "Drag and drop files here",
                accept_multiple_files=True,
                key="file_uploader",
                help="Upload multiple files to your repository",
            )

            if uploaded_files:
                st.info(f"📁 {len(uploaded_files)} file(s) ready to upload")
                if st.button("Upload All", use_container_width=True, type="primary"):
                    success_count = 0
                    failed_files = []

                    for uploaded_file in uploaded_files:
                        filename = uploaded_file.name
                        valid, error = validate_filename(filename)
                        if not valid:
                            st.error(f"❌ {filename}: {error}")
                            failed_files.append(filename)
                            continue

                        file_size = uploaded_file.size
                        if file_size > MAX_FILE_SIZE:
                            st.error(f"❌ {filename}: File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)")
                            failed_files.append(filename)
                            continue

                        try:
                            content = uploaded_file.read()
                            if write_file(repo_id, branch, filename, content.decode("utf-8", errors="ignore")):
                                success_count += 1
                                st.toast(f"✅ Uploaded {filename}")
                            else:
                                failed_files.append(filename)
                        except Exception as exc:
                            st.error(f"❌ {filename}: {exc}")
                            failed_files.append(filename)

                    if success_count > 0:
                        st.success(f"✅ Uploaded {success_count} file(s)")
                        if zip_key in st.session_state:
                            del st.session_state[zip_key]
                        st.rerun()

                    if failed_files:
                        st.error(f"❌ Failed: {', '.join(failed_files)}")

        st.divider()

        with st.expander("➕ New File"):
            new_filename = st.text_input("Filename")
            if st.button("Create", use_container_width=True):
                if new_filename:
                    valid, error = validate_filename(new_filename)
                    if valid:
                        if write_file(repo_id, branch, new_filename, "# New File\n"):
                            st.success(f"✅ Created {new_filename}")
                            st.rerun()
                    else:
                        st.error(f"❌ {error}")
                else:
                    st.error("❌ Filename required")

        st.divider()

        st.markdown("### 📁 Files")
        files = list_files(repo_id, branch)

        if not files:
            st.info("No files")
        else:
            for file_name in files:
                col1, col2 = st.columns([4, 1])
                if col1.button(f"📄 {file_name}", key=f"f_{file_name}", use_container_width=True):
                    st.session_state.editor_file = file_name
                    st.rerun()
                if col2.button("🗑️", key=f"d_{file_name}"):
                    if delete_file(repo_id, branch, file_name):
                        if st.session_state.editor_file == file_name:
                            st.session_state.editor_file = None
                        st.success(f"✅ Deleted {file_name}")
                        st.rerun()

        st.divider()
        staged = get_staged_files(repo_id, branch)
        if staged:
            st.markdown("### 📋 Staged")
            for filename in staged.keys():
                st.text(f"✓ {filename}")

    st.title(f"{username} / {repo_name}")
    branches = list_branches(repo_id)
    selected_branch = st.selectbox(
        "🌿 Branch",
        branches,
        index=branches.index(branch) if branch in branches else 0,
    )

    if selected_branch != branch:
        st.session_state.current_branch = selected_branch
        st.session_state.editor_file = None
        zip_key = f"zip_{repo_id}_{branch}"
        if zip_key in st.session_state:
            del st.session_state[zip_key]
        st.rerun()

    tab1, tab2, tab3, tab4 = st.tabs(["📝 Editor", "📜 History", "🔍 Advanced", "💻 Terminal"])

    with tab1:
        if st.session_state.editor_file:
            render_editor_tab(repo_id, branch, st.session_state.editor_file)
        else:
            st.info("👈 Select a file from the sidebar to edit")

    with tab2:
        render_history_tab(repo_id, branch)

    with tab3:
        render_advanced_tab(repo_id, branch)

    with tab4:
        render_terminal_tab(repo_id, branch, repo_name, u)


def render_terminal_tab(repo_id: str, branch: str, repo_name: str, username: str):
    """Render git-like terminal interface."""
    st.markdown("### 💻 MiniHub Terminal")
    terminal = MiniHubTerminal()
    ctx = TerminalContext(
        username=username,
        repo_name=repo_name,
        repo_id=repo_id,
        branch=branch,
        session_state=st.session_state,
        session_token=st.session_state.get("session_token"),
    )
    history_key = f"terminal_history_{repo_id}_{branch}"
    cmd_key = f"terminal_cmd_{repo_id}_{branch}"
    history = st.session_state.setdefault(history_key, [])

    history_container = st.container(border=True)
    with history_container:
        if history:
            for entry in history:
                prompt = entry.get("prompt", "")
                lines = entry.get("output", [])
                st.markdown(f"<span style='color:#79c0ff;'>{prompt}</span>", unsafe_allow_html=True)
                if lines:
                    st.code("\n".join(lines), language="text")
        else:
            st.info("Type `help` to see available commands.")

    with st.form(key=f"terminal_form_{repo_id}_{branch}", clear_on_submit=True):
        command = st.text_input(
            label="Terminal",
            key=cmd_key,
            placeholder="e.g. status, add README.md, commit -m \"message\"",
        )
        submitted = st.form_submit_button("Run", use_container_width=True)

    if submitted and command:
        result = terminal.execute(command, ctx)
        if result.get("clear_history"):
            st.session_state[history_key] = []
        else:
            prompt = f"{repo_name}({branch})$ {command}"
            history.append({"prompt": prompt, "output": result.get("lines", [])})
            st.session_state[history_key] = history
        st.rerun()


def _render_diff_card(change_type: str, filename: str, diff_text: str | None, raw_text: str | None = None, raw_language: str = "text"):
    """Render a single diff block with consistent styling."""
    badge_map = {
        "added": ("Added", "#238636", "➕"),
        "modified": ("Modified", "#d29922", "📝"),
        "deleted": ("Deleted", "#f85149", "➖"),
    }
    label, color, icon = badge_map.get(change_type, ("Changed", "#6e7681", "📄"))
    badge_html = f"<span style='background-color:{color}; color:white; padding:0.15rem 0.65rem; border-radius:999px; font-size:0.75rem;'>{label}</span>"

    with st.container(border=True):
        col1, col2 = st.columns([4, 1])
        col1.markdown(f"**{icon} {filename}**")
        col2.markdown(badge_html, unsafe_allow_html=True)

        if diff_text:
            st.code(diff_text, language="diff")
        elif raw_text:
            st.code(raw_text, language=raw_language)
        else:
            st.info("No diff to display for this file")


__all__ = [
    "dashboard_page",
    "init_session",
    "login_page",
    "render_commit_details_modal",
    "render_editor_tab",
    "render_history_tab",
    "render_advanced_tab",
    "repo_page",
]

