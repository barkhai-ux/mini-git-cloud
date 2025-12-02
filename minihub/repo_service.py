import io
import zipfile
from typing import List, Optional, Tuple

import streamlit as st

from minihub.config import MAX_FILE_SIZE, STORAGE_BUCKET, supabase
from minihub.validation import validate_filename, validate_repo_name


def get_repo_id(username: str, repo_name: str) -> Optional[str]:
    """Get repository UUID from username and repo name."""
    try:
        result = (
            supabase.table("repositories")
            .select("id")
            .eq("owner_username", username)
            .eq("name", repo_name)
            .execute()
        )
        return result.data[0]["id"] if result.data else None
    except Exception as exc:
        st.error(f"Error fetching repository: {exc}")
        return None


def init_repo(username: str, repo_name: str, description: str = "") -> Tuple[bool, str]:
    """Initialize a new repository. Returns (success, message)."""
    valid, error = validate_repo_name(repo_name)
    if not valid:
        return False, error

    try:
        existing = (
            supabase.table("repositories")
            .select("id")
            .eq("owner_username", username)
            .eq("name", repo_name)
            .execute()
        )
        if existing.data:
            return False, "Repository already exists"

        repo_result = supabase.table("repositories").insert(
            {
                "name": repo_name,
                "owner_username": username,
                "description": description,
                "is_public": True,
                "default_branch": "main",
            }
        ).execute()

        repo_id = repo_result.data[0]["id"]
        supabase.table("branches").insert({"repository_id": repo_id, "name": "main", "head_commit_id": None}).execute()

        readme_content = f"# {repo_name}\n\n{description or 'Initialized with MiniHub Cloud'}"
        supabase.storage.from_(STORAGE_BUCKET).upload(f"{repo_id}/main/head/README.md", readme_content.encode("utf-8"))

        return True, "Repository created successfully"
    except Exception as exc:
        return False, f"Failed to create repository: {exc}"


def list_repos(username: str) -> List[dict]:
    """List all repositories owned by user."""
    try:
        result = (
            supabase.table("repositories")
            .select("*")
            .eq("owner_username", username)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data if result.data else []
    except Exception as exc:
        st.error(f"Error listing repositories: {exc}")
        return []


def list_branches(repo_id: str) -> List[str]:
    """List all branches in a repository."""
    try:
        result = supabase.table("branches").select("name").eq("repository_id", repo_id).execute()
        return [b["name"] for b in result.data] if result.data else ["main"]
    except Exception as exc:
        st.error(f"Error listing branches: {exc}")
        return ["main"]


def read_file(repo_id: str, branch: str, filename: str) -> str:
    """Read a file from working directory."""
    try:
        data = supabase.storage.from_(STORAGE_BUCKET).download(f"{repo_id}/{branch}/head/{filename}")
        return data.decode("utf-8")
    except Exception as exc:
        st.warning(f"Could not read file {filename}: {exc}")
        return ""


def write_file(repo_id: str, branch: str, filename: str, content: str | bytes) -> bool:
    """Write a file to working directory. Accepts string or bytes."""
    valid, error = validate_filename(filename)
    if not valid:
        st.error(error)
        return False

    content_bytes = content.encode("utf-8") if isinstance(content, str) else content
    if len(content_bytes) > MAX_FILE_SIZE:
        st.error(f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)")
        return False

    try:
        supabase.storage.from_(STORAGE_BUCKET).upload(
            f"{repo_id}/{branch}/head/{filename}", content_bytes, {"upsert": "true"}
        )
        return True
    except Exception as exc:
        st.error(f"Failed to write file: {exc}")
        return False


def delete_file(repo_id: str, branch: str, filename: str) -> bool:
    """Delete a file from working directory."""
    try:
        supabase.storage.from_(STORAGE_BUCKET).remove([f"{repo_id}/{branch}/head/{filename}"])
        return True
    except Exception as exc:
        st.error(f"Failed to delete file: {exc}")
        return False


def list_files(repo_id: str, branch: str) -> List[str]:
    """List all files in working directory."""
    try:
        files = supabase.storage.from_(STORAGE_BUCKET).list(f"{repo_id}/{branch}/head")
        return [f["name"] for f in files if f["name"] != ".empty"]
    except Exception as exc:
        st.warning(f"Error listing files: {exc}")
        return []


def create_repo_zip(repo_id: str, branch: str) -> Optional[io.BytesIO]:
    """Creates a zip file in memory of the current branch head."""
    buffer = io.BytesIO()
    prefix = f"{repo_id}/{branch}/head"

    try:
        files = supabase.storage.from_(STORAGE_BUCKET).list(prefix)
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                if f["name"] == ".empty":
                    continue
                file_path = f"{prefix}/{f['name']}"
                try:
                    file_data = supabase.storage.from_(STORAGE_BUCKET).download(file_path)
                    zf.writestr(f["name"], file_data)
                except Exception as exc:
                    st.warning(f"Failed to add {f['name']} to archive: {exc}")

        buffer.seek(0)
        return buffer
    except Exception as exc:
        st.error(f"Failed to create archive: {exc}")
        return None


__all__ = [
    "create_repo_zip",
    "delete_file",
    "get_repo_id",
    "init_repo",
    "list_branches",
    "list_files",
    "list_repos",
    "read_file",
    "write_file",
]

