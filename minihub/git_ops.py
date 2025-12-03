import datetime
import difflib
import hashlib
import io
import json
import zipfile
from typing import Dict, List, Optional

import streamlit as st

from minihub.config import STORAGE_BUCKET, supabase


def sha256_bytes(data: bytes) -> str:
    """Compute SHA256 hash of byte data."""
    return hashlib.sha256(data).hexdigest()


def now_utc_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def object_path_for_hash(hash_str: str) -> str:
    """Get storage path for object using first two chars as subdirectory."""
    return f"{hash_str[:2]}/{hash_str[2:]}"


def store_object(repo_id: str, branch: str, content: bytes) -> str:
    """
    Store content as a content-addressed object and return the SHA256 hash.
    Ensures both storage and database entries are created successfully.
    """
    hash_str = sha256_bytes(content)
    obj_path = object_path_for_hash(hash_str)
    storage_path = f"{repo_id}/{branch}/objects/{obj_path}"

    # Check if object already exists
    try:
        existing = (
            supabase.table("objects")
            .select("hash, storage_path")
            .eq("hash", hash_str)
            .eq("repository_id", repo_id)
            .execute()
        )
        if existing.data:
            # Verify storage file exists
            try:
                stored_path = existing.data[0]["storage_path"]
                supabase.storage.from_(STORAGE_BUCKET).download(stored_path)
                return hash_str
            except Exception:
                # Storage missing but DB entry exists - continue to re-store
                st.warning(f"Object {hash_str[:8]} found in DB but missing in storage, re-storing...")
    except Exception as exc:
        st.warning(f"Error checking object existence: {exc}")

    # Compress content
    compressed = io.BytesIO()
    try:
        with zipfile.ZipFile(compressed, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("content", content)
        compressed.seek(0)
        compressed_data = compressed.read()
    except Exception as exc:
        raise Exception(f"Failed to compress content: {exc}") from exc

    # Upload to storage (must succeed)
    try:
        supabase.storage.from_(STORAGE_BUCKET).upload(
            storage_path, compressed_data, {"upsert": "true", "content-type": "application/zip"}
        )
    except Exception as exc:
        raise Exception(f"Failed to upload object to storage: {exc}") from exc

    # Store metadata in database (must succeed)
    try:
        supabase.table("objects").insert(
            {
                "hash": hash_str,
                "repository_id": repo_id,
                "branch_name": branch,
                "object_type": "blob",
                "size_bytes": len(content),
                "storage_path": storage_path,
            }
        ).execute()
    except Exception as exc:
        if "duplicate" not in str(exc).lower() and "unique" not in str(exc).lower():
            # If storage succeeded but DB insert failed, try to clean up
            try:
                supabase.storage.from_(STORAGE_BUCKET).remove([storage_path])
            except Exception:
                pass
            raise Exception(f"Failed to store object metadata: {exc}") from exc

    return hash_str


def retrieve_object(repo_id: str, branch: str, hash_str: str) -> bytes:
    """
    Retrieve content from object store by hash.
    Tries database first, then falls back to trying storage paths directly.
    """
    # First, try to get storage path from database
    try:
        result = (
            supabase.table("objects")
            .select("storage_path")
            .eq("hash", hash_str)
            .eq("repository_id", repo_id)
            .execute()
        )

        if result.data:
            storage_path = result.data[0]["storage_path"]
            try:
                compressed_data = supabase.storage.from_(STORAGE_BUCKET).download(storage_path)
                with zipfile.ZipFile(io.BytesIO(compressed_data), "r") as zf:
                    return zf.read("content")
            except Exception as storage_exc:
                st.warning(f"Failed to download from DB path {storage_path}: {storage_exc}")
    except Exception as db_exc:
        st.warning(f"Database lookup failed for object {hash_str[:8]}: {db_exc}")

    # Fallback: try to find object in storage by trying common branch paths
    obj_path = object_path_for_hash(hash_str)
    branches_to_try = [branch, "main", "master"]
    
    for try_branch in branches_to_try:
        fallback_path = f"{repo_id}/{try_branch}/objects/{obj_path}"
        try:
            compressed_data = supabase.storage.from_(STORAGE_BUCKET).download(fallback_path)
            with zipfile.ZipFile(io.BytesIO(compressed_data), "r") as zf:
                content = zf.read("content")
                # Verify hash matches
                if sha256_bytes(content) == hash_str:
                    # Store metadata in DB for future lookups
                    try:
                        supabase.table("objects").insert({
                            "hash": hash_str,
                            "repository_id": repo_id,
                            "branch_name": try_branch,
                            "object_type": "blob",
                            "size_bytes": len(content),
                            "storage_path": fallback_path,
                        }).execute()
                    except Exception:
                        pass  # Ignore duplicate errors
                    return content
        except Exception:
            continue
    
    raise Exception(f"Object {hash_str} not found in database or storage")


def load_staging_index(repo_id: str, branch: str) -> Dict[str, Dict[str, str]]:
    """Load staging index from database."""
    try:
        result = (
            supabase.table("staging_index")
            .select("*")
            .eq("repository_id", repo_id)
            .eq("branch_name", branch)
            .execute()
        )

        index = {}
        for item in result.data:
            index[item["filename"]] = {
                "status": item["status"],
                "added_at": item["staged_at"],
                "hash": item["object_hash"],
            }
        return index
    except Exception as exc:
        st.error(f"Error loading staging index: {exc}")
        return {}


def save_staging_entry(repo_id: str, branch: str, filename: str, status: str, obj_hash: Optional[str] = None):
    """Save or update a staging entry."""
    try:
        supabase.table("staging_index").upsert(
            {
                "repository_id": repo_id,
                "branch_name": branch,
                "filename": filename,
                "status": status,
                "object_hash": obj_hash,
            },
            on_conflict="repository_id,branch_name,filename",
        ).execute()
    except Exception as exc:
        st.error(f"Error saving staging entry: {exc}")


def clear_staging_entry(repo_id: str, branch: str, filename: str):
    """Remove a file from staging."""
    try:
        supabase.table("staging_index").delete().eq("repository_id", repo_id).eq("branch_name", branch).eq("filename", filename).execute()
    except Exception as exc:
        st.error(f"Error clearing staging entry: {exc}")


def read_head(repo_id: str, branch: str) -> Optional[str]:
    """Read current HEAD commit ID from branches table."""
    try:
        result = (
            supabase.table("branches")
            .select("head_commit_id")
            .eq("repository_id", repo_id)
            .eq("name", branch)
            .execute()
        )

        if result.data and result.data[0]["head_commit_id"]:
            return result.data[0]["head_commit_id"]
        return None
    except Exception as exc:
        st.error(f"Error reading HEAD: {exc}")
        return None


def stage_file(repo_id: str, branch: str, filename: str, content: str) -> Optional[Dict[str, str]]:
    """Stage a file for commit."""
    try:
        stage_path = f"{repo_id}/{branch}/stage/{filename}"
        supabase.storage.from_(STORAGE_BUCKET).upload(stage_path, content.encode("utf-8"), {"upsert": "true"})
        save_staging_entry(repo_id, branch, filename, "staged", None)
        return {"status": "staged", "added_at": now_utc_iso(), "hash": None}
    except Exception as exc:
        st.error(f"Error staging file: {exc}")
        return None


def get_staged_files(repo_id: str, branch: str) -> Dict[str, Dict[str, str]]:
    """Get all files currently staged."""
    index = load_staging_index(repo_id, branch)
    return {k: v for k, v in index.items() if v.get("status") == "staged"}


def _update_branch_head(repo_id: str, branch: str, commit_id: Optional[str]):
    """Update the HEAD pointer for a branch."""
    try:
        supabase.table("branches").update({"head_commit_id": commit_id}).eq("repository_id", repo_id).eq("name", branch).execute()
    except Exception as exc:
        st.error(f"Failed to update branch head: {exc}")


def create_commit(repo_id: str, branch: str, message: str, author: Optional[str] = None) -> Optional[str]:
    """
    Create a commit from staged files and return commit ID (SHA256 hash).
    """
    staged = get_staged_files(repo_id, branch)
    if not staged:
        return None

    files_map: Dict[str, str] = {}
    failed_files: List[str] = []
    for filename in staged.keys():
        stage_path = f"{repo_id}/{branch}/stage/{filename}"
        try:
            content = supabase.storage.from_(STORAGE_BUCKET).download(stage_path)
            hash_str = store_object(repo_id, branch, content)
            files_map[filename] = hash_str
        except Exception as exc:
            st.error(f"Failed to store {filename}: {exc}")
            failed_files.append(filename)

    if failed_files:
        st.error(f"Commit aborted; failed to process: {', '.join(failed_files)}")
        return None

    if not files_map:
        st.error("No files were successfully stored")
        return None

    parent_commit = read_head(repo_id, branch)
    # Ensure parent exists to avoid FK violations if HEAD points to a missing commit
    if parent_commit:
        try:
            check = (
                supabase.table("commits")
                .select("commit_id")
                .eq("repository_id", repo_id)
                .eq("commit_id", parent_commit)
                .execute()
            )
            if not check.data:
                parent_commit = None
        except Exception as exc:
            st.warning(f"Could not verify parent commit, treating as root commit: {exc}")
            parent_commit = None
    commit_obj = {
        "parent": parent_commit,
        "timestamp": now_utc_iso(),
        "author": author or "User <user@example.com>",
        "message": message,
        "files": files_map,
    }

    canonical = json.dumps(commit_obj, separators=(",", ":"), sort_keys=True)
    commit_id = sha256_bytes(canonical.encode("utf-8"))

    try:
        supabase.table("commits").insert(
            {
                "commit_id": commit_id,
                "repository_id": repo_id,
                "branch_name": branch,
                "parent_commit_id": parent_commit,
                "author": commit_obj["author"],
                "message": message,
                "timestamp": commit_obj["timestamp"],
                "files": files_map,
            }
        ).execute()
    except Exception as exc:
        st.error(f"Failed to store commit: {exc}")
        return None

    for filename in staged.keys():
        try:
            supabase.storage.from_(STORAGE_BUCKET).remove([f"{repo_id}/{branch}/stage/{filename}"])
        except Exception as exc:
            st.warning(f"Failed to clear staged file {filename}: {exc}")
        clear_staging_entry(repo_id, branch, filename)

    _update_branch_head(repo_id, branch, commit_id)
    return commit_id


def checkout_commit(repo_id: str, branch: str, commit_id: str) -> bool:
    """
    Checkout a commit - replaces working directory with commit state.
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
            files_to_remove = [f"{repo_id}/{branch}/head/{f['name']}" for f in file_list if f["name"] != ".empty"]
            if files_to_remove:
                supabase.storage.from_(STORAGE_BUCKET).remove(files_to_remove)
                st.toast(f"🗑️ Cleared {len(files_to_remove)} file(s)")
        except Exception as exc:
            st.warning(f"Error clearing directory: {exc}")

        if not files_map:
            st.warning("⚠️ This commit has no files")
            _update_branch_head(repo_id, branch, commit_id)
            return True

        st.info(f"📦 Restoring {len(files_map)} file(s) from commit...")
        restored_count = 0
        failed_files: List[str] = []

        for filename, hash_str in files_map.items():
            try:
                content = retrieve_object(repo_id, branch, hash_str)
                supabase.storage.from_(STORAGE_BUCKET).upload(
                    f"{repo_id}/{branch}/head/{filename}",
                    content,
                    {"upsert": "true", "content-type": "application/octet-stream"},
                )
                restored_count += 1
                st.toast(f"✅ Restored: {filename}")
            except Exception as exc:
                st.error(f"❌ Failed to restore {filename}: {exc}")
                failed_files.append(filename)

        if restored_count == 0:
            st.error("❌ Failed to restore any files from commit")
            return False

        try:
            _update_branch_head(repo_id, branch, commit_id)
            st.success(f"✅ Checked out commit {commit_id[:8]} ({restored_count}/{len(files_map)} files)")
            if failed_files:
                st.warning(f"⚠️ Failed files: {', '.join(failed_files)}")
        except Exception as exc:
            st.error(f"❌ Failed to update HEAD: {exc}")
            return False

        return True
    except Exception as exc:
        st.error(f"❌ Checkout failed: {exc}")
        return False


def get_commit_log(repo_id: str, branch: str, limit: int = 50) -> List[dict]:
    """
    Get commit history for a branch ordered by timestamp desc.
    Shows the complete history even if HEAD is moved to an older commit.
    """
    try:
        result = (
            supabase.table("commits")
            .select("*")
            .eq("repository_id", repo_id)
            .eq("branch_name", branch)
            .order("timestamp", desc=True)
            .limit(limit)
            .execute()
        )
        return result.data if result.data else []
    except Exception as exc:
        st.error(f"Error fetching commit log: {exc}")
        return []


def get_file_from_commit(repo_id: str, branch: str, commit_id: str, filename: str) -> Optional[str]:
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
        return content.decode("utf-8", errors="replace")
    except Exception as exc:
        st.error(f"Error retrieving file from commit: {exc}")
        return None


def get_commit_details(repo_id: str, commit_id: str) -> Optional[dict]:
    """Get detailed information about a commit including parent comparison."""
    try:
        result = supabase.table("commits").select("*").eq("commit_id", commit_id).execute()
        if not result.data:
            return None

        commit = result.data[0]
        details = {"commit": commit, "files_added": [], "files_modified": [], "files_deleted": []}

        if commit.get("parent_commit_id"):
            parent_result = supabase.table("commits").select("files").eq("commit_id", commit["parent_commit_id"]).execute()
            if parent_result.data:
                parent_files = parent_result.data[0]["files"]
                current_files = commit["files"]

                for filename, hash_str in current_files.items():
                    if filename not in parent_files:
                        details["files_added"].append(filename)
                    elif parent_files[filename] != hash_str:
                        details["files_modified"].append(filename)

                for filename in parent_files.keys():
                    if filename not in current_files:
                        details["files_deleted"].append(filename)
        else:
            details["files_added"] = list(commit["files"].keys())

        return details
    except Exception as exc:
        st.error(f"Error getting commit details: {exc}")
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
        lineterm="",
    )
    return "".join(diff)


def find_commits_by_message(repo_id: str, message: str) -> List[dict]:
    """Find all commits whose message matches the supplied text."""
    try:
        result = supabase.rpc(
            "find_commits_by_message",
            {"p_repository_id": repo_id, "p_search_text": message},
        ).execute()
        return result.data if result.data else []
    except Exception as exc:
        st.error(f"Error searching commits: {exc}")
        return []


__all__ = [
    "checkout_commit",
    "clear_staging_entry",
    "create_commit",
    "find_commits_by_message",
    "generate_diff",
    "get_commit_details",
    "get_commit_log",
    "get_file_from_commit",
    "get_staged_files",
    "load_staging_index",
    "now_utc_iso",
    "object_path_for_hash",
    "read_head",
    "retrieve_object",
    "save_staging_entry",
    "sha256_bytes",
    "stage_file",
    "store_object",
]

