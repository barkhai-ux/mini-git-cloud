import datetime
import hashlib
import secrets
from typing import Optional, Tuple

import streamlit as st

from minihub.config import supabase


def hash_password(password: str) -> str:
    """Hash password using SHA256 (basic implementation)."""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_session_token() -> str:
    """Generate a secure random session token."""
    return secrets.token_urlsafe(32)


def create_session(username: str) -> Optional[str]:
    """Create a new session for user and return token."""
    try:
        token = generate_session_token()
        expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat()

        supabase.table("user_sessions").insert(
            {"username": username, "token": token, "expires_at": expires_at}
        ).execute()
        return token
    except Exception as exc:
        st.error(f"Failed to create session: {exc}")
        return None


def validate_session(token: str) -> Optional[str]:
    """Validate session token and return username if valid."""
    try:
        result = supabase.table("user_sessions").select("username, expires_at").eq("token", token).execute()
        if not result.data:
            return None

        session = result.data[0]
        expires_at = datetime.datetime.fromisoformat(session["expires_at"])
        if datetime.datetime.utcnow() > expires_at:
            supabase.table("user_sessions").delete().eq("token", token).execute()
            return None

        return session["username"]
    except Exception as exc:
        st.error(f"Session validation error: {exc}")
        return None


def logout_session(token: str):
    """Delete session token on logout."""
    try:
        supabase.table("user_sessions").delete().eq("token", token).execute()
    except Exception as exc:
        st.warning(f"Failed to delete session: {exc}")


def register_user(username: str, password: str) -> Tuple[bool, str]:
    """Register a new user. Returns (success, message)."""
    if not username or not password:
        return False, "Username and password required"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"

    try:
        existing = supabase.table("users").select("*").eq("username", username).execute()
        if existing.data:
            return False, "Username already exists"

        supabase.table("users").insert({"username": username, "password": hash_password(password)}).execute()
        return True, "Registration successful"
    except Exception as exc:
        return False, f"Registration failed: {exc}"


def login_user(username: str, password: str) -> Tuple[bool, Optional[str]]:
    """Authenticate user and return (success, token)."""
    try:
        result = (
            supabase.table("users")
            .select("*")
            .eq("username", username)
            .eq("password", hash_password(password))
            .execute()
        )

        if result.data:
            token = create_session(username)
            return True, token
        return False, None
    except Exception as exc:
        st.error(f"Login error: {exc}")
        return False, None


__all__ = [
    "create_session",
    "generate_session_token",
    "hash_password",
    "login_user",
    "logout_session",
    "register_user",
    "validate_session",
]

