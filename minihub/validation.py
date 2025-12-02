import re
from typing import Tuple

from minihub.config import ALLOWED_FILENAME_PATTERN


def validate_filename(filename: str) -> Tuple[bool, str]:
    """Validate filenames uploaded or created via the UI."""
    if not filename:
        return False, "Filename cannot be empty"
    if ".." in filename:
        return False, "Filename cannot contain '..'"
    if not re.match(ALLOWED_FILENAME_PATTERN, filename):
        return False, "Filename contains invalid characters"
    if len(filename) > 255:
        return False, "Filename too long"
    return True, ""


def validate_repo_name(name: str) -> Tuple[bool, str]:
    """Validate new repository names."""
    if not name:
        return False, "Repository name cannot be empty"
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return False, "Repository name can only contain letters, numbers, underscores, and hyphens"
    if len(name) > 100:
        return False, "Repository name too long"
    return True, ""


__all__ = ["validate_filename", "validate_repo_name"]

