import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional

from minihub.git_ops import (
    checkout_commit,
    create_commit,
    get_commit_log,
    get_staged_files,
    read_head,
    stage_file,
)
from minihub.repo_service import list_files, read_file
from minihub.user_service import login_user


@dataclass
class TerminalContext:
    username: str
    repo_name: str
    repo_id: str
    branch: str
    session_state: Optional[dict] = None
    session_token: Optional[str] = None

    @property
    def author(self) -> str:
        return f"{self.username} <{self.username}@minihub.cloud>"

    def set_user(self, username: str, token: Optional[str]):
        self.username = username
        self.session_token = token
        if self.session_state is not None:
            self.session_state.user = username
            self.session_state.session_token = token


class MiniHubTerminal:
    """Lightweight git-like CLI that reuses the same Supabase backend."""

    def execute(self, command_str: str, context: TerminalContext) -> Dict[str, object]:
        result = {"lines": [], "clear_history": False}
        cmd = command_str.strip()
        if not cmd:
            return result

        try:
            parts = shlex.split(cmd)
        except ValueError as exc:
            result["lines"] = [f"Parse error: {exc}"]
            return result

        name = parts[0].lower()
        handler = getattr(self, f"_cmd_{name}", None)
        if not handler:
            result["lines"] = [f"Unknown command: {name}", "Type `help` for available commands."]
            return result

        lines, clear = handler(parts[1:], context)
        result["lines"] = lines
        result["clear_history"] = clear
        return result

    # --- commands ---

    def _cmd_help(self, args: List[str], context: TerminalContext):
        lines = [
            "MiniHub CLI commands:",
            "  help                 Show this help message",
            "  login <u> <p>        Authenticate as another user",
            "  status               Show branch, HEAD and staged files",
            "  ls                   List files in the working directory",
            "  cat <file>           Display file contents",
            "  add <file>           Stage a file for commit",
            "  commit -m \"msg\"    Create a commit with message",
            "  log                  Show recent commits",
            "  checkout <hash>      Checkout a commit",
            "  clear                Clear terminal output",
        ]
        return lines, False

    def _cmd_ls(self, args: List[str], context: TerminalContext):
        files = list_files(context.repo_id, context.branch)
        if not files:
            return ["(repository is empty)"], False
        return files, False

    def _cmd_cat(self, args: List[str], context: TerminalContext):
        if not args:
            return ["Usage: cat <filename>"], False
        filename = args[0]
        files = list_files(context.repo_id, context.branch)
        if filename not in files:
            return [f"{filename}: not found"], False
        content = read_file(context.repo_id, context.branch, filename)
        if content == "":
            return ["(empty file)"], False
        return content.splitlines(), False

    def _cmd_add(self, args: List[str], context: TerminalContext):
        if not args:
            return ["Usage: add <filename>"], False
        filename = args[0]
        files = list_files(context.repo_id, context.branch)
        if filename not in files:
            return [f"{filename}: not found"], False
        content = read_file(context.repo_id, context.branch, filename)
        staged = stage_file(context.repo_id, context.branch, filename, content)
        if staged:
            return [f"staged {filename}"], False
        return [f"failed to stage {filename}"], False

    def _cmd_login(self, args: List[str], context: TerminalContext):
        if len(args) < 2:
            return ["Usage: login <username> <password>"], False
        username, password = args[0], args[1]
        success, token = login_user(username, password)
        if success and token:
            context.set_user(username, token)
            return [f"Logged in as {username}"], False
        return ["Login failed"], False

    def _cmd_status(self, args: List[str], context: TerminalContext):
        head = read_head(context.repo_id, context.branch)
        staged = get_staged_files(context.repo_id, context.branch)
        files = list_files(context.repo_id, context.branch)

        lines = [
            f"On branch {context.branch}",
            f"HEAD: {head[:8] if head else 'None'}",
            "",
            "Staged files:" if staged else "No files staged",
        ]
        for filename in staged.keys():
            lines.append(f"  ✓ {filename}")
        lines.append("")
        lines.append("Working tree files:" if files else "No files in working tree")
        for filename in files:
            lines.append(f"  • {filename}")
        return lines, False

    def _cmd_commit(self, args: List[str], context: TerminalContext):
        message = self._extract_message(args)
        if not message:
            return ["Usage: commit -m \"message\""], False
        commit_id = create_commit(context.repo_id, context.branch, message, context.author)
        if commit_id:
            return [f"[{context.branch} {commit_id[:8]}] {message}"], False
        return ["Nothing to commit"], False

    def _cmd_log(self, args: List[str], context: TerminalContext):
        commits = get_commit_log(context.repo_id, context.branch, limit=20)
        if not commits:
            return ["No commits yet"], False
        lines: List[str] = []
        for commit in commits:
            lines.append(f"{commit['commit_id'][:8]} {commit.get('message', '')}")
            lines.append(f"Author: {commit.get('author', 'Unknown')}")
            lines.append(f"Date:   {commit.get('timestamp', 'Unknown')}")
            lines.append("")
        return lines, False

    def _cmd_checkout(self, args: List[str], context: TerminalContext):
        if not args:
            return ["Usage: checkout <commit_id>"], False
        commit_id = args[0]
        success = checkout_commit(context.repo_id, context.branch, commit_id)
        if success:
            return [f"Checked out {commit_id[:8]}"], False
        return [f"Failed to checkout {commit_id}"], False

    def _cmd_clear(self, args: List[str], context: TerminalContext):
        return [], True

    @staticmethod
    def _extract_message(args: List[str]) -> Optional[str]:
        if not args:
            return None
        if args[0] == "-m" and len(args) >= 2:
            return " ".join(args[1:])
        return " ".join(args)


__all__ = ["MiniHubTerminal", "TerminalContext"]

