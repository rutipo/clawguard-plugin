"""Classify data sources and action types from tool calls."""

from __future__ import annotations


def classify_source(tool_name: str) -> str:
    """Map a tool name to a source category."""
    name = tool_name.lower()
    if "drive" in name:
        return "drive"
    if "slack" in name:
        return "slack"
    if "telegram" in name:
        return "telegram"
    if "file" in name or "read" in name or "write" in name:
        return "local_file"
    if "browser" in name or "web" in name:
        return "web"
    if "db" in name or "database" in name or "sql" in name:
        return "database"
    if "http" in name or "request" in name or "fetch" in name:
        return "api"
    if "shell" in name or "exec" in name or "bash" in name or "cmd" in name:
        return "shell"
    if "email" in name or "mail" in name:
        return "email"
    return "api"


def classify_action(tool_name: str, kwargs: dict) -> dict | None:
    """Classify a tool call into an action event, or return None if not classifiable."""
    name = tool_name.lower()

    # File reads
    if any(kw in name for kw in ("read", "open", "load", "cat")):
        target = kwargs.get("path") or kwargs.get("file_path") or kwargs.get("filepath") or "unknown"
        return {"action_type": "file_read", "target": str(target), "direction": "inbound"}

    # File writes
    if any(kw in name for kw in ("write", "save", "upload", "put")):
        target = kwargs.get("path") or kwargs.get("file_path") or kwargs.get("filepath") or "unknown"
        return {"action_type": "file_write", "target": str(target), "direction": "outbound"}

    # HTTP / API calls
    if any(kw in name for kw in ("http", "request", "fetch", "post", "get_url")):
        target = kwargs.get("url") or kwargs.get("endpoint") or "unknown"
        return {"action_type": "http_request", "target": str(target), "direction": "outbound"}

    # Email sends
    if any(kw in name for kw in ("email", "mail", "send_email")):
        target = kwargs.get("to") or kwargs.get("recipient") or "unknown"
        return {"action_type": "email_send", "target": str(target), "direction": "outbound"}

    # Slack sends
    if "slack" in name and any(kw in name for kw in ("send", "post", "write")):
        target = kwargs.get("channel") or kwargs.get("thread") or "unknown"
        return {"action_type": "slack_send", "target": str(target), "direction": "outbound"}

    # Drive writes
    if "drive" in name and any(kw in name for kw in ("write", "upload", "create")):
        target = kwargs.get("path") or kwargs.get("name") or "unknown"
        return {"action_type": "drive_write", "target": str(target), "direction": "outbound"}

    # Database writes
    if any(kw in name for kw in ("db_write", "db_insert", "db_update", "db_delete")):
        target = kwargs.get("table") or kwargs.get("collection") or "unknown"
        return {"action_type": "db_write", "target": str(target), "direction": "outbound"}

    # Shell execution
    if any(kw in name for kw in ("shell", "exec", "bash", "cmd", "run_command")):
        target = kwargs.get("command") or kwargs.get("cmd") or "unknown"
        return {"action_type": "shell_exec", "target": str(target)[:100], "direction": "outbound"}

    # Generic file access
    if "file" in name:
        target = kwargs.get("path") or kwargs.get("file_path") or kwargs.get("filepath") or "unknown"
        return {"action_type": "file_read", "target": str(target), "direction": "inbound"}

    return None
