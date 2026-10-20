"""Read OpenCode's coexisting SQLite generations; never query credential values."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .sqlite_input import sqlite_snapshot


def _object(value):
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("OpenCode message payload is not an object")
    return parsed


def _text_parts(parts):
    return "\n".join(part["text"] for part in parts if isinstance(part, dict) and part.get("type") in {"text", "reasoning"} and isinstance(part.get("text"), str))


def opencode_records(path: Path):
    """Yield normalized content only, preserving generation in session identities."""
    with sqlite_snapshot(path) as connection:
        connection.row_factory = sqlite3.Row
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for generation, session_table, message_table in (("v1", "session", "message"), ("v2", "session_v2", "session_message")):
            if not {session_table, message_table}.issubset(tables):
                continue
            for session in connection.execute(f'SELECT id,title,directory,time_created FROM "{session_table}"'):
                base = {"session_id": f"{generation}:{session['id']}", "session_title": session["title"], "cwd": session["directory"], "timestamp": session["time_created"]}
                yield {**base, "role": "metadata", "content": ""}
                for message in connection.execute(f'SELECT * FROM "{message_table}" WHERE session_id=? ORDER BY time_created,id', (session["id"],)):
                    data = _object(message["data"])
                    role = message["type"] if generation == "v2" else data.get("role")
                    if generation == "v1":
                        if "part" not in tables:
                            continue
                        parts = [_object(row[0]) for row in connection.execute('SELECT data FROM part WHERE message_id=? ORDER BY time_created,id', (message["id"],))]
                    else:
                        parts = data.get("content", [])
                    content = data.get("text", "") if role == "user" and generation == "v2" else _text_parts(parts)
                    if role in {"user", "assistant"} and content:
                        yield {**base, "role": role, "content": content, "timestamp": message["time_created"]}
                    for part in parts:
                        if not isinstance(part, dict) or part.get("type") != "tool":
                            continue
                        state = part.get("state")
                        if not isinstance(state, dict):
                            continue
                        content = json.dumps(state.get("input", {}), ensure_ascii=False)
                        output = state.get("output")
                        if isinstance(output, str):
                            content += "\n" + output
                        if isinstance(state.get("content"), list):
                            content += "\n" + _text_parts(state["content"])
                        yield {**base, "role": "tool", "content": content, "timestamp": message["time_created"]}


def collect_opencode_sessions(paths, progress=None):
    from .analyze import SessionMetric, _epoch_ms_to_utc
    from .common import artifact

    rows, artifacts, errors = [], [], []
    for path in (progress.items(paths) if progress else paths):
        sessions = {}
        try:
            for record in opencode_records(path):
                session = sessions.setdefault(record["session_id"], SessionMetric("OpenCode", record["session_id"]))
                session.add_source(path)
                session.session_title = record["session_title"]
                if record["cwd"]:
                    session.project_or_cwd.add(record["cwd"])
                session.add_timestamp(_epoch_ms_to_utc(record["timestamp"]))
                role = record["role"]
                if role == "metadata":
                    continue
                size = len(record["content"].encode("utf-8"))
                session.line_count += 1
                prefix = {"user": "request", "assistant": "response", "tool": "tool_event"}[role]
                count_name = prefix + ("_count" if role == "tool" else "_message_count")
                setattr(session, count_name, getattr(session, count_name) + 1)
                setattr(session, "total_" + prefix + "_bytes", getattr(session, "total_" + prefix + "_bytes") + size)
                if role != "tool":
                    setattr(session, "max_" + prefix + "_bytes", max(getattr(session, "max_" + prefix + "_bytes"), size))
            rows.extend(session.to_output() for session in sessions.values())
            artifacts.append(artifact(f"opencode.session_detail.{len(artifacts)}", "OpenCode", path, "Sessions / Chats", "SQLite", exists=True, parsed=True, metadata={"credential_values_read": False, "may_contain_credentials": True, "generations_kept_separate": True}))
        except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
            artifacts.append(artifact(f"opencode.session_detail.{len(artifacts)}", "OpenCode", path, "Sessions / Chats", "SQLite", exists=True, parsed=False, parse_error=str(exc)))
    return rows, artifacts, errors
