from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .common import (
    add_parse_error,
    artifact,
    build_envelope,
    finding,
    first_value,
    InputRoots,
    iter_jsonl,
    resolve_input_roots,
    safe_name,
    sha256_text,
    summarize_tools,
    text_metric,
    tool_result,
    write_output,
)
from .session_input import SessionSource


def _arbitrary_session_roots(input_root: str | Path) -> InputRoots:
    root = Path(input_root).expanduser().resolve()
    return InputRoots(
        input_mode="arbitrary_download",
        package_root=None,
        target_root=root,
        target_tool=None,
        codex_root=None,
        claude_root=None,
        claude_home_config=None,
        cursor_root=None,
        antigravity_cli_root=None,
    )


def _session_source_paths(sources: Iterable[SessionSource]) -> dict[str, dict[str, list[Path]]]:
    grouped: dict[str, dict[str, list[Path]]] = {}
    for source in sources:
        grouped.setdefault(source.detected_tool, {}).setdefault(source.artifact_type, []).append(source.path)
    for artifacts in grouped.values():
        for paths in artifacts.values():
            paths.sort(key=lambda path: str(path).lower())
    return grouped


def _source_paths(grouped: dict[str, dict[str, list[Path]]], tool: str, *, format_name: str | None = None) -> list[Path]:
    artifacts = grouped.get(tool, {})
    if format_name == "SQLite":
        paths = [path for artifact_type, artifact_paths in artifacts.items() if artifact_type.endswith("_sqlite") for path in artifact_paths]
    elif format_name == "JSONL":
        paths = [path for artifact_type, artifact_paths in artifacts.items() if not artifact_type.endswith("_sqlite") for path in artifact_paths]
    else:
        paths = [path for artifact_paths in artifacts.values() for path in artifact_paths]
    return sorted(set(paths), key=lambda path: str(path).lower())


def _sqlite_schema_counts(path: Path) -> dict[str, Any]:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("PRAGMA query_only = ON")
        tables = [str(row[0]) for row in connection.execute("select name from sqlite_master where type = 'table' order by name")]
        counts: dict[str, int | None] = {}
        for table in tables:
            quoted = table.replace('"', '""')
            try:
                counts[table] = int(connection.execute(f'select count(*) from "{quoted}"').fetchone()[0])
            except sqlite3.Error:
                counts[table] = None
    return {"size_bytes": path.stat().st_size, "table_names": tables, "table_counts": counts, "body_columns_read": False}


def _epoch_ms_to_utc(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(float(value) / 1000, timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return str(value)


def _cursor_store_metadata(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute("select value from meta where key = 0").fetchone()
    if not row:
        return {}
    try:
        raw = bytes.fromhex(str(row[0])).decode("utf-8")
        value = json.loads(raw)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _cursor_store_records_from_connection(connection: sqlite3.Connection) -> tuple[dict[str, Any], list[dict[str, Any]], int, int]:
    records: list[dict[str, Any]] = []
    malformed_blob_count = 0
    metadata = _cursor_store_metadata(connection)
    blob_count = connection.execute("select count(*) from blobs").fetchone()[0]
    for blob_id, data in connection.execute("select id, data from blobs order by rowid"):
        try:
            value = json.loads(data)
        except (TypeError, json.JSONDecodeError, UnicodeDecodeError):
            malformed_blob_count += 1
            continue
        if not isinstance(value, dict) or not isinstance(value.get("role"), str):
            continue
        value["_cursor_blob_id"] = str(blob_id)
        records.append(value)
    return metadata, records, blob_count, malformed_blob_count


def _cursor_store_records(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], int, int, bool]:
    with tempfile.TemporaryDirectory(prefix="blacklight-cursor-store-", ignore_cleanup_errors=True) as tempdir:
        temp_path = Path(tempdir) / path.name
        shutil.copy2(path, temp_path)
        uri = f"{temp_path.resolve().as_uri()}?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            metadata, records, blob_count, malformed_blob_count = _cursor_store_records_from_connection(connection)
    return metadata, records, blob_count, malformed_blob_count, True


def _record_is_turn_aborted(record: dict[str, Any]) -> bool:
    event_type = str(first_value(record, ("type", "event_type", "eventType", "kind")) or "").lower()
    status = str(first_value(record, ("status", "state", "outcome")) or "").lower()
    reason = str(first_value(record, ("reason", "finish_reason", "finishReason")) or "").lower()
    return event_type in {"turn_aborted", "turn-aborted", "abort", "aborted"} or status in {"aborted", "cancelled", "canceled"} or reason in {"aborted", "cancelled", "canceled"}


def _top_level_value(record: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _codex_rollout_session_id(path: Path) -> str | None:
    match = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", path.stem, re.IGNORECASE)
    return match.group(1) if match else None


def _codex_envelope_session_id(record: dict[str, Any]) -> str | None:
    if str(record.get("type") or "").lower() != "session_meta":
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    value = _top_level_value(payload, ("id", "session_id", "sessionId"))
    return str(value) if value is not None else None


def _session_id_for_record(tool_name: str, path: Path, record: dict[str, Any], source_session_id: str | None = None) -> str:
    explicit_id = _top_level_value(record, ("session_id", "sessionId", "conversation_id", "conversationId"))
    if explicit_id is not None:
        return str(explicit_id)
    if tool_name == "Antigravity CLI":
        conversation_id = _antigravity_cli_conversation_id(path)
        if conversation_id is not None:
            return conversation_id
        if path.name == "history.jsonl":
            timestamp = first_value(record, ("timestamp", "created_at", "createdAt", "updated_at", "updatedAt", "ts"))
            content_hash = sha256_text(record) or "unknown"
            return f"history:{str(timestamp or 'no_timestamp')}:{content_hash[:12]}"
    if tool_name == "Codex":
        envelope_id = _codex_envelope_session_id(record)
        if envelope_id is not None:
            return envelope_id
        if source_session_id is not None:
            return source_session_id
    if tool_name == "Codex" and path.name == "session_index.jsonl":
        index_id = _top_level_value(record, ("id",))
        if index_id is not None:
            return str(index_id)
    if tool_name == "Codex" and any(part in {"sessions", "archived_sessions"} for part in path.parts):
        rollout_id = _codex_rollout_session_id(path)
        if rollout_id is not None:
            return rollout_id
    return path.stem


def _jsonl_paths(root: Path | None, relative_paths: Iterable[str]) -> list[Path]:
    if not root:
        return []
    paths: list[Path] = []
    for relative in relative_paths:
        path = root / relative
        if path.is_file():
            paths.append(path)
        elif path.is_dir():
            paths.extend(sorted(path.rglob("*.jsonl")))
    return paths


def _antigravity_cli_conversation_id(path: Path) -> str | None:
    uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    for part in reversed(path.parts):
        stem = Path(part).stem
        if uuid_pattern.match(part):
            return part.lower()
        if uuid_pattern.match(stem):
            return stem.lower()
    return None


def _antigravity_cli_transcript_paths(root: Path | None) -> list[Path]:
    if not root:
        return []
    brain = root / "brain"
    paths: list[Path] = []
    if brain.is_dir():
        for session_dir in sorted(child for child in brain.iterdir() if child.is_dir()):
            logs = session_dir / ".system_generated" / "logs"
            if not logs.is_dir():
                continue
            full = logs / "transcript_full.jsonl"
            compact = logs / "transcript.jsonl"
            if full.is_file():
                paths.append(full)
            elif compact.is_file():
                paths.append(compact)
    history = root / "history.jsonl"
    if history.is_file():
        paths.append(history)
    return paths


def _cursor_chat_db_paths(root: Path | None) -> list[Path]:
    if not root:
        return []
    chats = root / "chats"
    return sorted(chats.rglob("store.db")) if chats.is_dir() else []


def _cursor_agent_transcript_paths(root: Path | None) -> list[Path]:
    if not root:
        return []
    projects = root / "projects"
    return sorted(projects.glob("*/agent-transcripts/*/*.jsonl")) if projects.is_dir() else []


def _cursor_project_from_agent_transcript(path: Path) -> str | None:
    parts = path.parts
    try:
        project_index = parts.index("projects") + 1
    except ValueError:
        return None
    if project_index >= len(parts):
        return None
    encoded = parts[project_index]
    if not encoded or encoded == "__blacklight_unknown__":
        return None
    if encoded.isdigit():
        return encoded
    if encoded.startswith("Users-"):
        return "/" + encoded.replace("-", "/")
    return encoded.replace("-", "/")


@dataclass
class SessionMetric:
    tool: str
    session_id: str
    source_files: set[str] = field(default_factory=set)
    raw_jsonl_bytes: int = 0
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    project_or_cwd: set[str] = field(default_factory=set)
    session_title: str | None = None
    title_updated_at: str | None = None
    line_count: int = 0
    parse_error_count: int = 0
    request_message_count: int = 0
    response_message_count: int = 0
    tool_event_count: int = 0
    machine_context_count: int = 0
    attachment_snapshot_count: int = 0
    total_request_bytes: int = 0
    total_response_bytes: int = 0
    total_tool_event_bytes: int = 0
    total_machine_context_bytes: int = 0
    max_request_bytes: int = 0
    max_response_bytes: int = 0
    turn_aborted: bool = False

    def add_source(self, path: Path) -> None:
        key = str(path)
        if key not in self.source_files:
            self.source_files.add(key)
            self.raw_jsonl_bytes += path.stat().st_size

    def add_timestamp(self, value: Any) -> None:
        if value in (None, ""):
            return
        text = str(value)
        self.first_timestamp = text if self.first_timestamp is None or text < self.first_timestamp else self.first_timestamp
        self.last_timestamp = text if self.last_timestamp is None or text > self.last_timestamp else self.last_timestamp

    def to_output(self) -> dict[str, Any]:
        if self.response_message_count > 0:
            response_capture_status = "present"
        elif self.turn_aborted:
            response_capture_status = "absent_turn_aborted"
        elif self.line_count == 0:
            response_capture_status = "absent_index_only"
        else:
            response_capture_status = "absent_no_assistant_records"
        return {
            "tool": self.tool,
            "session_id": self.session_id,
            "primary_source_path": sorted(self.source_files)[0] if self.source_files else None,
            "source_paths": sorted(self.source_files),
            "source_file_count": len(self.source_files),
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "primary_project_or_cwd": sorted(self.project_or_cwd)[0] if self.project_or_cwd else None,
            "project_or_cwd_count": len(self.project_or_cwd),
            "title_present": self.session_title is not None,
            "session_title": self.session_title,
            "title_length": len(self.session_title) if self.session_title else None,
            "title_sha256": sha256_text(self.session_title),
            "title_updated_at": self.title_updated_at,
            "raw_jsonl_bytes": self.raw_jsonl_bytes,
            "line_count": self.line_count,
            "parse_error_count": self.parse_error_count,
            "request_message_count": self.request_message_count,
            "response_message_count": self.response_message_count,
            "tool_event_count": self.tool_event_count,
            "machine_context_count": self.machine_context_count,
            "attachment_snapshot_count": self.attachment_snapshot_count,
            "response_capture_status": response_capture_status,
            "total_request_bytes": self.total_request_bytes,
            "total_response_bytes": self.total_response_bytes,
            "total_tool_event_bytes": self.total_tool_event_bytes,
            "total_machine_context_bytes": self.total_machine_context_bytes,
            "total_extracted_content_bytes": self.total_request_bytes + self.total_response_bytes + self.total_tool_event_bytes,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
        }


def _claude_session_role(record: dict[str, Any]) -> str:
    """Classify Claude Code transcript records without treating metadata as user input."""
    event_type = str(record.get("type") or "").lower()
    message = record.get("message")
    message_role = str(message.get("role") or "").lower() if isinstance(message, dict) else ""
    user_type = str(record.get("userType") or "").lower()
    if event_type == "user" and message_role == "user" and user_type == "external":
        return "request"
    if event_type == "assistant" and message_role == "assistant":
        return "response"
    return "machine_context"


def _session_role(record: dict[str, Any], tool_name: str | None = None) -> str:
    if tool_name == "Claude Code":
        return _claude_session_role(record)
    role = first_value(record, ("role", "author", "sender"))
    if role:
        role_text = str(role).lower()
        if role_text in {"user", "human"}:
            return "request"
        if role_text in {"assistant", "ai"}:
            return "response"
        if role_text in {"tool", "function"}:
            return "tool"
    event_type = str(first_value(record, ("type", "event_type", "eventType", "kind")) or "").lower()
    source = str(first_value(record, ("source",)) or "").lower()
    if source in {"user_explicit", "user"} or event_type in {"user_input"}:
        return "request"
    if source == "model" or event_type in {"planner_response"}:
        return "response"
    if event_type in {"run_command", "view_file", "list_directory", "code_action", "tool_call", "tool_result"}:
        return "tool"
    if "assistant" in event_type or "response" in event_type:
        return "response"
    if "tool" in event_type or "function" in event_type:
        return "tool"
    return "request"


def _normalized_session_record(tool_name: str, record: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    if tool_name != "Codex":
        return record, _session_role(record, tool_name)
    outer_type = str(record.get("type") or "").lower()
    payload = record.get("payload")
    if outer_type not in {"event_msg", "response_item", "session_meta", "turn_context"} or not isinstance(payload, dict):
        return record, _session_role(record)
    if outer_type in {"session_meta", "turn_context"}:
        return payload, None

    payload_type = str(payload.get("type") or "").lower()
    role = str(payload.get("role") or "").lower()
    if (
        role in {"tool", "function"}
        or payload_type in {"tool_call", "tool_result"}
        or payload_type.endswith("_call")
        or payload_type.endswith("_call_output")
    ):
        return payload, "tool"
    if role in {"user", "human"} or payload_type in {"user_input", "user_message"}:
        return payload, "request"
    if role in {"assistant", "ai"} or payload_type in {"agent_message", "assistant_message"}:
        return payload, "response"
    return payload, None


def _attachment_snapshot_count(record: dict[str, Any]) -> int:
    value = first_value(record, ("attachments", "attachment_snapshots", "attachmentSnapshots"))
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value) if value else 0
    return 1 if value not in (None, "") else 0


def _collect_sessions(tool_name: str, paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    sessions: dict[str, SessionMetric] = {}
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        artifact_id = f"{tool_name.lower().replace(' ', '_')}.session_detail.{index}"
        metric_count_before = len(sessions)
        parse_error_count = 0
        source_session_id = _codex_rollout_session_id(path) if tool_name == "Codex" else None
        try:
            for line_number, record, error in iter_jsonl(path):
                if error:
                    parse_error_count += 1
                    errors.append({"path": str(path), "error": f"line {line_number}: {error}"})
                    continue
                record = record or {}
                source_session_id = _codex_envelope_session_id(record) or source_session_id
                session_id = _session_id_for_record(tool_name, path, record, source_session_id)
                session = sessions.setdefault(session_id, SessionMetric(tool_name, session_id))
                session.add_source(path)
                session.add_timestamp(first_value(record, ("timestamp", "created_at", "createdAt", "updated_at", "updatedAt", "ts")))
                project = first_value(
                    record,
                    (
                        "cwd",
                        "Cwd",
                        "project",
                        "project_path",
                        "projectPath",
                        "workspace",
                        "workspace_path",
                        "workspace_uris",
                        "DirectoryPath",
                        "AbsolutePath",
                        "TargetFile",
                    ),
                )
                if project:
                    session.project_or_cwd.add(str(project))
                title = first_value(record, ("title", "thread_name", "session_title", "sessionTitle"), scalar_only=True)
                if title:
                    session.session_title = str(title)
                    session.title_updated_at = str(first_value(record, ("updated_at", "updatedAt", "timestamp")) or "") or None
                if tool_name == "Codex" and path.name == "session_index.jsonl":
                    continue
                session.line_count += 1
                session.attachment_snapshot_count += _attachment_snapshot_count(record)
                if _record_is_turn_aborted(record):
                    session.turn_aborted = True
                semantic_record, role = _normalized_session_record(tool_name, record)
                metric = text_metric(semantic_record)
                if role == "response":
                    session.response_message_count += 1
                    session.total_response_bytes += metric["bytes"]
                    session.max_response_bytes = max(session.max_response_bytes, metric["bytes"])
                elif role == "tool":
                    session.tool_event_count += 1
                    session.total_tool_event_bytes += metric["bytes"]
                elif role == "machine_context":
                    session.machine_context_count += 1
                    session.total_machine_context_bytes += metric["bytes"]
                elif role == "request":
                    session.request_message_count += 1
                    session.total_request_bytes += metric["bytes"]
                    session.max_request_bytes = max(session.max_request_bytes, metric["bytes"])
            artifacts.append(
                artifact(
                    artifact_id,
                    tool_name,
                    path,
                    "Sessions / Chats",
                    "JSONL",
                    exists=True,
                    parsed=True,
                    metadata={"size_bytes": path.stat().st_size, "parse_error_count": parse_error_count},
                )
            )
            if parse_error_count and sessions:
                affected_sessions = [session for session in sessions.values() if str(path) in session.source_files]
                if not affected_sessions:
                    affected_sessions = list(sessions.values())
                for session in affected_sessions:
                    session.parse_error_count += parse_error_count
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(path), "error": str(exc)})
            artifacts.append(artifact(artifact_id, tool_name, path, "Sessions / Chats", "JSONL", exists=True, parsed=False, parse_error=str(exc)))
        if len(sessions) == metric_count_before and path.exists() and path.stat().st_size == 0:
            artifacts[-1]["metadata"] = {"size_bytes": 0, "parse_error_count": parse_error_count}
    session_rows = [session.to_output() for session in sessions.values()]
    session_rows.sort(key=lambda item: (item["total_extracted_content_bytes"], item["raw_jsonl_bytes"]), reverse=True)
    return session_rows, artifacts, errors


def _cursor_session_id(path: Path, metadata: dict[str, Any]) -> str:
    value = metadata.get("agentId") or metadata.get("conversationId") or metadata.get("id")
    return str(value) if value not in (None, "") else path.parent.name


def _collect_cursor_sessions(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    session_rows: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        artifact_id = f"cursor.session_detail.{index}"
        try:
            metadata, records, blob_count, malformed_blob_count, snapshot_opened = _cursor_store_records(path)
            if records or metadata:
                session_id = _cursor_session_id(path, metadata)
                session = SessionMetric("Cursor", session_id)
                session.add_source(path)
                session.line_count = len(records)
                session.parse_error_count = malformed_blob_count
                timestamp = _epoch_ms_to_utc(metadata.get("createdAt") or metadata.get("updatedAt"))
                session.add_timestamp(timestamp)
                title = metadata.get("name")
                if title not in (None, ""):
                    session.session_title = str(title)
                    session.title_updated_at = timestamp
                for record in records:
                    session.attachment_snapshot_count += _attachment_snapshot_count(record)
                    metric = text_metric(record)
                    role = _session_role(record)
                    if role == "response":
                        session.response_message_count += 1
                        session.total_response_bytes += metric["bytes"]
                        session.max_response_bytes = max(session.max_response_bytes, metric["bytes"])
                    elif role == "tool":
                        session.tool_event_count += 1
                        session.total_tool_event_bytes += metric["bytes"]
                    else:
                        session.request_message_count += 1
                        session.total_request_bytes += metric["bytes"]
                        session.max_request_bytes = max(session.max_request_bytes, metric["bytes"])
                session_rows.append(session.to_output())
            artifacts.append(
                artifact(
                    artifact_id,
                    "Cursor",
                    path,
                    "Sessions / Chats",
                    "SQLite",
                    exists=True,
                    parsed=True,
                    metadata={
                        "size_bytes": path.stat().st_size,
                        "blob_count": blob_count,
                        "json_message_count": len(records),
                        "malformed_blob_count": malformed_blob_count,
                        "metadata_present": bool(metadata),
                        "snapshot_opened": snapshot_opened,
                    },
                )
            )
            for error_index in range(malformed_blob_count):
                errors.append({"path": str(path), "error": f"malformed Cursor blob {error_index + 1}"})
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(path), "error": str(exc)})
            artifacts.append(artifact(artifact_id, "Cursor", path, "Sessions / Chats", "SQLite", exists=True, parsed=False, parse_error=str(exc)))
    session_rows.sort(key=lambda item: (item["total_extracted_content_bytes"], item["raw_jsonl_bytes"]), reverse=True)
    return session_rows, artifacts, errors


def _collect_cursor_agent_transcript_sessions(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    session_rows: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        artifact_id = f"cursor.agent_transcript_detail.{index}"
        parse_error_count = 0
        try:
            session_id = path.stem
            session = SessionMetric("Cursor", session_id)
            session.add_source(path)
            project = _cursor_project_from_agent_transcript(path)
            if project:
                session.project_or_cwd.add(project)
            for line_number, record, error in iter_jsonl(path):
                if error:
                    parse_error_count += 1
                    errors.append({"path": str(path), "error": f"line {line_number}: {error}"})
                    continue
                record = record or {}
                session.line_count += 1
                session.attachment_snapshot_count += _attachment_snapshot_count(record)
                session.add_timestamp(first_value(record, ("timestamp", "created_at", "createdAt", "updated_at", "updatedAt", "ts")))
                record_project = first_value(record, ("cwd", "project", "project_path", "projectPath", "workspace", "workspace_path"))
                if record_project:
                    session.project_or_cwd.add(str(record_project))
                title = first_value(record, ("title", "session_title", "sessionTitle"), scalar_only=True)
                if title:
                    session.session_title = str(title)
                    session.title_updated_at = str(first_value(record, ("updated_at", "updatedAt", "timestamp")) or "") or None
                if _record_is_turn_aborted(record):
                    session.turn_aborted = True
                metric = text_metric(record)
                role = _session_role(record)
                if role == "response":
                    session.response_message_count += 1
                    session.total_response_bytes += metric["bytes"]
                    session.max_response_bytes = max(session.max_response_bytes, metric["bytes"])
                elif role == "tool":
                    session.tool_event_count += 1
                    session.total_tool_event_bytes += metric["bytes"]
                else:
                    session.request_message_count += 1
                    session.total_request_bytes += metric["bytes"]
                    session.max_request_bytes = max(session.max_request_bytes, metric["bytes"])
            session.parse_error_count = parse_error_count
            session_rows.append(session.to_output())
            artifacts.append(
                artifact(
                    artifact_id,
                    "Cursor",
                    path,
                    "Sessions / Chats",
                    "JSONL",
                    exists=True,
                    parsed=True,
                    metadata={"size_bytes": path.stat().st_size, "parse_error_count": parse_error_count},
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(path), "error": str(exc)})
            artifacts.append(artifact(artifact_id, "Cursor", path, "Sessions / Chats", "JSONL", exists=True, parsed=False, parse_error=str(exc)))
    session_rows.sort(key=lambda item: (item["total_extracted_content_bytes"], item["raw_jsonl_bytes"]), reverse=True)
    return session_rows, artifacts, errors


def _session_aggregate(session_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "session_count": len(session_rows),
        "total_request_message_count": sum(item["request_message_count"] for item in session_rows),
        "total_response_message_count": sum(item["response_message_count"] for item in session_rows),
        "total_tool_event_count": sum(item["tool_event_count"] for item in session_rows),
        "total_machine_context_count": sum(item["machine_context_count"] for item in session_rows),
        "total_attachment_snapshot_count": sum(item["attachment_snapshot_count"] for item in session_rows),
        "total_request_bytes": sum(item["total_request_bytes"] for item in session_rows),
        "total_response_bytes": sum(item["total_response_bytes"] for item in session_rows),
        "total_tool_event_bytes": sum(item["total_tool_event_bytes"] for item in session_rows),
        "total_machine_context_bytes": sum(item["total_machine_context_bytes"] for item in session_rows),
        "total_extracted_content_bytes": sum(item["total_extracted_content_bytes"] for item in session_rows),
        "top_sessions_by_total_extracted_content_bytes": session_rows[:10],
    }


def run_session_detail(
    *,
    run_id: str,
    output_directory: str | Path | None = None,
    package_root: str | Path | None = None,
    target_root: str | Path | None = None,
    target_tool: str = "Auto",
    live_root: bool = False,
    codex_root: str | Path | None = None,
    claude_root: str | Path | None = None,
    claude_home_config: str | Path | None = None,
    cursor_root: str | Path | None = None,
    antigravity_cli_root: str | Path | None = None,
    session_sources: Iterable[SessionSource] | None = None,
    input_root: str | Path | None = None,
) -> dict[str, Any]:
    grouped_sources: dict[str, dict[str, list[Path]]] | None = None
    if session_sources is not None:
        if input_root is None:
            raise ValueError("input_root is required with session_sources")
        grouped_sources = _session_source_paths(session_sources)
        roots = _arbitrary_session_roots(input_root)
    else:
        roots = resolve_input_roots(
            package_root=package_root,
            target_root=target_root,
            target_tool=target_tool,
            live_root=live_root,
            codex_root=codex_root,
            claude_root=claude_root,
            claude_home_config=claude_home_config,
            cursor_root=cursor_root,
            antigravity_cli_root=antigravity_cli_root,
        )
    tools: list[dict[str, Any]] = []
    for tool_name, root, paths in (
        ("Codex", roots.target_root if grouped_sources and grouped_sources.get("Codex") else roots.codex_root,
         _source_paths(grouped_sources, "Codex", format_name="JSONL") if grouped_sources is not None else _jsonl_paths(roots.codex_root, ("session_index.jsonl", "history.jsonl", "sessions", "archived_sessions"))),
        ("Claude Code", roots.target_root if grouped_sources and grouped_sources.get("Claude Code") else roots.claude_root,
         _source_paths(grouped_sources, "Claude Code", format_name="JSONL") if grouped_sources is not None else _jsonl_paths(roots.claude_root, ("history.jsonl", "projects"))),
    ):
        if not root:
            continue
        tool = tool_result(tool_name, root)
        session_rows, artifacts, errors = _collect_sessions(tool_name, paths)
        if not paths:
            tool["artifacts"].append(artifact(f"{tool_name.lower().replace(' ', '_')}.session_detail", tool_name, root / "history.jsonl", "Sessions / Chats", "JSONL", exists=False, parsed=False))
        else:
            tool["artifacts"].extend(artifacts)
        tool["parse_errors"].extend(errors)
        aggregate = _session_aggregate(session_rows)
        tool["findings"].append(finding(tool_name, f"{tool_name.lower().replace(' ', '_')}.session_detail", "session_volume_structure", f"{tool_name}.sessions", {"aggregate": aggregate, "sessions": session_rows}))
        tools.append(tool)
    cursor_root = roots.target_root if grouped_sources and grouped_sources.get("Cursor") else roots.cursor_root
    if cursor_root and cursor_root.exists():
        tool = tool_result("Cursor", cursor_root)
        chat_paths = _source_paths(grouped_sources, "Cursor", format_name="SQLite") if grouped_sources is not None else _cursor_chat_db_paths(cursor_root)
        transcript_paths = _source_paths(grouped_sources, "Cursor", format_name="JSONL") if grouped_sources is not None else _cursor_agent_transcript_paths(cursor_root)
        chat_rows, chat_artifacts, chat_errors = _collect_cursor_sessions(chat_paths)
        transcript_rows, transcript_artifacts, transcript_errors = _collect_cursor_agent_transcript_sessions(transcript_paths)
        session_rows = sorted(chat_rows + transcript_rows, key=lambda item: (item["total_extracted_content_bytes"], item["raw_jsonl_bytes"]), reverse=True)
        if not chat_paths and not transcript_paths:
            tool["artifacts"].append(artifact("cursor.session_detail", "Cursor", cursor_root / "chats", "Sessions / Chats", "SQLite/JSONL", exists=False, parsed=False))
        else:
            tool["artifacts"].extend(chat_artifacts)
            tool["artifacts"].extend(transcript_artifacts)
        tool["parse_errors"].extend(chat_errors)
        tool["parse_errors"].extend(transcript_errors)
        aggregate = _session_aggregate(session_rows)
        tool["findings"].append(
            finding("Cursor", "cursor.session_detail", "session_volume_structure", "Cursor.sessions", {"aggregate": aggregate, "sessions": session_rows})
        )
        tools.append(tool)
    antigravity_root = roots.target_root if grouped_sources and grouped_sources.get("Antigravity CLI") else roots.antigravity_cli_root
    if antigravity_root and antigravity_root.exists():
        tool = tool_result("Antigravity CLI", antigravity_root)
        paths = _source_paths(grouped_sources, "Antigravity CLI", format_name="JSONL") if grouped_sources is not None else _antigravity_cli_transcript_paths(antigravity_root)
        sqlite_paths = _source_paths(grouped_sources, "Antigravity CLI", format_name="SQLite") if grouped_sources is not None else []
        session_rows, artifacts, errors = _collect_sessions("Antigravity CLI", paths)
        if not paths and not sqlite_paths:
            tool["artifacts"].append(
                artifact("antigravity_cli.session_detail", "Antigravity CLI", antigravity_root / "brain", "Sessions / Chats", "JSONL", exists=False, parsed=False)
            )
        else:
            tool["artifacts"].extend(artifacts)
        for index, path in enumerate(sqlite_paths):
            try:
                tool["artifacts"].append(artifact(f"antigravity_cli.session_sqlite.{index}", "Antigravity CLI", path, "Sessions / Chats", "SQLite", exists=True, parsed=True, metadata=_sqlite_schema_counts(path)))
            except Exception as exc:  # noqa: BLE001
                add_parse_error(tool, path, str(exc))
                tool["artifacts"].append(artifact(f"antigravity_cli.session_sqlite.{index}", "Antigravity CLI", path, "Sessions / Chats", "SQLite", exists=True, parsed=False, parse_error=str(exc)))
        tool["parse_errors"].extend(errors)
        aggregate = _session_aggregate(session_rows)
        tool["findings"].append(
            finding(
                "Antigravity CLI",
                "antigravity_cli.session_detail",
                "session_volume_structure",
                "Antigravity CLI.sessions",
                {"aggregate": aggregate, "sessions": session_rows},
            )
        )
        tools.append(tool)
    summary = summarize_tools(tools)
    aggregates = [item["findings"][0]["value"]["aggregate"] for item in tools if item["findings"]]
    summary.update(
        {
            "total_session_count": sum(item["session_count"] for item in aggregates),
            "total_request_message_count": sum(item["total_request_message_count"] for item in aggregates),
            "total_response_message_count": sum(item["total_response_message_count"] for item in aggregates),
            "total_machine_context_count": sum(item["total_machine_context_count"] for item in aggregates),
            "total_request_bytes": sum(item["total_request_bytes"] for item in aggregates),
            "total_response_bytes": sum(item["total_response_bytes"] for item in aggregates),
            "total_machine_context_bytes": sum(item["total_machine_context_bytes"] for item in aggregates),
        }
    )
    result = build_envelope(
        run_id=run_id,
        parser_name="session_detail",
        output_kind="session_detail",
        roots=roots,
        content_policy={
            "raw_message_text_included": False,
            "raw_credential_values_included": False,
            "semantic_parsing_included": False,
            "sensitivity_scoring_included": False,
            "config_values_included": False,
            "session_titles_included": True,
        },
        tools=tools,
        summary=summary,
    )
    return write_output(result, output_directory, f"{safe_name(run_id)}_Session_Detail_Parse", _summary_lines("Blacklight session detail parse", result))


@dataclass(frozen=True)
class IndicatorRule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    weight: int
    secret: bool = False


INDICATOR_RULES = [
    IndicatorRule("credential.assignment", "credential_secret", re.compile(r"\b(?:api[-_ ]?key|access[-_ ]?token|token|secret|password|passwd|pwd|authorization)\b\s*(?:[:=]|=>|-eq|\bis\b)\s*[\"']?(?:bearer\s+)?[A-Za-z0-9._~+/=:,@-]{8,}[\"']?", re.I), 10, True),
    IndicatorRule("credential.aws_access_key", "credential_secret", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 10, True),
    IndicatorRule("credential.private_key_header", "credential_secret", re.compile(r"^\s*-----BEGIN (?:RSA |DSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----\s*$", re.I | re.M), 10, True),
    IndicatorRule("credential.connection_string", "credential_secret", re.compile(r"\b(?:(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|mssql|sqlserver)://[^\s'\"<>]+|(?:server|data source|host|hostname|addr|address)\s*=\s*[^;\r\n]+;[^\r\n]{0,300})", re.I), 10, True),
    IndicatorRule("internal.private_ipv4", "internal_host", re.compile(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b"), 5),
    IndicatorRule("internal.localhost", "internal_host", re.compile(r"\b(?:localhost|127\.0\.0\.1|::1)\b", re.I), 3),
    IndicatorRule("internal.domain", "internal_host", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan|intranet)\b", re.I), 5),
    IndicatorRule("internal.named_host", "internal_host", re.compile(r"\b(?:dev|stage|stg|prod|admin|vpn|dc|ldap|sso|jump|bastion)[-_][a-z0-9][a-z0-9-]{0,62}\b(?:\.[a-z0-9.-]+)?", re.I), 2),
    IndicatorRule("cloud.aws_arn", "cloud_identity", re.compile(r"\barn:(?:aws|aws-cn|aws-us-gov):[a-z0-9-]+:[^:\s]*:[^:\s]*:[^\s'\"<>]+", re.I), 8),
    IndicatorRule("cloud.aws_account", "cloud_identity", re.compile(r"\b(?:aws[_ -]?account(?:[_ -]?id)?|account[_ -]?id)\b\s*[:=]\s*[\"']?\d{12}[\"']?", re.I), 6),
    IndicatorRule("cloud.azure_guid", "cloud_identity", re.compile(r"\b(?:tenant|subscription|client|application)(?:[_ -]?(?:id|guid))?\b\s*[:=]\s*[\"'{(]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\"')}]?", re.I), 6),
    IndicatorRule("cloud.gcp_service_account", "cloud_identity", re.compile(r"\b[a-z0-9-]{6,30}@[a-z][a-z0-9-]{4,62}\.iam\.gserviceaccount\.com\b", re.I), 7),
    IndicatorRule("network.host_port", "network_target", re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)\:(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})\b"), 4),
    IndicatorRule("network.ip_port", "network_target", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\:(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})\b"), 5),
    IndicatorRule("source_control.git_remote", "source_control", re.compile(r"\b(?:git@[\w.-]+:[^\s'\"<>]+\.git|ssh://(?:[^@\s]+@)?[\w.-]+(?::\d+)?/[^\s'\"<>]+\.git|https?://[\w.-]+/[^\s'\"<>]+\.git)\b", re.I), 4),
    IndicatorRule("agent_fs.posix_agent_root", "agent_filesystem", re.compile(r"(?<![\w/.-])(?:~|\$HOME|/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+)/(?:\.codex|\.claude|\.cursor|\.gemini/antigravity-cli)(?:/[^\s'\"<>)]{1,240})?", re.I), 3),
    IndicatorRule("agent_fs.windows_agent_root", "agent_filesystem", re.compile(r"(?i)(?<![\w\\.-])(?:%USERPROFILE%|[A-Z]:\\Users\\[A-Za-z0-9._ -]+)\\(?:\.codex|\.claude|\.cursor|\.gemini\\antigravity-cli)(?:\\[^\s'\"<>)]{1,240})?"), 3),
]


SENSITIVITY_SEVERITY_BUCKETS = ("critical", "high", "medium", "low")


def _severity_bucket(weight: int) -> str:
    if weight >= 10:
        return "critical"
    if weight >= 5:
        return "high"
    if weight >= 3:
        return "medium"
    return "low"


def _canonical_indicator_value(rule: IndicatorRule, value: str) -> str:
    clean = re.sub(r"\s+", " ", value).strip().strip("\"'`")
    if not rule.secret:
        clean = clean.strip(".,;:)]}").lower()
    return clean


def _placeholder_secret(value: str) -> bool:
    lower = value.strip().strip("\"'<>[]{}").lower()
    if not lower:
        return True
    return bool(
        re.match(
            r"^(?:example|sample|changeme|change_me|redacted|masked|placeholder|dummy|test|none|null|undefined|your[_-]?(?:api[_-]?key|token|secret|password)|x+|\*+|\.+)$",
            lower,
        )
    )


def _valid_indicator_match(rule: IndicatorRule, value: str, context: str) -> bool:
    clean = value.strip()
    if not clean:
        return False
    lower = clean.lower()
    if rule.rule_id == "credential.assignment":
        secret_part = re.sub(r"(?i)^.*?(?:[:=]|=>|-eq|\bis\b)\s*[\"']?(?:bearer\s+)?", "", clean).strip().strip("\"'")
        return len(secret_part) >= 8 and not _placeholder_secret(secret_part)
    if rule.rule_id == "credential.connection_string":
        if re.match(r"(?i)^(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|mssql|sqlserver)://", clean):
            return True
        return len(re.findall(r"(?i)\b(?:server|data source|host|hostname|addr|address|database|dbname|uid|user(?: id)?|password|pwd|trusted_connection|integrated security)\s*=", clean)) >= 2
    if rule.rule_id == "cloud.aws_account":
        return "aws" in f"{context} {clean}".lower()
    if rule.rule_id == "cloud.aws_arn":
        return len(clean.split(":")) >= 6
    if rule.rule_id == "network.host_port":
        if re.match(r"(?i)^(?:[a-z]:\\|[a-z0-9_.-]+\.(?:py|ipynb|ps1|psm1|js|jsx|ts|tsx|html|htm|css|md|json|jsonl|yaml|yml|toml|xml|csv|txt|tsv|log|lock|template|headers|go|rs|java|cs|cpp|c|h|hpp|rb|php|sh|bat|cmd|png|jpg|jpeg|gif|svg|ico)):\d{1,6}$", lower):
            return False
        if re.match(r"^\d{1,2}:\d{2}(?::\d{2})?$", lower) or re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}$", lower):
            return False
        return bool(re.match(r"(?i)^(?:localhost|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+):\d{2,5}$", lower))
    if rule.rule_id == "network.ip_port":
        return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}$", lower))
    if rule.rule_id in {"internal.domain", "internal.named_host"}:
        if re.search(r"(?i)\.(?:png|jpg|jpeg|gif|svg|ico|dll|exe|py|ps1|js|ts|tsx|jsx|html|css|md|json|yaml|yml|toml|txt|tsv|headers|lock|template|log)$", lower):
            return False
        if lower == "twindows.ui.shell.internal":
            return False
    if rule.rule_id == "internal.named_host":
        if "_" in lower:
            return False
        if "." in lower:
            return True
        if not re.match(r"^(?:dev|stage|stg|prod|vpn|sso|jump|bastion)-[a-z0-9][a-z0-9-]{1,62}$", lower):
            return False
        return bool(re.search(r"(?i)\b(?:host|server|endpoint|url|ssh|vpn|bastion|jump|sso|ldap|domain|target)\b", context))
    if rule.rule_id.startswith("agent_fs."):
        return bool(re.search(r"(?i)(?:\.codex|\.claude|\.cursor|antigravity-cli|agent-transcripts|session_index\.jsonl|history\.jsonl|sessions|projects)", clean))
    return True


def _iter_text_fragments(value: Any, path: str = "value", include_strings: bool = False) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        if include_strings and value.strip():
            yield path, value
        return
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key.lower() in {
                "text",
                "content",
                "output",
                "stdout",
                "stderr",
                "aggregated_output",
                "formatted_output",
                "display",
                "message",
                "prompt",
                "response",
                "result",
                "experimental_content",
            }:
                yield from _iter_text_fragments(child, child_path, True)
            elif isinstance(child, (dict, list)):
                yield from _iter_text_fragments(child, child_path, False)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_text_fragments(child, f"{path}[{index}]", include_strings)


def _risk_labels(categories: Counter[str]) -> list[str]:
    labels = []
    if categories["credential_secret"]:
        labels.append("credential_exposure_candidate")
    if categories["internal_host"]:
        labels.append("internal_infra_reference")
    if categories["cloud_identity"]:
        labels.append("cloud_access_reference")
    if categories["network_target"]:
        labels.append("network_target_reference")
    if categories["source_control"]:
        labels.append("source_control_reference")
    if categories["agent_filesystem"]:
        labels.append("agent_filesystem_reference")
    return labels


def _fragment_count_key(role: str) -> str:
    return "tool_event_fragment_count" if role == "tool" else f"{role}_fragment_count"


def _record_indicator_match(session: dict[str, Any], rule: IndicatorRule, value: str, fragment_path: str, role: str) -> None:
    canonical_value = _canonical_indicator_value(rule, value)
    digest = sha256_text(canonical_value)
    indicator_key = f"{rule.rule_id}:{digest}"
    session["high_value_score"] += rule.weight
    session["category_counts"][rule.category] += 1
    session["rule_counts"][rule.rule_id] += 1
    indicator = session["indicators"].setdefault(
        indicator_key,
        {
            "category": rule.category,
            "rule_id": rule.rule_id,
            "severity_weight": rule.weight,
            "severity_bucket": _severity_bucket(rule.weight),
            "match_count": 0,
            "matched_value_length": len(canonical_value),
            "matched_value_sha256": digest,
            "paths": set(),
            "roles": set(),
        },
    )
    indicator["match_count"] += 1
    indicator["paths"].add(fragment_path)
    indicator["roles"].add(role)


def _serialized_indicators(session: dict[str, Any]) -> list[dict[str, Any]]:
    indicators = []
    for indicator in session["indicators"].values():
        indicators.append(
            {
                **{key: value for key, value in indicator.items() if key not in {"paths", "roles"}},
                "paths": sorted(indicator["paths"]),
                "roles": sorted(indicator["roles"]),
            }
        )
    indicators.sort(key=lambda item: (item["category"], item["rule_id"], item["matched_value_sha256"] or ""))
    return indicators


def _unique_category_counts(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(indicator.get("category") or "") for indicator in indicators)
    return [{"category": key, "count": value} for key, value in sorted(counts.items()) if key]


def _severity_bucket_counts(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(indicator.get("severity_bucket") or "") for indicator in indicators)
    return [
        {"severity_bucket": bucket, "count": counts[bucket]}
        for bucket in SENSITIVITY_SEVERITY_BUCKETS
        if counts[bucket]
    ]


def _unique_high_value_score(indicators: list[dict[str, Any]]) -> int:
    return sum(int(indicator.get("severity_weight") or 0) for indicator in indicators)


def _high_value_target_row(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": session["tool"],
        "session_id": session["session_id"],
        "session_title": session["session_title"],
        "primary_project_or_cwd": session["primary_project_or_cwd"],
        "high_value_score": session["high_value_score"],
        "unique_high_value_score": session.get("unique_high_value_score", 0),
        "indicator_count": session["indicator_count"],
        "unique_indicator_count": session.get("unique_indicator_count", session["indicator_count"]),
        "risk_labels": session["risk_labels"],
        "category_counts": session["category_counts"],
        "unique_category_counts": session.get("unique_category_counts", []),
        "severity_bucket_counts": session.get("severity_bucket_counts", []),
    }


def _high_value_aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    category_counts = Counter()
    unique_indicators: dict[str, dict[str, Any]] = {}
    for row in rows:
        for entry in row["category_counts"]:
            category_counts[entry["category"]] += entry["count"]
        for indicator in row.get("indicators", []):
            indicator_key = f"{indicator.get('rule_id')}:{indicator.get('matched_value_sha256')}"
            unique_indicator = unique_indicators.setdefault(
                indicator_key,
                {
                    "category": indicator.get("category"),
                    "rule_id": indicator.get("rule_id"),
                    "severity_weight": int(indicator.get("severity_weight") or 0),
                    "severity_bucket": indicator.get("severity_bucket"),
                    "match_count": 0,
                    "session_count": 0,
                },
            )
            unique_indicator["match_count"] += int(indicator.get("match_count") or 0)
            unique_indicator["session_count"] += 1
    unique_rows = list(unique_indicators.values())
    unique_category_counts = Counter(str(item.get("category") or "") for item in unique_rows)
    severity_bucket_counts = Counter(str(item.get("severity_bucket") or "") for item in unique_rows)
    severity_bucket_match_counts = Counter()
    severity_bucket_weighted_scores = Counter()
    unique_category_weighted_scores = Counter()
    for item in unique_rows:
        bucket = str(item.get("severity_bucket") or "")
        category = str(item.get("category") or "")
        weight = int(item.get("severity_weight") or 0)
        severity_bucket_match_counts[bucket] += int(item.get("match_count") or 0)
        severity_bucket_weighted_scores[bucket] += weight
        unique_category_weighted_scores[category] += weight
    total_unique_high_value_score = sum(int(item.get("severity_weight") or 0) for item in unique_rows)
    return {
        "session_count": len(rows),
        "nonzero_session_count": sum(1 for item in rows if item["high_value_score"] > 0),
        "total_indicator_count": sum(item["indicator_count"] for item in rows),
        "unique_indicator_count": len(unique_rows),
        "total_match_count": sum(sum(entry["count"] for entry in item["rule_counts"]) for item in rows),
        "total_high_value_score": sum(item["high_value_score"] for item in rows),
        "total_unique_high_value_score": total_unique_high_value_score,
        "category_counts": [{"category": key, "count": value} for key, value in sorted(category_counts.items())],
        "unique_category_counts": [{"category": key, "count": value} for key, value in sorted(unique_category_counts.items()) if key],
        "severity_bucket_counts": [
            {"severity_bucket": bucket, "count": severity_bucket_counts[bucket]}
            for bucket in SENSITIVITY_SEVERITY_BUCKETS
            if severity_bucket_counts[bucket]
        ],
        "severity_bucket_match_counts": [
            {"severity_bucket": bucket, "match_count": severity_bucket_match_counts[bucket]}
            for bucket in SENSITIVITY_SEVERITY_BUCKETS
            if severity_bucket_match_counts[bucket]
        ],
        "severity_bucket_weighted_scores": [
            {"severity_bucket": bucket, "weighted_score": severity_bucket_weighted_scores[bucket]}
            for bucket in SENSITIVITY_SEVERITY_BUCKETS
            if severity_bucket_weighted_scores[bucket]
        ],
        "unique_category_weighted_scores": [
            {"category": key, "weighted_score": value}
            for key, value in sorted(unique_category_weighted_scores.items())
            if key
        ],
        "top_sessions_by_high_value_score": [_high_value_target_row(item) for item in rows[:10] if item["high_value_score"] > 0],
        "credential_candidate_sessions": [_high_value_target_row(item) for item in rows if any(entry["category"] == "credential_secret" for entry in item["category_counts"])][:10],
        "internal_infrastructure_sessions": [_high_value_target_row(item) for item in rows if any(entry["category"] == "internal_host" for entry in item["category_counts"])][:10],
        "cloud_indicator_sessions": [_high_value_target_row(item) for item in rows if any(entry["category"] == "cloud_identity" for entry in item["category_counts"])][:10],
    }


def _cursor_high_value_rows(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        artifact_id = f"cursor.session_high_value.{index}"
        try:
            metadata, records, blob_count, malformed_blob_count, snapshot_opened = _cursor_store_records(path)
            if not records and not metadata:
                artifacts.append(
                    artifact(
                        artifact_id,
                        "Cursor",
                        path,
                        "Sessions / Chats",
                        "SQLite",
                        exists=True,
                        parsed=True,
                        metadata={
                            "size_bytes": path.stat().st_size,
                            "blob_count": blob_count,
                            "json_message_count": 0,
                            "malformed_blob_count": malformed_blob_count,
                            "metadata_present": False,
                            "snapshot_opened": snapshot_opened,
                        },
                    )
                )
                for error_index in range(malformed_blob_count):
                    errors.append({"path": str(path), "error": f"malformed Cursor blob {error_index + 1}"})
                continue
            session_id = _cursor_session_id(path, metadata)
            timestamp = _epoch_ms_to_utc(metadata.get("createdAt") or metadata.get("updatedAt"))
            session = {
                "tool": "Cursor",
                "session_id": session_id,
                "primary_source_path": str(path),
                "source_files": {str(path)},
                "first_timestamp": timestamp,
                "last_timestamp": timestamp,
                "project_or_cwd": set(),
                "session_title": str(metadata["name"]) if metadata.get("name") not in (None, "") else None,
                "line_count": len(records),
                "parse_error_count": malformed_blob_count,
                "scanned_fragment_count": 0,
                "scanned_text_bytes": 0,
                "request_fragment_count": 0,
                "response_fragment_count": 0,
                "tool_event_fragment_count": 0,
                "machine_context_fragment_count": 0,
                "high_value_score": 0,
                "category_counts": Counter(),
                "rule_counts": Counter(),
                "indicators": {},
            }
            for record in records:
                role = _session_role(record)
                for fragment_path, fragment in _iter_text_fragments(record):
                    session["scanned_fragment_count"] += 1
                    session["scanned_text_bytes"] += len(fragment.encode("utf-8"))
                    session[_fragment_count_key(role)] += 1
                    for rule in INDICATOR_RULES:
                        for match in rule.pattern.finditer(fragment):
                            value = match.group(0)
                            context_start = max(0, match.start() - 80)
                            context_end = min(len(fragment), match.end() + 80)
                            if not _valid_indicator_match(rule, value, fragment[context_start:context_end]):
                                continue
                            _record_indicator_match(session, rule, value, fragment_path, role)
            indicators = _serialized_indicators(session)
            rows.append(
                {
                    "tool": session["tool"],
                    "session_id": session["session_id"],
                    "primary_source_path": session["primary_source_path"],
                    "source_file_count": len(session["source_files"]),
                    "first_timestamp": session["first_timestamp"],
                    "last_timestamp": session["last_timestamp"],
                    "primary_project_or_cwd": None,
                    "project_or_cwd_count": 0,
                    "title_present": session["session_title"] is not None,
                    "session_title": session["session_title"],
                    "title_length": len(session["session_title"]) if session["session_title"] else None,
                    "title_sha256": sha256_text(session["session_title"]),
                    "title_updated_at": timestamp,
                    "line_count": session["line_count"],
                    "parse_error_count": session["parse_error_count"],
                    "scanned_fragment_count": session["scanned_fragment_count"],
                    "scanned_text_bytes": session["scanned_text_bytes"],
                    "request_fragment_count": session["request_fragment_count"],
                    "response_fragment_count": session["response_fragment_count"],
                    "tool_event_fragment_count": session["tool_event_fragment_count"],
                    "machine_context_fragment_count": session["machine_context_fragment_count"],
                    "high_value_score": session["high_value_score"],
                    "unique_high_value_score": _unique_high_value_score(indicators),
                    "risk_labels": _risk_labels(session["category_counts"]),
                    "category_counts": [{"category": key, "count": value} for key, value in sorted(session["category_counts"].items())],
                    "rule_counts": [{"rule_id": key, "count": value} for key, value in sorted(session["rule_counts"].items())],
                    "indicator_count": len(indicators),
                    "unique_indicator_count": len(indicators),
                    "unique_category_counts": _unique_category_counts(indicators),
                    "severity_bucket_counts": _severity_bucket_counts(indicators),
                    "indicators": indicators,
                }
            )
            artifacts.append(
                artifact(
                    artifact_id,
                    "Cursor",
                    path,
                    "Sessions / Chats",
                    "SQLite",
                    exists=True,
                    parsed=True,
                    metadata={
                        "size_bytes": path.stat().st_size,
                        "blob_count": blob_count,
                        "json_message_count": len(records),
                        "malformed_blob_count": malformed_blob_count,
                        "metadata_present": bool(metadata),
                        "snapshot_opened": snapshot_opened,
                    },
                )
            )
            for error_index in range(malformed_blob_count):
                errors.append({"path": str(path), "error": f"malformed Cursor blob {error_index + 1}"})
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(path), "error": str(exc)})
            artifacts.append(artifact(artifact_id, "Cursor", path, "Sessions / Chats", "SQLite", exists=True, parsed=False, parse_error=str(exc)))
    rows.sort(key=lambda item: (item["high_value_score"], item["indicator_count"]), reverse=True)
    return rows, artifacts, errors


def _cursor_agent_transcript_high_value_rows(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        artifact_id = f"cursor.agent_transcript_high_value.{index}"
        parse_errors = 0
        session = {
            "tool": "Cursor",
            "session_id": path.stem,
            "primary_source_path": str(path),
            "source_files": {str(path)},
            "first_timestamp": None,
            "last_timestamp": None,
            "project_or_cwd": set(),
            "session_title": None,
            "line_count": 0,
            "parse_error_count": 0,
            "scanned_fragment_count": 0,
            "scanned_text_bytes": 0,
            "request_fragment_count": 0,
            "response_fragment_count": 0,
            "tool_event_fragment_count": 0,
            "machine_context_fragment_count": 0,
            "high_value_score": 0,
            "category_counts": Counter(),
            "rule_counts": Counter(),
            "indicators": {},
        }
        project = _cursor_project_from_agent_transcript(path)
        if project:
            session["project_or_cwd"].add(project)
        try:
            for line_number, record, error in iter_jsonl(path):
                if error:
                    parse_errors += 1
                    errors.append({"path": str(path), "error": f"line {line_number}: {error}"})
                    continue
                record = record or {}
                session["line_count"] += 1
                timestamp = first_value(record, ("timestamp", "created_at", "createdAt", "updated_at", "updatedAt", "ts"))
                if timestamp:
                    text = str(timestamp)
                    session["first_timestamp"] = text if session["first_timestamp"] is None or text < session["first_timestamp"] else session["first_timestamp"]
                    session["last_timestamp"] = text if session["last_timestamp"] is None or text > session["last_timestamp"] else session["last_timestamp"]
                record_project = first_value(record, ("cwd", "project", "project_path", "projectPath", "workspace", "workspace_path"))
                if record_project:
                    session["project_or_cwd"].add(str(record_project))
                title = first_value(record, ("title", "session_title", "sessionTitle"), scalar_only=True)
                if title:
                    session["session_title"] = str(title)
                role = _session_role(record)
                for fragment_path, fragment in _iter_text_fragments(record):
                    session["scanned_fragment_count"] += 1
                    session["scanned_text_bytes"] += len(fragment.encode("utf-8"))
                    session[_fragment_count_key(role)] += 1
                    for rule in INDICATOR_RULES:
                        for match in rule.pattern.finditer(fragment):
                            value = match.group(0)
                            context_start = max(0, match.start() - 80)
                            context_end = min(len(fragment), match.end() + 80)
                            if not _valid_indicator_match(rule, value, fragment[context_start:context_end]):
                                continue
                            _record_indicator_match(session, rule, value, fragment_path, role)
            session["parse_error_count"] = parse_errors
            indicators = _serialized_indicators(session)
            rows.append(
                {
                    "tool": session["tool"],
                    "session_id": session["session_id"],
                    "primary_source_path": session["primary_source_path"],
                    "source_file_count": len(session["source_files"]),
                    "first_timestamp": session["first_timestamp"],
                    "last_timestamp": session["last_timestamp"],
                    "primary_project_or_cwd": sorted(session["project_or_cwd"])[0] if session["project_or_cwd"] else None,
                    "project_or_cwd_count": len(session["project_or_cwd"]),
                    "title_present": session["session_title"] is not None,
                    "session_title": session["session_title"],
                    "title_length": len(session["session_title"]) if session["session_title"] else None,
                    "title_sha256": sha256_text(session["session_title"]),
                    "title_updated_at": None,
                    "line_count": session["line_count"],
                    "parse_error_count": session["parse_error_count"],
                    "scanned_fragment_count": session["scanned_fragment_count"],
                    "scanned_text_bytes": session["scanned_text_bytes"],
                    "request_fragment_count": session["request_fragment_count"],
                    "response_fragment_count": session["response_fragment_count"],
                    "tool_event_fragment_count": session["tool_event_fragment_count"],
                    "machine_context_fragment_count": session["machine_context_fragment_count"],
                    "high_value_score": session["high_value_score"],
                    "unique_high_value_score": _unique_high_value_score(indicators),
                    "risk_labels": _risk_labels(session["category_counts"]),
                    "category_counts": [{"category": key, "count": value} for key, value in sorted(session["category_counts"].items())],
                    "rule_counts": [{"rule_id": key, "count": value} for key, value in sorted(session["rule_counts"].items())],
                    "indicator_count": len(indicators),
                    "unique_indicator_count": len(indicators),
                    "unique_category_counts": _unique_category_counts(indicators),
                    "severity_bucket_counts": _severity_bucket_counts(indicators),
                    "indicators": indicators,
                }
            )
            artifacts.append(
                artifact(
                    artifact_id,
                    "Cursor",
                    path,
                    "Sessions / Chats",
                    "JSONL",
                    exists=True,
                    parsed=True,
                    metadata={"size_bytes": path.stat().st_size, "parse_error_count": parse_errors},
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": str(path), "error": str(exc)})
            artifacts.append(artifact(artifact_id, "Cursor", path, "Sessions / Chats", "JSONL", exists=True, parsed=False, parse_error=str(exc)))
    rows.sort(key=lambda item: (item["high_value_score"], item["indicator_count"]), reverse=True)
    return rows, artifacts, errors


def run_session_high_value(
    *,
    run_id: str,
    output_directory: str | Path | None = None,
    package_root: str | Path | None = None,
    target_root: str | Path | None = None,
    target_tool: str = "Auto",
    live_root: bool = False,
    codex_root: str | Path | None = None,
    claude_root: str | Path | None = None,
    claude_home_config: str | Path | None = None,
    cursor_root: str | Path | None = None,
    antigravity_cli_root: str | Path | None = None,
    session_sources: Iterable[SessionSource] | None = None,
    input_root: str | Path | None = None,
) -> dict[str, Any]:
    grouped_sources: dict[str, dict[str, list[Path]]] | None = None
    if session_sources is not None:
        if input_root is None:
            raise ValueError("input_root is required with session_sources")
        grouped_sources = _session_source_paths(session_sources)
        roots = _arbitrary_session_roots(input_root)
    else:
        roots = resolve_input_roots(
            package_root=package_root,
            target_root=target_root,
            target_tool=target_tool,
            live_root=live_root,
            codex_root=codex_root,
            claude_root=claude_root,
            claude_home_config=claude_home_config,
            cursor_root=cursor_root,
            antigravity_cli_root=antigravity_cli_root,
        )
    tools: list[dict[str, Any]] = []
    for detail_tool, root, paths in (
        ("Codex", roots.target_root if grouped_sources and grouped_sources.get("Codex") else roots.codex_root,
         _source_paths(grouped_sources, "Codex", format_name="JSONL") if grouped_sources is not None else _jsonl_paths(roots.codex_root, ("session_index.jsonl", "history.jsonl", "sessions", "archived_sessions"))),
        ("Claude Code", roots.target_root if grouped_sources and grouped_sources.get("Claude Code") else roots.claude_root,
         _source_paths(grouped_sources, "Claude Code", format_name="JSONL") if grouped_sources is not None else _jsonl_paths(roots.claude_root, ("history.jsonl", "projects"))),
        (
            "Antigravity CLI",
            roots.target_root if grouped_sources and grouped_sources.get("Antigravity CLI") else (roots.antigravity_cli_root if roots.antigravity_cli_root and roots.antigravity_cli_root.exists() else None),
            _source_paths(grouped_sources, "Antigravity CLI", format_name="JSONL") if grouped_sources is not None else _antigravity_cli_transcript_paths(roots.antigravity_cli_root),
        ),
    ):
        if not root:
            continue
        tool = tool_result(detail_tool, root)
        session_map: dict[str, dict[str, Any]] = {}
        for path in paths:
            artifact_id = f"{detail_tool.lower().replace(' ', '_')}.session_high_value.{len(tool['artifacts'])}"
            parse_errors = 0
            source_session_id = _codex_rollout_session_id(path) if detail_tool == "Codex" else None
            try:
                for line_number, record, error in iter_jsonl(path):
                    if error:
                        parse_errors += 1
                        add_parse_error(tool, path, f"line {line_number}: {error}")
                        continue
                    record = record or {}
                    source_session_id = _codex_envelope_session_id(record) or source_session_id
                    session_id = _session_id_for_record(detail_tool, path, record, source_session_id)
                    session = session_map.setdefault(
                        session_id,
                        {
                            "tool": detail_tool,
                            "session_id": session_id,
                            "primary_source_path": str(path),
                            "source_files": set(),
                            "first_timestamp": None,
                            "last_timestamp": None,
                            "project_or_cwd": set(),
                            "session_title": None,
                            "line_count": 0,
                            "parse_error_count": 0,
                            "scanned_fragment_count": 0,
                            "scanned_text_bytes": 0,
                            "request_fragment_count": 0,
                            "response_fragment_count": 0,
                            "tool_event_fragment_count": 0,
                            "machine_context_fragment_count": 0,
                            "high_value_score": 0,
                            "category_counts": Counter(),
                            "rule_counts": Counter(),
                            "indicators": {},
                        },
                    )
                    session["source_files"].add(str(path))
                    session["line_count"] += 1
                    timestamp = first_value(record, ("timestamp", "created_at", "createdAt", "updated_at", "updatedAt", "ts"))
                    if timestamp:
                        text = str(timestamp)
                        session["first_timestamp"] = text if session["first_timestamp"] is None or text < session["first_timestamp"] else session["first_timestamp"]
                        session["last_timestamp"] = text if session["last_timestamp"] is None or text > session["last_timestamp"] else session["last_timestamp"]
                    project = first_value(
                        record,
                        (
                            "cwd",
                            "Cwd",
                            "project",
                            "project_path",
                            "projectPath",
                            "workspace",
                            "workspace_path",
                            "workspace_uris",
                            "DirectoryPath",
                            "AbsolutePath",
                            "TargetFile",
                        ),
                    )
                    if project:
                        session["project_or_cwd"].add(str(project))
                    title = first_value(record, ("title", "thread_name", "session_title", "sessionTitle"), scalar_only=True)
                    if title:
                        session["session_title"] = str(title)
                    semantic_record, role = _normalized_session_record(detail_tool, record)
                    if role is None:
                        continue
                    for fragment_path, fragment in _iter_text_fragments(semantic_record):
                        session["scanned_fragment_count"] += 1
                        session["scanned_text_bytes"] += len(fragment.encode("utf-8"))
                        session[_fragment_count_key(role)] += 1
                        for rule in INDICATOR_RULES:
                            for match in rule.pattern.finditer(fragment):
                                value = match.group(0)
                                context_start = max(0, match.start() - 80)
                                context_end = min(len(fragment), match.end() + 80)
                                if not _valid_indicator_match(rule, value, fragment[context_start:context_end]):
                                    continue
                                _record_indicator_match(session, rule, value, fragment_path, role)
                tool["artifacts"].append(artifact(artifact_id, detail_tool, path, "Sessions / Chats", "JSONL", exists=True, parsed=True, metadata={"size_bytes": path.stat().st_size, "parse_error_count": parse_errors}))
                if parse_errors and session_map:
                    affected_sessions = [session for session in session_map.values() if str(path) in session["source_files"]]
                    if not affected_sessions:
                        affected_sessions = list(session_map.values())
                    for session in affected_sessions:
                        session["parse_error_count"] += parse_errors
            except Exception as exc:  # noqa: BLE001
                tool["artifacts"].append(artifact(artifact_id, detail_tool, path, "Sessions / Chats", "JSONL", exists=True, parsed=False, parse_error=str(exc)))
                add_parse_error(tool, path, str(exc))
        rows = []
        for session in session_map.values():
            indicators = _serialized_indicators(session)
            rows.append(
                {
                    "tool": session["tool"],
                    "session_id": session["session_id"],
                    "primary_source_path": session["primary_source_path"],
                    "source_file_count": len(session["source_files"]),
                    "first_timestamp": session["first_timestamp"],
                    "last_timestamp": session["last_timestamp"],
                    "primary_project_or_cwd": sorted(session["project_or_cwd"])[0] if session["project_or_cwd"] else None,
                    "project_or_cwd_count": len(session["project_or_cwd"]),
                    "title_present": session["session_title"] is not None,
                    "session_title": session["session_title"],
                    "title_length": len(session["session_title"]) if session["session_title"] else None,
                    "title_sha256": sha256_text(session["session_title"]),
                    "title_updated_at": None,
                    "line_count": session["line_count"],
                    "parse_error_count": session["parse_error_count"],
                    "scanned_fragment_count": session["scanned_fragment_count"],
                    "scanned_text_bytes": session["scanned_text_bytes"],
                    "request_fragment_count": session["request_fragment_count"],
                    "response_fragment_count": session["response_fragment_count"],
                    "tool_event_fragment_count": session["tool_event_fragment_count"],
                    "machine_context_fragment_count": session["machine_context_fragment_count"],
                    "high_value_score": session["high_value_score"],
                    "unique_high_value_score": _unique_high_value_score(indicators),
                    "risk_labels": _risk_labels(session["category_counts"]),
                    "category_counts": [{"category": key, "count": value} for key, value in sorted(session["category_counts"].items())],
                    "rule_counts": [{"rule_id": key, "count": value} for key, value in sorted(session["rule_counts"].items())],
                    "indicator_count": len(indicators),
                    "unique_indicator_count": len(indicators),
                    "unique_category_counts": _unique_category_counts(indicators),
                    "severity_bucket_counts": _severity_bucket_counts(indicators),
                    "indicators": indicators,
                }
            )
        rows.sort(key=lambda item: (item["high_value_score"], item["indicator_count"]), reverse=True)
        aggregate = _high_value_aggregate(rows)
        if detail_tool == "Antigravity CLI" and grouped_sources is not None:
            for index, sqlite_path in enumerate(_source_paths(grouped_sources, "Antigravity CLI", format_name="SQLite")):
                try:
                    tool["artifacts"].append(artifact(f"antigravity_cli.session_high_value.sqlite.{index}", detail_tool, sqlite_path, "Sessions / Chats", "SQLite", exists=True, parsed=True, metadata=_sqlite_schema_counts(sqlite_path)))
                except Exception as exc:  # noqa: BLE001
                    add_parse_error(tool, sqlite_path, str(exc))
                    tool["artifacts"].append(artifact(f"antigravity_cli.session_high_value.sqlite.{index}", detail_tool, sqlite_path, "Sessions / Chats", "SQLite", exists=True, parsed=False, parse_error=str(exc)))
        tool["findings"].append(finding(detail_tool, f"{detail_tool.lower().replace(' ', '_')}.session_high_value", "session_high_value_indicators", f"{detail_tool}.sessions", {"aggregate": aggregate, "sessions": rows}))
        tools.append(tool)
    cursor_root = roots.target_root if grouped_sources and grouped_sources.get("Cursor") else roots.cursor_root
    if cursor_root and cursor_root.exists():
        tool = tool_result("Cursor", cursor_root)
        chat_paths = _source_paths(grouped_sources, "Cursor", format_name="SQLite") if grouped_sources is not None else _cursor_chat_db_paths(cursor_root)
        transcript_paths = _source_paths(grouped_sources, "Cursor", format_name="JSONL") if grouped_sources is not None else _cursor_agent_transcript_paths(cursor_root)
        chat_rows, chat_artifacts, chat_errors = _cursor_high_value_rows(chat_paths)
        transcript_rows, transcript_artifacts, transcript_errors = _cursor_agent_transcript_high_value_rows(transcript_paths)
        rows = sorted(chat_rows + transcript_rows, key=lambda item: (item["high_value_score"], item["indicator_count"]), reverse=True)
        if not chat_paths and not transcript_paths:
            tool["artifacts"].append(artifact("cursor.session_high_value", "Cursor", cursor_root / "chats", "Sessions / Chats", "SQLite/JSONL", exists=False, parsed=False))
        else:
            tool["artifacts"].extend(chat_artifacts)
            tool["artifacts"].extend(transcript_artifacts)
        tool["parse_errors"].extend(chat_errors)
        tool["parse_errors"].extend(transcript_errors)
        aggregate = _high_value_aggregate(rows)
        tool["findings"].append(
            finding("Cursor", "cursor.session_high_value", "session_high_value_indicators", "Cursor.sessions", {"aggregate": aggregate, "sessions": rows})
        )
        tools.append(tool)
    summary = summarize_tools(tools)
    aggregates = [item["findings"][0]["value"]["aggregate"] for item in tools if item["findings"]]
    summary.update(
        {
            "rule_count": len(INDICATOR_RULES),
            "total_session_count": sum(item["session_count"] for item in aggregates),
            "total_nonzero_session_count": sum(item["nonzero_session_count"] for item in aggregates),
            "total_indicator_count": sum(item["total_indicator_count"] for item in aggregates),
            "total_unique_indicator_count": sum(item.get("unique_indicator_count", item["total_indicator_count"]) for item in aggregates),
            "total_match_count": sum(item["total_match_count"] for item in aggregates),
            "total_high_value_score": sum(item["total_high_value_score"] for item in aggregates),
            "total_unique_high_value_score": sum(item.get("total_unique_high_value_score", item["total_high_value_score"]) for item in aggregates),
        }
    )
    result = build_envelope(
        run_id=run_id,
        parser_name="session_high_value",
        output_kind="session_high_value",
        roots=roots,
        content_policy={
            "raw_message_text_included": False,
            "raw_credential_values_included": False,
            "semantic_parsing_included": True,
            "sensitivity_scoring_included": True,
            "config_values_included": False,
            "session_titles_included": True,
        },
        tools=tools,
        summary=summary,
    )
    return write_output(result, output_directory, f"{safe_name(run_id)}_Session_High_Value_Parse", _summary_lines("Blacklight session high-value indicator parse", result))


RESPONSE_STATUS_EXPLANATIONS = {
    "present": "Assistant responses were captured.",
    "absent_index_only": "Only an index/title record was present; session detail was not collected or parsed.",
    "absent_turn_aborted": "A turn was aborted before an assistant response was captured.",
    "absent_no_assistant_records": "Parsed session records existed, but no assistant records were present.",
}


_AGGREGATE_SESSION_FILENAMES = {
    "history.jsonl",
    "session_index.jsonl",
    "transcript.jsonl",
    "transcript_full.jsonl",
}


def _is_aggregate_session_file(path: str | Path) -> bool:
    return Path(path).name.lower() in _AGGREGATE_SESSION_FILENAMES


def _is_subagent_source_path(path: str | Path) -> bool:
    return "subagents" in Path(path).parts


def _best_session_source_from_paths(session_id: str, paths: list[str]) -> str | None:
    if not paths:
        return None
    preferred_paths = [path for path in paths if not _is_subagent_source_path(path)] or list(paths)
    for path in preferred_paths:
        candidate = Path(path)
        if candidate.suffix.lower() == ".jsonl" and candidate.stem == session_id:
            return str(candidate.resolve())
    for path in preferred_paths:
        candidate = Path(path)
        if candidate.suffix.lower() == ".jsonl" and candidate.parent.name == session_id:
            return str(candidate.resolve())
    non_aggregate_jsonl = [
        path
        for path in preferred_paths
        if Path(path).suffix.lower() == ".jsonl" and not _is_aggregate_session_file(path)
    ]
    if len(non_aggregate_jsonl) == 1:
        return str(Path(non_aggregate_jsonl[0]).resolve())
    for path in non_aggregate_jsonl:
        if session_id and session_id in path:
            return str(Path(path).resolve())
    if non_aggregate_jsonl:
        return str(Path(sorted(non_aggregate_jsonl)[0]).resolve())
    jsonl_paths = [path for path in paths if Path(path).suffix.lower() == ".jsonl"]
    if jsonl_paths:
        return str(Path(sorted(jsonl_paths)[0]).resolve())
    return str(Path(paths[0]).resolve())


def _lookup_per_session_source_path(
    session_id: str | None,
    source_paths: Iterable[str] | None,
    primary_source_path: str | None,
) -> str | None:
    session_id_text = str(session_id or "").strip()
    paths = [str(path) for path in (source_paths or []) if path]
    if primary_source_path and str(primary_source_path) not in paths:
        paths.append(str(primary_source_path))
    if not paths:
        return None

    if session_id_text:
        resolved = _best_session_source_from_paths(session_id_text, paths)
        if resolved and not _is_aggregate_session_file(resolved):
            return resolved

    if session_id_text:
        return _best_session_source_from_paths(session_id_text, paths)
    return str(Path(paths[0]).resolve())


def _normalized_tool_name(tool_name: str) -> str:
    if tool_name == "Codex":
        return "codex"
    if tool_name == "Claude Code":
        return "claude"
    if tool_name == "Cursor":
        return "cursor"
    if tool_name == "Antigravity CLI":
        return "antigravity_cli"
    return safe_name(tool_name).lower()


def _session_targeting_rows(session_detail_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for tool in session_detail_result.get("tools", []):
        tool_name = str(tool.get("tool_name") or "")
        for item in tool.get("findings", []):
            if item.get("finding_type") != "session_volume_structure":
                continue
            value = item.get("value")
            if not isinstance(value, dict):
                continue
            sessions = value.get("sessions", [])
            if not isinstance(sessions, list):
                continue
            for session in sessions:
                if not isinstance(session, dict):
                    continue
                status = str(session.get("response_capture_status") or "absent_no_assistant_records")
                source_paths = session.get("source_paths")
                if not isinstance(source_paths, list):
                    source_paths = []
                primary_source_path = session.get("primary_source_path")
                session_source_path = _lookup_per_session_source_path(
                    str(session.get("session_id") or ""),
                    source_paths,
                    str(primary_source_path) if primary_source_path else None,
                )
                rows.append(
                    {
                        "rank": 0,
                        "session_id": session.get("session_id"),
                        "session_title": session.get("session_title"),
                        "tool": _normalized_tool_name(tool_name or str(session.get("tool") or "")),
                        "project_worktree_path": session.get("primary_project_or_cwd"),
                        "request_count": int(session.get("request_message_count") or 0),
                        "response_count": int(session.get("response_message_count") or 0),
                        "captured_request_bytes": int(session.get("total_request_bytes") or 0),
                        "captured_response_bytes": int(session.get("total_response_bytes") or 0),
                        "captured_tool_event_bytes": int(session.get("total_tool_event_bytes") or 0),
                        "captured_total_bytes": int(session.get("total_extracted_content_bytes") or 0),
                        "raw_source_bytes": int(session.get("raw_jsonl_bytes") or 0),
                        "last_activity": session.get("last_timestamp"),
                        "response_status": status,
                        "response_status_explanation": RESPONSE_STATUS_EXPLANATIONS.get(status, "Response capture status was not recognized."),
                        "primary_source_path": primary_source_path,
                        "session_source_path": session_source_path,
                        "parse_error_count": int(session.get("parse_error_count") or 0),
                    }
                )
    rows.sort(
        key=lambda item: (
            item["captured_total_bytes"],
            item["request_count"],
            item["response_count"],
            str(item["last_activity"] or ""),
            str(item["session_title"] or ""),
            str(item["session_id"] or ""),
        ),
        reverse=True,
    )
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
    return rows


def _status_count_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(row["response_status"]) for row in rows)
    return [
        {
            "response_status": status,
            "response_status_explanation": RESPONSE_STATUS_EXPLANATIONS.get(status, "Response capture status was not recognized."),
            "session_count": count,
        }
        for status, count in sorted(counts.items())
    ]


def _session_targeting_aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tools = Counter(str(row["tool"]) for row in rows)
    projects = Counter(str(row["project_worktree_path"]) for row in rows if row.get("project_worktree_path"))
    status_rows = _status_count_rows(rows)
    return {
        "session_count": len(rows),
        "total_request_count": sum(row["request_count"] for row in rows),
        "total_response_count": sum(row["response_count"] for row in rows),
        "total_captured_request_bytes": sum(row["captured_request_bytes"] for row in rows),
        "total_captured_response_bytes": sum(row["captured_response_bytes"] for row in rows),
        "total_captured_tool_event_bytes": sum(row["captured_tool_event_bytes"] for row in rows),
        "total_captured_bytes": sum(row["captured_total_bytes"] for row in rows),
        "tool_counts": [{"tool": key, "session_count": value} for key, value in sorted(tools.items())],
        "response_status_counts": status_rows,
        "top_project_worktree_paths": [
            {"project_worktree_path": key, "session_count": value}
            for key, value in projects.most_common(10)
        ],
        "top_ranked_sessions": rows[:10],
    }


def build_session_targeting_report(combined_analysis: dict[str, Any]) -> dict[str, Any]:
    session_detail = combined_analysis.get("session_detail")
    if not isinstance(session_detail, dict):
        raise ValueError("combined analysis must include a session_detail result")
    rows = _session_targeting_rows(session_detail)
    aggregate = _session_targeting_aggregate(rows)
    summary = {
        "session_count": aggregate["session_count"],
        "total_request_count": aggregate["total_request_count"],
        "total_response_count": aggregate["total_response_count"],
        "total_captured_bytes": aggregate["total_captured_bytes"],
        "response_status_counts": aggregate["response_status_counts"],
        "source_parsers": ["session_detail"],
    }
    return {
        "run_id": session_detail["run_id"],
        "collected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "parser": {
            **session_detail["parser"],
            "name": "session_targeting_report",
            "output_kind": "session_targeting_report",
        },
        "host": session_detail["host"],
        "os": session_detail["os"],
        "current_user": session_detail["current_user"],
        "content_policy": {
            "raw_message_text_included": False,
            "raw_credential_values_included": False,
            "semantic_parsing_included": False,
            "sensitivity_scoring_included": False,
            "config_values_included": False,
            "session_titles_included": bool(session_detail.get("content_policy", {}).get("session_titles_included")),
            "derived_from_parser_outputs": True,
        },
        "tools": [
            tool_result("Session Targeting Report", None)
            | {
                "findings": [
                    finding(
                        "Session Targeting Report",
                        "session_targeting_report",
                        "session_targeting_table",
                        "sessions.ranked",
                        {"aggregate": aggregate, "sessions": rows},
                    )
                ]
            }
        ],
        "summary": summary,
    }


def _write_session_targeting_outputs(result: dict[str, Any], output_directory: str | Path | None, base_name: str, text_lines: list[str]) -> dict[str, Any]:
    if output_directory is None:
        return result
    output_path = Path(output_directory).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / f"{base_name}.json"
    text_path = output_path / f"{base_name}.txt"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    text_path.write_text("\n".join(text_lines) + "\n", encoding="utf-8")
    result["_output"] = {
        "json": str(json_path),
        "text": str(text_path),
    }
    return result


def _session_targeting_summary_lines(result: dict[str, Any]) -> list[str]:
    lines = _summary_lines("Blacklight session targeting report", result)
    value = result["tools"][0]["findings"][0]["value"]
    aggregate = value["aggregate"]
    lines.extend(["", "Response status counts:"])
    for row in aggregate["response_status_counts"]:
        lines.append(f"- {row['response_status']}: {row['session_count']} ({row['response_status_explanation']})")
    lines.extend(["", "Top sessions:"])
    for row in value["sessions"][:10]:
        title = row["session_title"] or "(untitled)"
        project = row["project_worktree_path"] or "(no project path)"
        lines.append(
            f"- #{row['rank']} {row['tool']} {title} [{row['session_id']}]: "
            f"{row['request_count']} req/{row['response_count']} resp, "
            f"{row['captured_total_bytes']} bytes, {row['response_status']}, {project}"
        )
        session_source_path = row.get("session_source_path")
        if session_source_path:
            source_path = Path(str(session_source_path))
            label = "source_jsonl" if source_path.suffix.lower() == ".jsonl" else "source"
            lines.append(f"  {label}: {session_source_path}")
    return lines


def run_session_targeting_report(
    *,
    run_id: str,
    output_directory: str | Path | None = None,
    package_root: str | Path | None = None,
    target_root: str | Path | None = None,
    target_tool: str = "Auto",
    live_root: bool = False,
    codex_root: str | Path | None = None,
    claude_root: str | Path | None = None,
    claude_home_config: str | Path | None = None,
    cursor_root: str | Path | None = None,
    antigravity_cli_root: str | Path | None = None,
) -> dict[str, Any]:
    session_detail = run_session_detail(
        run_id=run_id,
        output_directory=None,
        package_root=package_root,
        target_root=target_root,
        target_tool=target_tool,
        live_root=live_root,
        codex_root=codex_root,
        claude_root=claude_root,
        claude_home_config=claude_home_config,
        cursor_root=cursor_root,
        antigravity_cli_root=antigravity_cli_root,
    )
    result = build_session_targeting_report({"session_detail": session_detail})
    return _write_session_targeting_outputs(
        result,
        output_directory,
        f"{safe_name(run_id)}_Session_Targeting_Report",
        _session_targeting_summary_lines(result),
    )


def _summary_lines(title: str, result: dict[str, Any]) -> list[str]:
    summary = result["summary"]
    lines = [
        title,
        f"Run ID: {result['run_id']}",
        f"Collected UTC: {result['collected_at_utc']}",
        f"Host: {result['host']}",
        f"OS: {result['os']}",
        f"Current user: {result['current_user']}",
        "",
        "Summary:",
    ]
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")
    return lines
