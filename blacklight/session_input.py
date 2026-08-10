from __future__ import annotations

import fnmatch
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SUPPORTED_TOOLS = ("codex", "claude", "cursor", "antigravity_cli")
_TOOL_NAMES = {
    "codex": "Codex",
    "claude": "Claude Code",
    "claude code": "Claude Code",
    "cursor": "Cursor",
    "antigravity": "Antigravity CLI",
    "antigravity cli": "Antigravity CLI",
    "antigravity_cli": "Antigravity CLI",
}


@dataclass(frozen=True)
class SessionSource:
    path: Path
    detected_tool: str
    artifact_type: str
    format: str
    confidence: str
    detection_reason: str
    size_bytes: int
    modified_time: str
    parser_name: str
    original_name: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["path"] = str(self.path)
        return value


@dataclass(frozen=True)
class SessionInputIssue:
    path: Path
    status: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"path": str(self.path), "status": self.status, "reason": self.reason}


@dataclass
class SessionInputDiscovery:
    input_path: Path
    files_examined: int = 0
    sources: list[SessionSource] = field(default_factory=list)
    issues: list[SessionInputIssue] = field(default_factory=list)
    skipped_links: int = 0
    limit_reached: bool = False

    @property
    def ambiguous_count(self) -> int:
        return sum(issue.status == "ambiguous" for issue in self.issues)

    @property
    def unsupported_count(self) -> int:
        return sum(issue.status == "unsupported" for issue in self.issues)

    @property
    def parse_failed_count(self) -> int:
        return sum(issue.status == "parse_failed" for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_path": str(self.input_path),
            "files_examined": self.files_examined,
            "supported_artifact_count": len(self.sources),
            "ambiguous_count": self.ambiguous_count,
            "unsupported_count": self.unsupported_count,
            "parse_failed_count": self.parse_failed_count,
            "skipped_link_count": self.skipped_links,
            "file_limit_reached": self.limit_reached,
            "sources": [source.to_dict() for source in self.sources],
            "issues": [issue.to_dict() for issue in self.issues],
        }


def normalize_tool_hint(value: str | None) -> str | None:
    if value in (None, "", "auto"):
        return None
    normalized = str(value).strip().lower().replace("-", " ")
    tool = _TOOL_NAMES.get(normalized)
    if tool is None:
        choices = ", ".join(SUPPORTED_TOOLS)
        raise ValueError(f"Unknown session tool hint '{value}'. Choose one of: {choices}.")
    return tool


def _modified_time(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")


def _source(
    path: Path,
    tool: str,
    artifact_type: str,
    format_name: str,
    confidence: str,
    reason: str,
    parser_name: str,
) -> SessionSource:
    stat = path.stat()
    return SessionSource(
        path=path.resolve(),
        detected_tool=tool,
        artifact_type=artifact_type,
        format=format_name,
        confidence=confidence,
        detection_reason=reason,
        size_bytes=stat.st_size,
        modified_time=_modified_time(path),
        parser_name=parser_name,
        original_name=path.name,
    )


def _path_tool(path: Path) -> tuple[str | None, str | None]:
    text = "/" + path.as_posix().lower().strip("/") + "/"
    name = path.name.lower()
    if "/.codex/" in text or "codex" in name:
        return "Codex", "recognized Codex filename or surrounding path"
    if "/.claude/" in text or "claude" in name:
        return "Claude Code", "recognized Claude Code filename or surrounding path"
    if "/.cursor/" in text or "/agent-transcripts/" in text or "cursor" in name:
        return "Cursor", "recognized Cursor filename or surrounding path"
    if "/antigravity-cli/" in text or "/.gemini/" in text or "antigravity" in name:
        return "Antigravity CLI", "recognized Antigravity CLI filename or surrounding path"
    if name in {"transcript_full.jsonl", "transcript.jsonl"}:
        return "Antigravity CLI", "recognized Antigravity CLI transcript filename"
    return None, None


def _probe_jsonl(path: Path) -> tuple[list[dict[str, Any]], int, str | None]:
    records: list[dict[str, Any]] = []
    malformed = 0
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= 50:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if isinstance(value, dict):
                    records.append(value)
    except OSError as exc:
        return [], 0, str(exc)
    return records, malformed, None


def _strong_jsonl_tool(records: Iterable[dict[str, Any]]) -> tuple[str | None, str | None]:
    records = list(records)
    keys = {str(key) for record in records for key in record}
    event_types = {str(record.get("type", "")).lower() for record in records}
    sources = {str(record.get("source", "")).lower() for record in records}
    if event_types & {"session_meta", "event_msg", "response_item", "turn_context"}:
        return "Codex", "Codex rollout record schema"
    if any({"id", "thread_name", "updated_at"}.issubset(record) for record in records):
        return "Codex", "Codex session index schema"
    if "session_id" in keys or any("payload" in record and isinstance(record.get("payload"), dict) and record.get("type") == "session_meta" for record in records):
        return "Codex", "Codex session record schema"
    if keys & {"sessionId", "parentUuid", "isSidechain", "userType"}:
        return "Claude Code", "Claude Code session record schema"
    if sources & {"user_explicit", "model"} or event_types & {"planner_response", "run_command", "view_file", "list_directory", "code_action"}:
        return "Antigravity CLI", "Antigravity CLI transcript record schema"
    if keys & {"agentId", "bubbleId", "composerId"}:
        return "Cursor", "Cursor transcript record schema"
    return None, None


def _detect_jsonl(path: Path, hint: str | None) -> SessionSource | SessionInputIssue:
    records, malformed, read_error = _probe_jsonl(path)
    if read_error:
        return SessionInputIssue(path.resolve(), "parse_failed", f"content probe failed: {read_error}")
    if not records:
        reason = "empty file" if path.stat().st_size == 0 else "no parser-safe JSON object records found"
        if malformed:
            reason += f" ({malformed} malformed probe lines)"
        return SessionInputIssue(path.resolve(), "parse_failed", reason)
    strong_tool, strong_reason = _strong_jsonl_tool(records)
    if hint and strong_tool and hint != strong_tool:
        return SessionInputIssue(path.resolve(), "unsupported", f"detected {strong_tool}, incompatible with --tool {hint}")
    tool = strong_tool
    confidence = "strong" if strong_tool else "moderate"
    reason = strong_reason
    if tool is None:
        path_tool, path_reason = _path_tool(path)
        if hint and path_tool and hint != path_tool:
            return SessionInputIssue(path.resolve(), "unsupported", f"path indicates {path_tool}, incompatible with --tool {hint}")
        tool = path_tool or hint
        reason = path_reason or ("parser-safe JSONL with compatible operator tool hint" if hint else None)
    if tool is None:
        return SessionInputIssue(path.resolve(), "ambiguous", "JSONL records are valid but do not identify a supported tool")
    if tool == "Cursor":
        artifact_type = "agent_transcript_jsonl"
        parser = "cursor_agent_transcript"
    elif tool == "Antigravity CLI":
        artifact_type = "transcript_jsonl"
        parser = "generic_session_jsonl"
    elif path.name.lower() in {"history.jsonl", "session_index.jsonl"}:
        artifact_type = "history_jsonl" if path.name.lower() == "history.jsonl" else "session_index_jsonl"
        parser = "generic_session_jsonl"
    else:
        artifact_type = "session_jsonl"
        parser = "generic_session_jsonl"
    return _source(path, tool, artifact_type, "JSONL", confidence, reason or "recognized JSONL", parser)


def _detect_sqlite(path: Path, hint: str | None) -> SessionSource | SessionInputIssue:
    try:
        uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            connection.execute("PRAGMA query_only = ON")
            tables = {str(row[0]).lower() for row in connection.execute("select name from sqlite_master where type = 'table'")}
            columns = {
                str(row[1]).lower()
                for table in tables
                for row in connection.execute(f'pragma table_info("{table.replace(chr(34), chr(34) * 2)}")')
            }
    except (OSError, sqlite3.Error) as exc:
        return SessionInputIssue(path.resolve(), "parse_failed", f"SQLite probe failed: {exc}")
    if {"blobs", "meta"}.issubset(tables):
        if hint and hint != "Cursor":
            return SessionInputIssue(path.resolve(), "unsupported", f"detected Cursor, incompatible with --tool {hint}")
        return _source(path, "Cursor", "chat_store_sqlite", "SQLite", "strong", "Cursor blobs/meta SQLite schema", "cursor_chat_store")
    antigravity_schema = (
        any("conversation" in table or "summary" in table for table in tables)
        or ({"conversation_id", "session_id"} & columns and {"message", "content", "summary", "title"} & columns)
    )
    path_tool, _ = _path_tool(path)
    known_antigravity_name = path.name.lower() == "conversation_summaries.db" or path.parent.name.lower() == "conversations"
    if antigravity_schema or (known_antigravity_name and path_tool == "Antigravity CLI"):
        if hint and hint != "Antigravity CLI":
            return SessionInputIssue(path.resolve(), "unsupported", f"detected Antigravity CLI, incompatible with --tool {hint}")
        reason = "Antigravity CLI conversation/summary SQLite schema" if antigravity_schema else "recognized Antigravity CLI SQLite location"
        return _source(path, "Antigravity CLI", "conversation_store_sqlite", "SQLite", "strong" if antigravity_schema else "moderate", reason, "antigravity_sqlite_metadata")
    return SessionInputIssue(path.resolve(), "unsupported", "SQLite schema is not supported for session parsing")


def _matches_patterns(path: Path, root: Path, includes: Iterable[str], excludes: Iterable[str]) -> bool:
    relative = path.name if root.is_file() else path.relative_to(root).as_posix()
    includes = list(includes)
    excludes = list(excludes)
    if includes and not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in includes):
        return False
    return not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in excludes)


def discover_session_inputs(
    input_path: str | Path,
    *,
    tool_hint: str | None = None,
    max_files: int = 10_000,
    max_file_size: int = 512 * 1024 * 1024,
    includes: Iterable[str] = (),
    excludes: Iterable[str] = (),
) -> SessionInputDiscovery:
    root = Path(input_path).expanduser()
    if root.is_symlink():
        raise ValueError(f"Session input path must not be a symbolic link: {root}")
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Session input path does not exist: {root}")
    if max_files < 1 or max_file_size < 1:
        raise ValueError("--max-files and --max-file-size must be positive integers")
    hint = normalize_tool_hint(tool_hint)
    result = SessionInputDiscovery(input_path=root)
    candidates = [root] if root.is_file() else root.rglob("*")
    accepted_paths: list[Path] = []
    for path in candidates:
        if path.is_symlink():
            result.skipped_links += 1
            continue
        if not path.is_file() or not _matches_patterns(path, root, includes, excludes):
            continue
        if "blacklight-reports" in {part.lower() for part in path.parts}:
            continue
        accepted_paths.append(path)
        result.files_examined += 1
        if root.is_dir() and result.files_examined == max_files:
            result.limit_reached = True
            break
    for path in sorted(accepted_paths, key=lambda item: str(item).lower()):
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.issues.append(SessionInputIssue(path.resolve(), "parse_failed", f"stat failed: {exc}"))
            continue
        if size > max_file_size:
            result.issues.append(SessionInputIssue(path.resolve(), "unsupported", f"file exceeds max size ({size} > {max_file_size} bytes)"))
            continue
        try:
            with path.open("rb") as handle:
                header = handle.read(16)
        except OSError as exc:
            result.issues.append(SessionInputIssue(path.resolve(), "parse_failed", f"read failed: {exc}"))
            continue
        if header == b"SQLite format 3\x00":
            detected = _detect_sqlite(path, hint)
        elif path.suffix.lower() in {".jsonl", ".json", ".bin", ".txt", ""}:
            detected = _detect_jsonl(path, hint)
        else:
            result.issues.append(SessionInputIssue(path.resolve(), "unsupported", "extension and content do not match a supported session artifact"))
            continue
        if isinstance(detected, SessionSource):
            result.sources.append(detected)
        else:
            result.issues.append(detected)
    return result
