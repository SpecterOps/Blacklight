from __future__ import annotations

import fnmatch
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import zstandard

from .common import open_session_text
from .progress import AnalysisProgress, ProgressCallback
from .sqlite_input import sqlite_snapshot
from .muse_sessions import is_muse_record


SUPPORTED_TOOLS = ("codex", "claude", "cursor", "antigravity_cli", "grok", "opencode", "muse_code")
_TOOL_NAMES = {
    "codex": "Codex",
    "claude": "Claude Code",
    "claude code": "Claude Code",
    "cursor": "Cursor",
    "antigravity": "Antigravity CLI",
    "antigravity cli": "Antigravity CLI",
    "antigravity_cli": "Antigravity CLI",
    "grok": "Grok",
    "grok cli": "Grok",
    "opencode": "OpenCode",
    "muse_code": "Muse Code",
    "muse code": "Muse Code",
}
_GROK_CHAT_NAMES = {"summary.json", "updates.jsonl", "chat_history.jsonl", "prompt_history.jsonl"}
_LOCAL_TOOL_ORDER = ("Codex", "Claude Code", "Cursor", "Antigravity CLI", "Grok", "OpenCode", "Muse Code")


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
    scan_scope: str = "selected_path"
    local_roots: dict[str, dict[str, Any]] = field(default_factory=dict)
    files_examined: int = 0
    session_candidates_examined: int = 0
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

    @property
    def skipped_non_session_count(self) -> int:
        return sum(issue.status == "skipped_non_session" for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_path": str(self.input_path),
            "scan_scope": self.scan_scope,
            "local_roots": self.local_roots,
            "files_examined": self.files_examined,
            "session_candidates_examined": self.session_candidates_examined,
            "skipped_non_session_files": self.skipped_non_session_count,
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
    if name in _GROK_CHAT_NAMES and "/.grok/" in text:
        return "Grok", "recognized Grok chat filename and location"
    return None, None


def _in_grok_sessions(path: Path) -> bool:
    parts = tuple(part.lower() for part in path.parts)
    return any(parts[index:index + 2] == (".grok", "sessions") for index in range(len(parts) - 1))


def _grok_acp_record(record: dict[str, Any]) -> bool:
    method = record.get("method")
    if method not in {"session/update", "_x.ai/session/update"}:
        return False
    params = record.get("params")
    if not isinstance(params, dict) or not params.get("sessionId"):
        return False
    update = params.get("update")
    return isinstance(update, dict) and bool(update.get("sessionUpdate"))


def _grok_prompt_record(record: dict[str, Any]) -> bool:
    session_id = record.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return False
    if record.get("timestamp") in (None, ""):
        return False
    if not isinstance(record.get("prompt"), str):
        return False
    return isinstance(record.get("is_bash"), bool)


def _grok_chat_content(content: Any) -> bool:
    if isinstance(content, str):
        return True
    if not isinstance(content, list) or not content:
        return False
    return any(isinstance(item, dict) and "type" in item and "text" in item for item in content)


def _grok_tool_call_entry(entry: Any) -> bool:
    return isinstance(entry, dict) and isinstance(entry.get("id"), str) and isinstance(entry.get("name"), str) and "arguments" in entry


def _grok_chat_records(records: Iterable[dict[str, Any]], *, require_tool_calls: bool = True) -> bool:
    saw_message = False
    saw_tool = False
    saw_system = False
    saw_user_or_assistant = False
    for record in records:
        kind = record.get("type")
        if kind not in {"system", "user", "assistant"}:
            continue
        if _grok_chat_content(record.get("content")):
            saw_message = True
            saw_system |= kind == "system"
            saw_user_or_assistant |= kind in {"user", "assistant"}
        calls = record.get("tool_calls")
        if kind == "assistant" and isinstance(calls, list) and any(_grok_tool_call_entry(item) for item in calls):
            saw_tool = True
    if require_tool_calls:
        return saw_message and (saw_tool or (saw_system and saw_user_or_assistant))
    return saw_message


def _grok_summary_document(record: dict[str, Any]) -> bool:
    info = record.get("info")
    if not isinstance(info, dict) or not info.get("id") or not info.get("cwd"):
        return False
    if "created_at" not in record or "updated_at" not in record:
        return False
    return "generated_title" in record or "session_summary" in record


def _load_grok_summary_document(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > 5 * 1024 * 1024:
            return None
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            first_line = ""
            for line in handle:
                if line.strip():
                    first_line = line.strip()
                    break
            else:
                return None
            try:
                json.loads(first_line)
            except json.JSONDecodeError:
                handle.seek(0)
                value = json.load(handle)
            else:
                return None
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if isinstance(value, dict) and _grok_summary_document(value):
        return value
    return None


def _grok_artifact(records: Iterable[dict[str, Any]], *, known_chat_name: bool = False) -> tuple[str, str, str] | None:
    records = list(records)
    if any(_grok_acp_record(record) for record in records):
        return "grok_acp_jsonl", "JSONL", "grok_session_jsonl"
    if any(_grok_prompt_record(record) for record in records):
        return "grok_prompt_history_jsonl", "JSONL", "grok_session_jsonl"
    if _grok_chat_records(records, require_tool_calls=not known_chat_name):
        return "grok_chat_history_jsonl", "JSONL", "grok_session_jsonl"
    if any(_grok_summary_document(record) for record in records):
        return "grok_summary_json", "JSON", "grok_session_summary"
    return None


def _probe_jsonl(path: Path) -> tuple[list[dict[str, Any]], int, str | None]:
    records: list[dict[str, Any]] = []
    malformed = 0
    try:
        with open_session_text(path) as handle:
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
    except (OSError, zstandard.ZstdError) as exc:
        return [], 0, str(exc)
    return records, malformed, None


def _strong_jsonl_tool(records: Iterable[dict[str, Any]]) -> tuple[str | None, str | None]:
    records = list(records)
    keys = {str(key) for record in records for key in record}
    event_types = {str(record.get("type", "")).lower() for record in records}
    sources = {str(record.get("source", "")).lower() for record in records}
    if any(is_muse_record(record) for record in records):
        return "Muse Code", "Muse durable event envelope schema"
    if any(record.get("type") == "system" and record.get("subtype") == "init"
           and "session_id" in record and "apiKeySource" in record for record in records):
        return "Cursor", "Cursor CLI stream initialization schema"
    if event_types & {"session_meta", "event_msg", "response_item", "turn_context"}:
        return "Codex", "Codex rollout record schema"
    if any({"id", "thread_name", "updated_at"}.issubset(record) for record in records):
        return "Codex", "Codex session index schema"
    if keys & {"parentUuid", "isSidechain", "userType"}:
        return "Claude Code", "Claude Code session record schema"
    if any(_grok_acp_record(record) for record in records):
        return "Grok", "Grok ACP session update schema"
    if any(_grok_prompt_record(record) for record in records):
        return "Grok", "Grok prompt history schema"
    if _grok_chat_records(records):
        return "Grok", "Grok chat history schema"
    if any(_grok_summary_document(record) for record in records):
        return "Grok", "Grok session summary schema"
    if any("session_id" in record and str(record.get("role") or "").lower() in {"user", "assistant", "tool"} and "content" in record for record in records):
        return "Codex", "Codex session record schema"
    if sources & {"user_explicit", "model"} or event_types & {"planner_response", "run_command", "view_file", "list_directory", "code_action"}:
        return "Antigravity CLI", "Antigravity CLI transcript record schema"
    if keys & {"agentId", "bubbleId", "composerId"}:
        return "Cursor", "Cursor transcript record schema"
    return None, None


def _detect_jsonl(path: Path, hint: str | None) -> SessionSource | SessionInputIssue:
    records, malformed, read_error = _probe_jsonl(path)
    if read_error:
        status = "parse_failed" if path.name.lower() in _GROK_CHAT_NAMES or not _in_grok_sessions(path) else "skipped_non_session"
        return SessionInputIssue(path.resolve(), status, f"content probe failed: {read_error}" if status == "parse_failed" else "not a Grok chat artifact")
    if not records:
        summary = _load_grok_summary_document(path)
        if summary is not None:
            records = [summary]
        else:
            reason = "empty file" if path.stat().st_size == 0 else "no parser-safe JSON object records found"
            if malformed:
                reason += f" ({malformed} malformed probe lines)"
            status = "parse_failed" if path.name.lower() in _GROK_CHAT_NAMES or not _in_grok_sessions(path) else "skipped_non_session"
            return SessionInputIssue(path.resolve(), status, reason if status == "parse_failed" else "not a Grok chat artifact")
    strong_tool, strong_reason = _strong_jsonl_tool(records)
    if _in_grok_sessions(path) and strong_tool not in {None, "Grok"}:
        status = "unsupported" if path.name.lower() in _GROK_CHAT_NAMES else "skipped_non_session"
        return SessionInputIssue(path.resolve(), status, "conflicting session schema" if status == "unsupported" else "not a Grok chat artifact")
    if _in_grok_sessions(path) and path.name.lower() not in _GROK_CHAT_NAMES and strong_tool != "Grok":
        return SessionInputIssue(path.resolve(), "skipped_non_session", "not a Grok chat artifact")
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
    format_name = "JSONL (Zstandard)" if path.name.lower().endswith(".jsonl.zst") else "JSONL"
    if tool == "Muse Code":
        artifact_type = "muse_session_jsonl"
        parser = "muse_durable_events"
    elif tool == "Cursor":
        artifact_type = "agent_transcript_jsonl"
        parser = "cursor_agent_transcript"
    elif tool == "Antigravity CLI":
        artifact_type = "transcript_jsonl"
        parser = "generic_session_jsonl"
    elif tool == "Grok":
        grok_artifact = _grok_artifact(records, known_chat_name=path.name.lower() == "chat_history.jsonl")
        if grok_artifact is None:
            if hint == "Grok" and not _in_grok_sessions(path):
                grok_artifact = ("session_jsonl", "JSONL", "grok_session_jsonl")
            else:
                status = ("parse_failed" if path.name.lower() in _GROK_CHAT_NAMES and _in_grok_sessions(path)
                          else "skipped_non_session" if _in_grok_sessions(path) else "ambiguous")
                return SessionInputIssue(path.resolve(), status, "not a recognized Grok chat schema")
        artifact_type, format_name, parser = grok_artifact
    elif path.name.lower() in {"history.jsonl", "session_index.jsonl"}:
        artifact_type = "history_jsonl" if path.name.lower() == "history.jsonl" else "session_index_jsonl"
        parser = "generic_session_jsonl"
    else:
        artifact_type = "session_jsonl"
        parser = "generic_session_jsonl"
    return _source(path, tool, artifact_type, format_name, confidence, reason or "recognized JSONL", parser)


def _detect_sqlite(path: Path, hint: str | None) -> SessionSource | SessionInputIssue:
    try:
        with sqlite_snapshot(path) as connection:
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
    if {"session", "message", "part"}.issubset(tables) or {"session_v2", "session_message"}.issubset(tables):
        if hint and hint != "OpenCode":
            return SessionInputIssue(path.resolve(), "unsupported", f"detected OpenCode, incompatible with --tool {hint}")
        return _source(path, "OpenCode", "opencode_session_sqlite", "SQLite", "strong", "OpenCode V1/V2 SQLite session tables; database may contain credentials", "opencode_sqlite")
    if _codex_state_name(path) and "threads" in tables and {"id", "rollout_path"}.issubset(columns):
        if hint and hint != "Codex":
            return SessionInputIssue(path.resolve(), "unsupported", f"detected Codex, incompatible with --tool {hint}")
        return _source(path, "Codex", "codex_state_sqlite", "SQLite", "strong", "Codex state index; rows do not establish rollout-file existence", "sqlite_metadata")
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


def _codex_state_name(path: Path) -> bool:
    name = path.name.lower()
    return name == "state_5.sqlite" or name.startswith(("state_5.sqlite.bak", "state_5.sqlite.corrupt", "state_5.sqlite.backup"))


def _matches_patterns(path: Path, root: Path, includes: Iterable[str], excludes: Iterable[str]) -> bool:
    relative = path.name if root.is_file() else path.relative_to(root).as_posix()
    includes = list(includes)
    excludes = list(excludes)
    if includes and not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in includes):
        return False
    return not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in excludes)


def _inspect_session_path(result: SessionInputDiscovery, path: Path, hint: str | None, max_file_size: int, *, local_candidate: bool = False) -> None:
    if local_candidate:
        result.session_candidates_examined += 1
    grok_directory_file = _in_grok_sessions(path)
    if grok_directory_file and path.suffix.lower() not in {".jsonl", ".json", ".bin"} and path.name.lower() not in _GROK_CHAT_NAMES:
        result.issues.append(SessionInputIssue(path.resolve(), "skipped_non_session", "not a Grok chat artifact"))
        return
    known_grok_candidate = grok_directory_file and path.name.lower() in _GROK_CHAT_NAMES
    if known_grok_candidate and not local_candidate:
        result.session_candidates_examined += 1
    try:
        size = path.stat().st_size
    except OSError as exc:
        result.issues.append(SessionInputIssue(path.resolve(), "parse_failed", f"stat failed: {exc}"))
        return
    if size > max_file_size:
        result.issues.append(SessionInputIssue(path.resolve(), "unsupported", f"file exceeds max size ({size} > {max_file_size} bytes)"))
        return
    if path.name.lower().endswith(".jsonl.zst"):
        try:
            expanded_size = 0
            with path.open("rb") as compressed:
                with zstandard.ZstdDecompressor().stream_reader(compressed) as decompressed:
                    while True:
                        chunk = decompressed.read(min(1024 * 1024, max_file_size - expanded_size + 1))
                        if not chunk:
                            break
                        expanded_size += len(chunk)
                        if expanded_size > max_file_size:
                            result.issues.append(SessionInputIssue(
                                path.resolve(), "unsupported",
                                f"decompressed file exceeds max size ({expanded_size} > {max_file_size} bytes)",
                            ))
                            return
        except (OSError, zstandard.ZstdError) as exc:
            result.issues.append(SessionInputIssue(path.resolve(), "parse_failed", f"zstd decompression failed: {exc}"))
            return
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError as exc:
        result.issues.append(SessionInputIssue(path.resolve(), "parse_failed", f"read failed: {exc}"))
        return
    if header == b"SQLite format 3\x00" or _codex_state_name(path):
        detected = (SessionInputIssue(path.resolve(), "skipped_non_session", "Grok search database is outside session scope")
                    if grok_directory_file else _detect_sqlite(path, hint))
    elif path.name.lower().endswith(".jsonl.zst") or path.suffix.lower() in {".jsonl", ".json", ".bin", ".txt", ""}:
        detected = _detect_jsonl(path, hint)
    else:
        result.issues.append(SessionInputIssue(path.resolve(), "unsupported", "extension and content do not match a supported session artifact"))
        return
    if isinstance(detected, SessionSource):
        result.sources.append(detected)
    else:
        result.issues.append(detected)
    if not local_candidate and not known_grok_candidate and (not isinstance(detected, SessionInputIssue) or detected.status != "skipped_non_session"):
        result.session_candidates_examined += 1


def _local_candidate_paths(home: Path, tool: str) -> tuple[Path, list[Path]]:
    if tool == "Muse Code":
        root = home / ".local/share/muse/sessions"
        paths = [] if root.is_symlink() else list(root.glob("**/session.jsonl"))
    elif tool == "OpenCode":
        root = home / ".local" / "share" / "opencode"
        paths = [] if root.is_symlink() else [root / "opencode.db"]
    elif tool == "Codex":
        root = home / ".codex"
        if root.is_symlink():
            return root, []
        paths = [root / "history.jsonl", root / "session_index.jsonl"]
        paths += [path for path in root.glob("state_5.sqlite*") if _codex_state_name(path) and not path.name.endswith(("-wal", "-shm"))]
        paths += list((root / "sessions").glob("**/*.jsonl"))
        paths += list((root / "sessions").glob("**/*.jsonl.zst"))
        paths += list((root / "archived_sessions").glob("**/*.jsonl"))
        paths += list((root / "archived_sessions").glob("**/*.jsonl.zst"))
    elif tool == "Claude Code":
        root = home / ".claude"
        if root.is_symlink():
            return root, []
        paths = [root / "history.jsonl"] + list((root / "projects").glob("**/*.jsonl"))
        paths += list((root / "sessions").glob("**/*.jsonl"))
    elif tool == "Cursor":
        root = home / ".cursor"
        if root.is_symlink():
            return root, []
        paths = list((root / "chats").glob("**/store.db"))
        paths += list((root / "projects").glob("*/agent-transcripts/**/*.jsonl"))
    elif tool == "Antigravity CLI":
        root = home / ".gemini" / "antigravity-cli"
        if root.is_symlink() or root.parent.is_symlink():
            return root, []
        paths = [root / "history.jsonl", root / "conversation_summaries.db"]
        paths += list((root / "conversations").glob("*.db"))
        for name in ("antigravity-cli", "antigravity-ide", "antigravity-backup"):
            sibling = root.parent / name
            if sibling.is_symlink():
                continue
            brain = sibling / "brain"
            for full in brain.glob("*/.system_generated/logs/transcript_full.jsonl"):
                paths.append(full)
            for compact in brain.glob("*/.system_generated/logs/transcript.jsonl"):
                full = compact.parent / "transcript_full.jsonl"
                if not full.is_file() or full.is_symlink():
                    paths.append(compact)
        if not root.is_dir() and paths:
            root = root.parent
    else:
        root = home / ".grok" / "sessions"
        if root.is_symlink() or root.parent.is_symlink():
            return root, []
        paths = [path for name in sorted(_GROK_CHAT_NAMES) for path in root.glob(f"**/{name}")]
    return root, paths


def discover_local_session_inputs(
    home_path: str | Path | None = None,
    *,
    tool: str | None = None,
    max_files: int = 10_000,
    max_file_size: int = 512 * 1024 * 1024,
    includes: Iterable[str] = (),
    excludes: Iterable[str] = (),
    progress_callback: ProgressCallback | None = None,
) -> SessionInputDiscovery:
    progress = AnalysisProgress(progress_callback)
    progress.start("Discovering files")
    home = Path(home_path).expanduser() if home_path is not None else Path.home()
    if home.is_symlink():
        raise ValueError(f"Session input path must not be a symbolic link: {home}")
    home = home.resolve()
    if max_files < 1 or max_file_size < 1:
        raise ValueError("--max-files and --max-file-size must be positive integers")
    selected_tool = normalize_tool_hint(tool)
    result = SessionInputDiscovery(input_path=home, scan_scope="local agent session roots")
    buckets: dict[str, list[Path]] = {}
    for name in _LOCAL_TOOL_ORDER:
        if selected_tool and name != selected_tool:
            continue
        root, found = _local_candidate_paths(home, name)
        status = "present" if root.is_dir() else "absent"
        if root.is_symlink() or any(parent.is_symlink() for parent in root.parents if parent != home and home in parent.parents):
            status = "symlink_skipped"
            result.skipped_links += 1
        accepted = []
        if status == "present":
            for path in found:
                if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != home and home in parent.parents):
                    result.skipped_links += 1
                    continue
                if path.is_file() and _matches_patterns(path, home, includes, excludes):
                    accepted.append(path)
        accepted = sorted(set(accepted), key=lambda path: (-path.stat().st_mtime_ns, path.as_posix()))
        buckets[name] = accepted
        result.local_roots[name] = {"path": str(root), "status": status, "candidate_count": len(accepted), "examined_count": 0}
    progress.start("Identifying supported artifacts", min(max_files, sum(len(paths) for paths in buckets.values())))
    positions = {name: 0 for name in buckets}
    while result.files_examined < max_files:
        progressed = False
        for name in buckets:
            position = positions[name]
            if position >= len(buckets[name]):
                continue
            path = buckets[name][position]
            positions[name] += 1
            result.files_examined += 1
            result.local_roots[name]["examined_count"] += 1
            _inspect_session_path(result, path, name, max_file_size, local_candidate=True)
            progress.advance()
            progressed = True
            if result.files_examined >= max_files:
                break
        if not progressed:
            break
    result.limit_reached = any(positions[name] < len(paths) for name, paths in buckets.items())
    return result


def discover_session_inputs(
    input_path: str | Path,
    *,
    tool_hint: str | None = None,
    max_files: int = 10_000,
    max_file_size: int = 512 * 1024 * 1024,
    includes: Iterable[str] = (),
    excludes: Iterable[str] = (),
    progress_callback: ProgressCallback | None = None,
) -> SessionInputDiscovery:
    progress = AnalysisProgress(progress_callback)
    progress.start("Discovering files")
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
    progress.start("Identifying supported artifacts", len(accepted_paths))
    for path in progress.items(sorted(accepted_paths, key=lambda item: str(item).lower())):
        _inspect_session_path(result, path, hint, max_file_size)
    return result
