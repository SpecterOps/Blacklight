from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA_VERSION = "blacklight.analyze.v1"
PARSER_VERSION = "0.1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def host_context() -> dict[str, str]:
    return {
        "host": socket.gethostname(),
        "os": platform.platform(),
        "current_user": getpass.getuser(),
    }


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", value)


def sha256_text(value: Any) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any] | None, str | None]]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                yield line_number, None, str(exc)
                continue
            if isinstance(value, dict):
                yield line_number, value, None
            else:
                yield line_number, {"value": value}, None


def flatten(value: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{prefix}.{key}" if prefix else str(key)
            yield from flatten(child, child_path)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{prefix}[{index}]"
            yield from flatten(child, child_path)
        return
    yield prefix, value


def text_fragments(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for key, child in value.items():
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
                yield from text_fragments(child)
            elif isinstance(child, (dict, list)):
                yield from text_fragments(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from text_fragments(child)


def first_value(value: Any, keys: Iterable[str], scalar_only: bool = False) -> Any:
    wanted = {key.lower() for key in keys}

    def accepted(child: Any) -> bool:
        if child in (None, ""):
            return False
        if scalar_only and not isinstance(child, (str, int, float, bool)):
            return False
        return True

    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in wanted and accepted(child):
                return child
        for child in value.values():
            result = first_value(child, wanted, scalar_only=scalar_only)
            if result not in (None, ""):
                return result
    elif isinstance(value, list):
        for child in value:
            result = first_value(child, wanted, scalar_only=scalar_only)
            if result not in (None, ""):
                return result
    return None


def text_metric(value: Any) -> dict[str, int]:
    fragments = list(text_fragments(value))
    return {
        "chars": sum(len(fragment) for fragment in fragments),
        "bytes": sum(len(fragment.encode("utf-8")) for fragment in fragments),
    }


def expand_env_path(value: str) -> Path:
    def replace_percent(match: re.Match[str]) -> str:
        key = match.group(1)
        if key.upper() == "USERPROFILE":
            return os.environ.get(key, str(Path.home()))
        return os.environ.get(key, match.group(0))

    expanded = re.sub(r"%([^%]+)%", replace_percent, value)
    expanded = os.path.expandvars(os.path.expanduser(expanded))
    return Path(expanded)


def _input_path(value: str | Path) -> Path:
    text = str(value)
    if os.name != "nt" and re.match(r"^[A-Za-z]:[\\/]", text):
        return Path(text)
    return expand_env_path(text).resolve()


def resolve_package_child(root: Path, candidates: Iterable[str]) -> Path | None:
    candidates = list(candidates)
    for candidate in candidates:
        path = root / candidate
        if path.exists():
            return path
    return None


def detect_tool(root: Path, requested: str = "Auto") -> str:
    normalized = requested.lower()
    if normalized == "codex":
        return "Codex"
    if normalized in {"claude", "claude code"}:
        return "Claude Code"
    if normalized == "cursor":
        return "Cursor"
    if normalized in {"antigravity cli", "antigravity-cli", "antigravity_cli"}:
        return "Antigravity CLI"
    codex_score = sum((root / candidate).exists() for candidate in ("auth.json", "session_index.jsonl", "sessions", "archived_sessions", "config.toml", "rules"))
    claude_score = sum((root / candidate).exists() for candidate in ("settings.json", ".claude.json", "projects", "history.jsonl"))
    cursor_score = sum((root / candidate).exists() for candidate in ("cli-config.json", "prompt_history.json", "plans", "chats", "ai-tracking"))
    antigravity_cli_score = sum(
        (root / candidate).exists()
        for candidate in ("settings.json", "history.jsonl", "conversation_summaries.db", "conversations", "brain", "cache", "builtin")
    )
    scores = {"Codex": codex_score, "Claude Code": claude_score, "Cursor": cursor_score, "Antigravity CLI": antigravity_cli_score}
    best_tool, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score > 0 and list(scores.values()).count(best_score) == 1:
        return best_tool
    raise ValueError(f"Could not determine target tool for '{root}'. Re-run with --target-tool Codex, Claude, Cursor, or Antigravity CLI.")


@dataclass
class InputRoots:
    input_mode: str
    package_root: Path | None
    target_root: Path | None
    target_tool: str | None
    codex_root: Path | None
    claude_root: Path | None
    claude_home_config: Path | None
    cursor_root: Path | None
    antigravity_cli_root: Path | None


def resolve_input_roots(
    *,
    package_root: str | Path | None = None,
    target_root: str | Path | None = None,
    target_tool: str = "Auto",
    live_root: bool = False,
    codex_root: str | Path | None = None,
    claude_root: str | Path | None = None,
    claude_home_config: str | Path | None = None,
    cursor_root: str | Path | None = None,
    antigravity_cli_root: str | Path | None = None,
) -> InputRoots:
    if package_root and target_root:
        raise ValueError("Supply only one of --package-root or --target-root.")
    if package_root and live_root:
        raise ValueError("Supply only one of --package-root or live-root analysis.")
    if target_root and live_root:
        raise ValueError("Supply only one of --target-root or live-root analysis.")
    explicit_live_roots = any((codex_root, claude_root, claude_home_config, cursor_root, antigravity_cli_root))
    if not package_root and not target_root and not live_root and not explicit_live_roots:
        raise ValueError("Session parsing requires a package root, target root, or explicit session sources.")
    if target_root:
        root = _input_path(target_root)
        tool = detect_tool(root, target_tool)
        return InputRoots(
            input_mode="target_root",
            package_root=None,
            target_root=root,
            target_tool=tool,
            codex_root=root if tool == "Codex" else None,
            claude_root=root if tool == "Claude Code" else None,
            claude_home_config=(
                _input_path(claude_home_config)
                if tool == "Claude Code" and claude_home_config
                else None
            ),
            cursor_root=root if tool == "Cursor" else None,
            antigravity_cli_root=root if tool == "Antigravity CLI" else None,
        )
    if live_root or explicit_live_roots:
        home = Path.home()
        return InputRoots(
            input_mode="live_root",
            package_root=None,
            target_root=None,
            target_tool=None,
            codex_root=_input_path(codex_root) if codex_root else home / ".codex",
            claude_root=_input_path(claude_root) if claude_root else home / ".claude",
            claude_home_config=_input_path(claude_home_config) if claude_home_config else home / ".claude.json",
            cursor_root=_input_path(cursor_root) if cursor_root else home / ".cursor",
            antigravity_cli_root=_input_path(antigravity_cli_root) if antigravity_cli_root else home / ".gemini" / "antigravity-cli",
        )
    root = _input_path(package_root)
    return InputRoots(
        input_mode="package",
        package_root=root,
        target_root=None,
        target_tool=None,
        codex_root=resolve_package_child(root, ("codex", ".codex")),
        claude_root=resolve_package_child(root, ("claude", ".claude")),
        claude_home_config=resolve_package_child(root, (".claude.json", "claude.json", "claude_home/.claude.json")),
        cursor_root=next((root / candidate for candidate in ("cursor", ".cursor") if (root / candidate).exists()), None),
        antigravity_cli_root=next((root / candidate for candidate in ("antigravity_cli", "antigravity-cli", ".gemini/antigravity-cli") if (root / candidate).exists()), None),
    )


def artifact(
    artifact_id: str,
    tool: str,
    path: Path,
    category: str,
    format_name: str,
    *,
    exists: bool,
    parsed: bool,
    metadata: Any = None,
    parse_error: str | None = None,
) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "tool": tool,
        "path": str(path),
        "category": category,
        "format": format_name,
        "exists": exists,
        "parsed": parsed,
        "metadata": metadata,
        "parse_error": parse_error,
    }


def finding(tool: str, artifact_id: str, finding_type: str, name: str, value: Any) -> dict[str, Any]:
    return {
        "tool": tool,
        "artifact_id": artifact_id,
        "finding_type": finding_type,
        "name": name,
        "value": value,
    }


def tool_result(tool_name: str, root_path: Path | None) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "root_path": str(root_path) if root_path else None,
        "artifacts": [],
        "findings": [],
        "parse_errors": [],
    }


def add_parse_error(tool: dict[str, Any], path: Path, message: str) -> None:
    tool["parse_errors"].append({"path": str(path), "error": message})


def build_envelope(
    *,
    run_id: str,
    parser_name: str,
    output_kind: str,
    roots: InputRoots,
    content_policy: dict[str, Any],
    tools: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    context = host_context()
    return {
        "run_id": run_id,
        "collected_at_utc": utc_now(),
        "parser": {
            "name": parser_name,
            "version": PARSER_VERSION,
            "schema_version": SCHEMA_VERSION,
            "output_kind": output_kind,
            "input_mode": roots.input_mode,
            "package_root": str(roots.package_root) if roots.package_root else None,
            "target_root": str(roots.target_root) if roots.target_root else None,
            "target_tool": roots.target_tool,
            "live_roots": (
                {
                    "codex": str(roots.codex_root) if roots.codex_root else None,
                    "claude": str(roots.claude_root) if roots.claude_root else None,
                    "claude_home_config": str(roots.claude_home_config) if roots.claude_home_config else None,
                    "cursor": str(roots.cursor_root) if roots.cursor_root else None,
                    "antigravity_cli": str(roots.antigravity_cli_root) if roots.antigravity_cli_root else None,
                }
                if roots.input_mode == "live_root"
                else None
            ),
        },
        **context,
        "content_policy": content_policy,
        "tools": tools,
        "summary": summary,
    }


def summarize_tools(tools: list[dict[str, Any]]) -> dict[str, int]:
    artifacts = [item for tool in tools for item in tool["artifacts"]]
    findings = [item for tool in tools for item in tool["findings"]]
    errors = [item for tool in tools for item in tool["parse_errors"]]
    return {
        "tool_count": len(tools),
        "artifact_count": len(artifacts),
        "parsed_artifact_count": sum(1 for item in artifacts if item["parsed"]),
        "absent_artifact_count": sum(1 for item in artifacts if not item["exists"]),
        "parse_error_count": len(errors) + sum(1 for item in artifacts if item["parse_error"]),
        "finding_count": len(findings),
    }


def write_output(result: dict[str, Any], output_directory: str | Path | None, base_name: str, text_lines: list[str]) -> dict[str, Any]:
    if output_directory is None:
        return result
    output_path = Path(output_directory).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / f"{base_name}.json"
    text_path = output_path / f"{base_name}.txt"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    text_path.write_text("\n".join(text_lines) + "\n", encoding="utf-8")
    result["_output"] = {"json": str(json_path), "text": str(text_path)}
    return result
