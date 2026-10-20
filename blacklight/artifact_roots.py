"""Locate discovery-only session stores without parsing conversation bodies.

Strands registry schema: strands-agents/harness-sdk,
strands-cli/src/tui/session/catalog.ts (SessionRootDocument, version 1).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Mapping


_MAX_REGISTRY_BYTES = 1024 * 1024
_MAX_REGISTRY_ROOTS = 1024


def _regular_path(path: Path) -> bool:
    return not any(part.is_symlink() for part in (path, *path.parents))


def session_artifact_roots(
    tool: str, home: Path | None = None, *, environ: Mapping[str, str] | None = None,
) -> list[Path]:
    """Return existing real directories; absent/cloud-only stores return no roots.

    Registry entries identify Strands storage directories, not workspace roots.
    """
    home = (home or Path.home()).absolute()
    environ = os.environ if environ is None else environ
    if tool in ("kiro", "devin"):
        override = environ.get(f"{tool.upper()}_SESSIONS_DIR", "").strip()
        if override:
            root = Path(override)
            if not root.is_absolute():
                raise ValueError("Session directory overrides must be absolute paths")
            candidates = [root]
        elif tool == "kiro":
            candidates = [home / ".kiro/sessions/cli", home / ".local/share/kiro-cli",
                          home / "Library/Application Support/kiro-cli",
                          home / "AppData/Roaming/kiro-cli"]
        else:
            candidates = [home / ".local/share/devin/cli", home / "AppData/Local/devin/cli"]
    elif tool == "strands":
        registry = home / ".strands/cli/session-roots.json"
        if not _regular_path(registry):
            return []
        try:
            with registry.open("rb") as stream:
                raw = stream.read(_MAX_REGISTRY_BYTES + 1)
            if len(raw) > _MAX_REGISTRY_BYTES:
                return []
            document = json.loads(raw)
        except (OSError, ValueError, UnicodeError):
            return []
        if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] != 1:
            return []
        entries = document.get("roots")
        if not isinstance(entries, list) or len(entries) > _MAX_REGISTRY_ROOTS:
            return []
        candidates = []
        for entry in entries:
            if not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) for key in ("directory", "workspace", "lastSeenAt")):
                continue
            directory = Path(entry["directory"])
            # Upstream writes absolute paths; do not interpret relative paths
            # against the analysis process's unrelated working directory.
            if directory.is_absolute():
                candidates.append(directory)
    else:
        raise ValueError(f"Unsupported discovery-only tool: {tool}")
    return sorted({path for path in candidates if _regular_path(path) and path.is_dir()})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True, choices=("kiro", "devin", "strands"))
    args = parser.parse_args()
    try:
        roots = session_artifact_roots(args.tool)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps({"tool": args.tool, "session_artifact_roots": [str(root) for root in roots],
                      "support": "discovery_only"}, indent=2))


if __name__ == "__main__":
    main()
