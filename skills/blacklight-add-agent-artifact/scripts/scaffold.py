#!/usr/bin/env python3
"""Scaffold Blacklight Scout and Rules catalog entries for agents and artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath


PLATFORMS = ("windows", "darwin", "linux")
SCOUT_EVIDENCE = "blacklight.scout.PATH_TARGETS"
ANALYZE_EVIDENCE = "blacklight.analyze.run_session_detail"
PATH_KINDS = ("file", "directory", "glob")
PRIORITIES = ("low", "medium", "high")
COVERAGE_STATES = ("explicitly_assessed", "recursively_discovered", "intentionally_deferred")


class ScaffoldError(ValueError):
    pass


def repository_root(explicit: str | None) -> Path:
    return Path(explicit).resolve() if explicit else Path(__file__).resolve().parents[3]


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScaffoldError(f"Cannot read {path}: {exc}") from exc


def normalize_relative_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/").rstrip("/")
    if not normalized or normalized.startswith(("/", "$HOME/", "%USERPROFILE%/")):
        raise ScaffoldError("Paths must be non-empty and relative to the user's home directory")
    if any(part in ("", ".", "..") for part in normalized.split("/")):
        raise ScaffoldError("Paths cannot contain empty, current-directory, or parent-directory segments")
    path = PurePosixPath(normalized)
    return path.as_posix()


def target_pattern(profile: dict, relative_path: str) -> str:
    return f'{profile["home_var"]}/{relative_path}'


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))


def render_targets(catalog: dict) -> str:
    lines = ["{", f'  "schema_version": {json.dumps(catalog["schema_version"])},', f'  "tools": {compact_json(catalog["tools"])},', '  "platforms": {']
    for platform_index, platform in enumerate(PLATFORMS):
        profile = catalog["platforms"][platform]
        lines.extend(
            [
                f'    "{platform}": {{',
                f'      "home_var": {json.dumps(profile["home_var"])},',
                f'      "path_separator": {json.dumps(profile["path_separator"])},',
                '      "targets": [',
            ]
        )
        targets = profile["targets"]
        for index, target in enumerate(targets):
            comma = "," if index < len(targets) - 1 else ""
            lines.append(f"        {compact_json(target)}{comma}")
        platform_comma = "," if platform_index < len(PLATFORMS) - 1 else ""
        lines.extend(["      ]", f"    }}{platform_comma}"])
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


def existing_artifact_indexes(rules: dict) -> tuple[set[str], set[tuple[str, str]]]:
    ids = {item["id"] for item in rules["artifacts"]}
    paths = {(item["tool"], item["relative_path"]) for item in rules["artifacts"]}
    return ids, paths


def add_scout_target(scout: dict, tool: str, family: str, relative_path: str) -> None:
    if any(char in relative_path for char in "*?["):
        raise ScaffoldError("Scout exact targets cannot contain glob characters; use --rules-only")
    for platform in PLATFORMS:
        profile = scout["platforms"][platform]
        pattern = target_pattern(profile, relative_path)
        targets = profile["targets"]
        if any(item["pattern"].replace("\\", "/") == pattern for item in targets):
            raise ScaffoldError(f"Scout target already exists for {platform}: {pattern}")
        targets.append({"tool": tool, "family": family, "pattern": pattern})


def artifact_record(
    *, artifact_id: str, tool: str, family: str, relative_path: str, path_kind: str,
    priority: str, confirmed_by: list[str], assessment_coverage: str,
) -> dict:
    return {
        "id": artifact_id,
        "tool": tool,
        "family": family,
        "relative_path": relative_path,
        "path_kind": path_kind,
        "priority": priority,
        "confirmed_by": confirmed_by,
        "assessment_coverage": assessment_coverage,
    }


def require_unique_artifact(rules: dict, artifact_id: str, tool: str, relative_path: str) -> None:
    ids, paths = existing_artifact_indexes(rules)
    if artifact_id in ids:
        raise ScaffoldError(f"Artifact id already exists: {artifact_id}")
    if (tool, relative_path) in paths:
        raise ScaffoldError(f"Artifact path already exists for {tool}: {relative_path}")


def scaffold_agent(args: argparse.Namespace, scout: dict, rules: dict) -> list[str]:
    tool = args.tool.strip()
    if not tool or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in tool):
        raise ScaffoldError("Tool ids must use lowercase letters, digits, and underscores")
    if tool in scout["tools"]:
        raise ScaffoldError(f"Tool already exists: {tool}")
    root_path = normalize_relative_path(args.root_path)
    config_path = normalize_relative_path(args.config_path)
    if config_path == root_path or not config_path.startswith(root_path + "/"):
        raise ScaffoldError("The config path must be a descendant of the agent root")

    root_id = f"{tool}.root"
    config_id = f"{tool}.config"
    require_unique_artifact(rules, root_id, tool, root_path)
    require_unique_artifact(rules, config_id, tool, config_path)
    scout["tools"].append(tool)
    add_scout_target(scout, tool, "root", root_path)
    add_scout_target(scout, tool, "config", config_path)
    rules["artifacts"].extend(
        [
            artifact_record(artifact_id=root_id, tool=tool, family="root", relative_path=root_path, path_kind="directory", priority="medium", confirmed_by=[SCOUT_EVIDENCE], assessment_coverage="explicitly_assessed"),
            artifact_record(artifact_id=config_id, tool=tool, family="config", relative_path=config_path, path_kind="file", priority="high", confirmed_by=[SCOUT_EVIDENCE], assessment_coverage="explicitly_assessed"),
        ]
    )
    return [f"add tool {tool}", f"add root {root_path}", f"add config {config_path}"]


def scaffold_artifact(args: argparse.Namespace, scout: dict, rules: dict) -> list[str]:
    tool = args.tool.strip()
    if tool not in scout["tools"]:
        raise ScaffoldError(f"Unknown tool {tool!r}; add the agent first")
    if not args.artifact_id or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_." for char in args.artifact_id):
        raise ScaffoldError("Artifact ids must use lowercase letters, digits, underscores, and periods")
    if not args.family or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in args.family):
        raise ScaffoldError("Families must use lowercase letters, digits, and underscores")
    relative_path = normalize_relative_path(args.relative_path)
    rules_only = args.rules_only
    if not rules_only and args.assessment_coverage != "explicitly_assessed":
        raise ScaffoldError("Exact Scout targets must use explicitly_assessed coverage; pass --rules-only")
    if not rules_only and args.path_kind == "glob":
        raise ScaffoldError("Glob artifacts cannot be exact Scout targets; pass --rules-only")
    require_unique_artifact(rules, args.artifact_id, tool, relative_path)
    confirmed_by = [] if rules_only else [SCOUT_EVIDENCE]
    if args.analyze_confirmed:
        confirmed_by.append(ANALYZE_EVIDENCE)
    if not confirmed_by:
        confirmed_by.append(args.evidence_source)
    unknown = set(confirmed_by) - set(rules["evidence_sources"])
    if unknown:
        raise ScaffoldError(f"Unknown evidence source(s): {', '.join(sorted(unknown))}")
    if not rules_only:
        add_scout_target(scout, tool, args.family, relative_path)
    rules["artifacts"].append(
        artifact_record(
            artifact_id=args.artifact_id, tool=tool, family=args.family,
            relative_path=relative_path, path_kind=args.path_kind,
            priority=args.priority, confirmed_by=confirmed_by,
            assessment_coverage=args.assessment_coverage,
        )
    )
    return [f"add artifact {args.artifact_id}", f"catalog path {relative_path}", "Rules catalog only" if rules_only else "Scout + Rules catalogs"]


def validate_catalogs(scout: dict, rules: dict) -> None:
    if set(scout["platforms"]) != set(PLATFORMS):
        raise ScaffoldError(f"Expected platforms: {', '.join(PLATFORMS)}")
    ids, paths = existing_artifact_indexes(rules)
    if len(ids) != len(rules["artifacts"]):
        raise ScaffoldError("Rules artifact ids are not unique")
    if len(paths) != len(rules["artifacts"]):
        raise ScaffoldError("Rules tool/path pairs are not unique")
    for platform in PLATFORMS:
        for item in scout["platforms"][platform]["targets"]:
            if item["tool"] not in scout["tools"]:
                raise ScaffoldError(f"Unknown tool in {platform} targets: {item['tool']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", help="Blacklight repository root; inferred from the skill path by default")
    parser.add_argument("--write", action="store_true", help="Write changes; otherwise preview only")
    parser.add_argument("--skip-generate", action="store_true", help="Do not regenerate Scout C/C# target tables")
    subparsers = parser.add_subparsers(dest="operation", required=True)

    agent = subparsers.add_parser("add-agent", help="Add a new tool with root and config targets")
    agent.add_argument("--tool", required=True)
    agent.add_argument("--root-path", required=True)
    agent.add_argument("--config-path", required=True)

    artifact = subparsers.add_parser("add-artifact", help="Add an artifact to an existing tool")
    artifact.add_argument("--tool", required=True)
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--family", required=True)
    artifact.add_argument("--relative-path", required=True)
    artifact.add_argument("--path-kind", choices=PATH_KINDS, required=True)
    artifact.add_argument("--priority", choices=PRIORITIES, required=True)
    artifact.add_argument("--assessment-coverage", choices=COVERAGE_STATES, default="explicitly_assessed")
    artifact.add_argument("--rules-only", action="store_true")
    artifact.add_argument("--analyze-confirmed", action="store_true")
    artifact.add_argument("--evidence-source", default="blacklight.scout.endpoint_assessment", help="Existing Rules evidence key used for Rules-only entries")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    root = repository_root(args.repo_root)
    scout_path = root / "blacklight-scout" / "catalog" / "targets.json"
    rules_path = root / "blacklight-rules" / "catalog" / "confirmed_artifacts.json"
    try:
        scout = read_json(scout_path)
        rules = read_json(rules_path)
        summary = scaffold_agent(args, scout, rules) if args.operation == "add-agent" else scaffold_artifact(args, scout, rules)
        validate_catalogs(scout, rules)
        print(("WRITE" if args.write else "PREVIEW") + ": " + "; ".join(summary))
        if not args.write:
            print("No files changed. Re-run with --write to apply.")
            return 0
        scout_path.write_text(render_targets(scout), encoding="utf-8")
        rules_path.write_text(json.dumps(rules, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if not args.skip_generate:
            subprocess.run([sys.executable, str(root / "blacklight-scout" / "catalog" / "generate_targets.py")], check=True)
        return 0
    except (ScaffoldError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
