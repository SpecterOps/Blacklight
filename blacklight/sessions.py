from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .progress import ProgressCallback, ProgressEvent

from .analyze import build_session_targeting_report, run_session_detail, run_session_high_value
from .common import host_context, safe_name, utc_now
from .session_input import SessionInputDiscovery, SessionSource, discover_local_session_inputs, discover_session_inputs


def default_session_run_id() -> str:
    return datetime.now(timezone.utc).strftime("SESSIONS-%Y%m%dT%H%M%SZ")


def _finding_sessions(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for tool in result.get("tools", []):
        for finding in tool.get("findings", []):
            value = finding.get("value")
            if isinstance(value, dict) and isinstance(value.get("sessions"), list):
                rows.extend(value["sessions"])
    return rows


def _targeting_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    return _finding_sessions(result)


def _session_score(row: dict[str, Any], high_value: dict[str, Any] | None) -> int:
    requests = int(row.get("request_count") or 0)
    responses = int(row.get("response_count") or 0)
    tool_bytes = int(row.get("captured_tool_event_bytes") or 0)
    content_bytes = int(row.get("captured_total_bytes") or 0)
    score = min(25, requests * 2)
    score += min(20, responses * 2)
    score += min(15, int(math.log2(tool_bytes + 1) * 1.5))
    score += min(15, int(math.log2(content_bytes + 1) * 1.2))
    score += 5 if row.get("session_title") else 0
    score += 5 if row.get("project_worktree_path") else 0
    if row.get("response_status") == "present":
        score += 5
    if not row.get("parse_error_count"):
        score += 5
    if high_value:
        score += min(5, int(high_value.get("unique_high_value_score") or 0))
    return min(100, score)


def _category_names(row: dict[str, Any] | None) -> set[str]:
    if not row:
        return set()
    return {
        str(item.get("category"))
        for item in row.get("category_counts", [])
        if isinstance(item, dict) and int(item.get("count") or 0) > 0
    }


def _artifact_parse_status(detail: dict[str, Any]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for tool in detail.get("tools", []):
        for artifact in tool.get("artifacts", []):
            path = str(artifact.get("path") or "")
            if path:
                if artifact.get("parsed"):
                    statuses[path] = "parsed_partial" if _artifact_parse_error_count(artifact) else "parsed"
                else:
                    statuses[path] = "parse_failed"
    return statuses


def _artifact_parse_error_count(artifact: dict[str, Any]) -> int:
    metadata = artifact.get("metadata")
    if not isinstance(metadata, dict):
        return 0
    return sum(int(metadata.get(key) or 0) for key in ("parse_error_count", "malformed_blob_count"))


def _partial_parse_error_count(detail: dict[str, Any]) -> int:
    return sum(
        _artifact_parse_error_count(artifact)
        for tool in detail.get("tools", [])
        for artifact in tool.get("artifacts", [])
        if artifact.get("parsed")
    )


def _artifact_parse_details(detail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for tool in detail.get("tools", []):
        for artifact in tool.get("artifacts", []):
            path = str(artifact.get("path") or "")
            if path:
                details[path] = {"metadata": artifact.get("metadata"), "parse_error": artifact.get("parse_error")}
    return details


def _rank_sessions(targeting: dict[str, Any], high_value: dict[str, Any]) -> list[dict[str, Any]]:
    def normalized_tool(value: Any) -> str:
        return str(value).lower().replace(" code", "").replace(" ", "_")

    high_rows = {
        (normalized_tool(row.get("tool")), str(row.get("session_id"))): row
        for row in _finding_sessions(high_value)
    }
    ranked = []
    for row in _targeting_rows(targeting):
        high = high_rows.get((normalized_tool(row.get("tool")), str(row.get("session_id"))))
        enriched = dict(row)
        enriched["blacklight_score"] = _session_score(row, high)
        enriched["indicator_categories"] = sorted(_category_names(high))
        enriched["high_value_detail"] = high
        ranked.append(enriched)
    ranked.sort(
        key=lambda item: (
            int(item["blacklight_score"]),
            int(item.get("captured_total_bytes") or 0),
            str(item.get("last_activity") or ""),
        ),
        reverse=True,
    )
    tool_ranks: Counter[str] = Counter()
    for index, row in enumerate(ranked, start=1):
        row["blacklight_rank"] = index
        tool_ranks[str(row["tool"])] += 1
        row["tool_rank"] = tool_ranks[str(row["tool"])]
    return ranked


def _top_sessions_per_tool(ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = ("codex", "claude", "cursor", "antigravity_cli", "grok")
    return [row for tool in order for row in ranked if row["tool"] == tool and row["tool_rank"] <= 5]


def _source_scan_targets(
    sources: Iterable[SessionSource],
    ranked_sessions: list[dict[str, Any]],
    parse_statuses: dict[str, str],
) -> list[dict[str, Any]]:
    sessions_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ranked_sessions:
        for key in ("session_source_path", "primary_source_path"):
            if row.get(key):
                sessions_by_path[str(Path(str(row[key])).resolve())].append(row)
    targets = []
    for source in sources:
        path = str(source.path.resolve())
        rows = sessions_by_path.get(path, [])
        best_score = max((int(row["blacklight_score"]) for row in rows), default=0)
        categories = {category for row in rows for category in row.get("indicator_categories", [])}
        reasons = ["supported structured session artifact"]
        if best_score >= 60:
            reasons.append("high activity")
        if "internal_host" in categories or "network_target" in categories:
            reasons.append("internal host indicators")
        if "credential_secret" in categories:
            reasons.append("credential-like indicators")
        if categories & {"cloud_identity", "source_control"}:
            reasons.append("cloud or repository indicators")
        if any(row.get("project_worktree_path") for row in rows):
            reasons.append("project or worktree context")
        status = parse_statuses.get(path, "parse_failed")
        if status == "parse_failed":
            reasons.append("manual parser review required")
        targets.append(
            {
                "path": path,
                "tool": source.detected_tool.lower().replace(" code", "").replace(" ", "_"),
                "artifact_type": source.artifact_type,
                "session_count": len({(row.get("tool"), row.get("session_id")) for row in rows}),
                "parse_status": status,
                "blacklight_rank": min((int(row["blacklight_rank"]) for row in rows), default=None),
                "blacklight_score": best_score,
                "reasons": reasons,
            }
        )
    targets.sort(key=lambda item: (item["blacklight_score"], item["session_count"], item["path"]), reverse=True)
    return targets


_REASON_SUFFIX_RE = re.compile(r"\s*\(\d[^)]*\)$")


def _normalize_reason(reason: str) -> str:
    return _REASON_SUFFIX_RE.sub("", reason).strip()


def _high_value_category_counts(high_value: dict[str, Any]) -> list[dict[str, Any]]:
    totals: Counter[str] = Counter()
    for tool in high_value.get("tools", []):
        for finding in tool.get("findings", []):
            value = finding.get("value")
            if not isinstance(value, dict):
                continue
            for entry in value.get("aggregate", {}).get("category_counts", []):
                totals[str(entry.get("category"))] += int(entry.get("count") or 0)
    return [{"category": category, "count": count} for category, count in sorted(totals.items())]


def _report_summary(
    discovery: SessionInputDiscovery,
    parsed_count: int,
    parse_failure_count: int,
    sessions_recovered: int,
    detail: dict[str, Any],
    high_value: dict[str, Any],
    targeting: dict[str, Any],
) -> dict[str, Any]:
    summary = {
        "files_examined": discovery.files_examined,
        "session_candidates_examined": discovery.session_candidates_examined,
        "skipped_non_session_files": discovery.skipped_non_session_count,
        "supported_artifacts": len(discovery.sources),
        "parsed_artifacts": parsed_count,
        "ambiguous_files": discovery.ambiguous_count,
        "unsupported_files": discovery.unsupported_count,
        "parse_failures": parse_failure_count,
        "file_limit_reached": discovery.limit_reached,
        "skipped_link_count": discovery.skipped_links,
        "sessions_recovered": sessions_recovered,
    }
    detail_summary = detail.get("summary", {})
    high_value_summary = high_value.get("summary", {})
    targeting_summary = targeting.get("summary", {})
    summary.update(
        {
            "total_request_message_count": detail_summary.get("total_request_message_count"),
            "total_response_message_count": detail_summary.get("total_response_message_count"),
            "total_completed_turn_count": detail_summary.get("total_completed_turn_count"),
            "total_user_message_chunk_count": detail_summary.get("total_user_message_chunk_count"),
            "total_assistant_message_chunk_count": detail_summary.get("total_assistant_message_chunk_count"),
            "total_machine_context_count": detail_summary.get("total_machine_context_count"),
            "total_request_bytes": detail_summary.get("total_request_bytes"),
            "total_response_bytes": detail_summary.get("total_response_bytes"),
            "total_machine_context_bytes": detail_summary.get("total_machine_context_bytes"),
            "indicator_rule_count": high_value_summary.get("rule_count"),
            "total_indicator_count": high_value_summary.get("total_indicator_count"),
            "total_unique_indicator_count": high_value_summary.get("total_unique_indicator_count"),
            "total_match_count": high_value_summary.get("total_match_count"),
            "total_high_value_score": high_value_summary.get("total_high_value_score"),
            "total_unique_high_value_score": high_value_summary.get("total_unique_high_value_score"),
            "response_status_counts": targeting_summary.get("response_status_counts"),
            "indicator_category_counts": _high_value_category_counts(high_value),
        }
    )
    return summary


def _session_report_text_lines(
    discovery: SessionInputDiscovery,
    inventory: dict[str, Any],
    summary: dict[str, Any],
    ranked_sessions: list[dict[str, Any]],
    top_sessions: list[dict[str, Any]],
    scan_targets: list[dict[str, Any]],
    run_id: str,
    output: Path,
) -> list[str]:
    lines = [
        "Blacklight Session Report",
        f"Run ID: {run_id}",
        f"Input: {discovery.input_path}",
        f"Scope: {discovery.scan_scope}",
        "",
        "Summary:",
        f"- Files encountered: {summary['files_examined']}; session candidates: {summary['session_candidates_examined']}; skipped non-session files: {summary['skipped_non_session_files']}",
        f"- Artifacts: {summary['parsed_artifacts']}/{summary['supported_artifacts']} parsed; parse failures: {summary['parse_failures']}; ambiguous: {summary['ambiguous_files']}; unsupported: {summary['unsupported_files']}",
        f"- Sessions recovered: {summary['sessions_recovered']}; requests: {summary.get('total_request_message_count') or 0}; responses: {summary.get('total_response_message_count') or 0}",
    ]
    if summary.get("total_assistant_message_chunk_count"):
        lines.append(
            f"- Grok ACP: {summary['total_completed_turn_count']} completed turns; "
            f"{summary['total_user_message_chunk_count']} user chunks; "
            f"{summary['total_assistant_message_chunk_count']} assistant chunks"
        )
    if summary.get("file_limit_reached"):
        lines.append("- Partial result: candidate file limit reached")
    if discovery.local_roots:
        absent = [name for name, info in discovery.local_roots.items() if info["status"] != "present"]
        if absent:
            lines.append(f"- Absent roots: {', '.join(absent)}")

    warning_counts: Counter[tuple[str, str]] = Counter()
    for issue in inventory["issues"]:
        if issue["status"] != "skipped_non_session":
            warning_counts[(issue["status"], _normalize_reason(issue["reason"]))] += 1
    for source in inventory["sources"]:
        if source["parse_status"] != "parsed":
            warning_counts[(source["parse_status"], source.get("parse_error") or "recognized artifact had parse errors")] += 1
    if warning_counts:
        lines.extend(["", "Warnings:"])
        for (status, reason), count in warning_counts.most_common():
            lines.append(f"- {status}: {count} file(s) - {reason}")

    lines.extend(["", f"Top sessions ({len(top_sessions)} of {len(ranked_sessions)}; up to 5 per tool):"])
    for tool in dict.fromkeys(row["tool"] for row in top_sessions):
        lines.append(f"{tool}:")
        for row in (row for row in top_sessions if row["tool"] == tool):
            title = " ".join(str(row.get("session_title") or "(untitled)").split())[:100]
            lines.append(f"  {row['tool_rank']}. score {row['blacklight_score']} | {row['request_count']} req / {row['response_count']} resp | {title}")

    lines.extend(["", "Reports:",
                  f"- JSON inventory and {len(scan_targets)} scanner targets: {output / (safe_name(run_id) + '_Session_Report.json')}",
                  f"- Text summary: {output / (safe_name(run_id) + '_Session_Report.txt')}"])
    return lines


def _write_session_report(
    discovery: SessionInputDiscovery,
    parse_statuses: dict[str, str],
    parse_details: dict[str, dict[str, Any]],
    ranked_sessions: list[dict[str, Any]],
    top_sessions: list[dict[str, Any]],
    scan_targets: list[dict[str, Any]],
    summary: dict[str, Any],
    run_id: str,
    root: Path,
    output: Path,
) -> dict[str, str]:
    inventory = discovery.to_dict()
    for source in inventory["sources"]:
        resolved_path = str(Path(source["path"]).resolve())
        source["parse_status"] = parse_statuses.get(resolved_path, "parse_failed")
        details = parse_details.get(resolved_path)
        if details:
            source["parse_metadata"] = details.get("metadata")
            source["parse_error"] = details.get("parse_error")

    envelope = {
        "run_id": run_id,
        "collected_at_utc": utc_now(),
        **host_context(),
        "input_path": str(root),
        "scan_scope": discovery.scan_scope,
        "output_directory": str(output),
        "content_policy": {
            "raw_message_text_included": False,
            "raw_credential_values_included": False,
            "semantic_parsing_included": True,
            "sensitivity_scoring_included": True,
            "config_values_included": False,
            "session_titles_included": True,
        },
        "summary": summary,
        "artifact_inventory": inventory,
        "sessions": ranked_sessions,
        "top_sessions": top_sessions,
        "scan_targets": scan_targets,
    }

    base_name = f"{safe_name(run_id)}_Session_Report"
    json_path = output / f"{base_name}.json"
    text_path = output / f"{base_name}.txt"
    json_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    text_lines = _session_report_text_lines(discovery, inventory, summary, ranked_sessions, top_sessions, scan_targets, run_id, output)
    text_path.write_text("\n".join(text_lines) + "\n", encoding="utf-8")
    return {"json": str(json_path), "text": str(text_path)}


def run_sessions_analysis(
    input_path: str | Path,
    *,
    tool: str | None = None,
    output_directory: str | Path | None = None,
    run_id: str | None = None,
    max_files: int = 10_000,
    max_file_size: int = 512 * 1024 * 1024,
    includes: Iterable[str] = (),
    excludes: Iterable[str] = (),
    local_mode: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    run_id = run_id or default_session_run_id()
    discover = discover_local_session_inputs if local_mode else discover_session_inputs
    discovery = discover(Path(input_path).expanduser(), **({"tool": tool} if local_mode else {"tool_hint": tool}),
                         max_files=max_files, max_file_size=max_file_size, includes=includes, excludes=excludes,
                         progress_callback=progress_callback)
    root = discovery.input_path
    output = Path(output_directory).expanduser().resolve() if output_directory else (root / "blacklight-reports" if root.is_dir() else root.parent / "blacklight-reports")
    if not discovery.sources and not local_mode:
        raise ValueError(f"No supported session artifacts were found under '{root}'.")
    output.mkdir(parents=True, exist_ok=True)
    detail = run_session_detail(
        run_id=run_id,
        output_directory=None,
        session_sources=discovery.sources,
        progress_callback=progress_callback,
        input_root=root,
    )
    high_value = run_session_high_value(
        run_id=run_id,
        output_directory=None,
        session_sources=discovery.sources,
        progress_callback=progress_callback,
        input_root=root,
    )
    if progress_callback is not None:
        progress_callback(ProgressEvent("Writing reports"))
    targeting = build_session_targeting_report({"session_detail": detail})
    ranked_sessions = _rank_sessions(targeting, high_value)
    top_sessions = _top_sessions_per_tool(ranked_sessions)
    statuses = _artifact_parse_status(detail)
    scan_targets = _source_scan_targets(discovery.sources, ranked_sessions, statuses)
    parsed_count = sum(status in {"parsed", "parsed_partial"} for status in statuses.values())
    parse_failure_count = (
        discovery.parse_failed_count
        + sum(status == "parse_failed" for status in statuses.values())
        + _partial_parse_error_count(detail)
    )
    summary = _report_summary(discovery, parsed_count, parse_failure_count, len(ranked_sessions), detail, high_value, targeting)
    parse_details = _artifact_parse_details(detail)
    report_paths = _write_session_report(discovery, statuses, parse_details, ranked_sessions, top_sessions, scan_targets, summary, run_id, root, output)
    return {
        "run_id": run_id,
        "input_path": str(root),
        "scan_scope": discovery.scan_scope,
        "local_roots": discovery.local_roots,
        "output_directory": str(output),
        "summary": {
            "files_examined": discovery.files_examined,
            "session_candidates_examined": discovery.session_candidates_examined,
            "skipped_non_session_files": discovery.skipped_non_session_count,
            "supported_artifacts": len(discovery.sources),
            "parsed_artifacts": parsed_count,
            "ambiguous_files": discovery.ambiguous_count,
            "unsupported_files": discovery.unsupported_count,
            "parse_failures": parse_failure_count,
            "file_limit_reached": discovery.limit_reached,
            "skipped_link_count": discovery.skipped_links,
            "sessions_recovered": len(ranked_sessions),
        },
        "top_sessions": top_sessions,
        "scan_targets": scan_targets,
        "reports": {"session_report": report_paths},
    }


def session_summary_lines(result: dict[str, Any]) -> list[str]:
    summary = result["summary"]
    lines = [
        "Blacklight Session Analysis",
        "",
        f"Input: {result['input_path']}",
        f"Scope: {result['scan_scope']}",
        f"Files examined:       {summary['files_examined']}",
        f"Session candidates:   {summary['session_candidates_examined']}",
        f"Non-session skipped:  {summary['skipped_non_session_files']}",
        f"Supported artifacts:  {summary['supported_artifacts']}",
        f"Parsed artifacts:     {summary['parsed_artifacts']}",
        f"Ambiguous files:      {summary['ambiguous_files']}",
        f"Parse failures:       {summary['parse_failures']}",
        f"File limit reached:   {summary['file_limit_reached']}",
        f"Links skipped:        {summary['skipped_link_count']}",
        f"Sessions recovered:   {summary['sessions_recovered']}",
        "",
        "Top sessions (up to 5 per tool):",
    ]
    if summary["file_limit_reached"]:
        lines.append("Partial result: candidate file limit reached")
    absent = [name for name, info in result.get("local_roots", {}).items() if info["status"] != "present"]
    if absent:
        lines.append(f"Absent roots: {', '.join(absent)}")
    for tool in dict.fromkeys(row["tool"] for row in result["top_sessions"]):
        lines.append(f"{tool}:")
        for row in (row for row in result["top_sessions"] if row["tool"] == tool):
            title = " ".join(str(row.get("session_title") or "(untitled)").split())[:100]
            lines.append(f"  {row['tool_rank']}. score {row['blacklight_score']} | {row['request_count']} req / {row['response_count']} resp | {title}")
    lines.extend(["", f"Reports: {result['output_directory']}"])
    return lines
