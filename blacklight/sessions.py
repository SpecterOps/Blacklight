from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .analyze import build_session_targeting_report, run_session_detail, run_session_high_value
from .common import host_context, safe_name, utc_now
from .session_input import SessionInputDiscovery, SessionSource, discover_session_inputs


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
    for index, row in enumerate(ranked, start=1):
        row["blacklight_rank"] = index
    return ranked


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
    scan_targets: list[dict[str, Any]],
    run_id: str,
    output: Path,
) -> list[str]:
    context = host_context()
    lines = [
        "Blacklight Session Report",
        f"Run ID: {run_id}",
        f"Collected UTC: {utc_now()}",
        f"Host: {context['host']}",
        f"OS: {context['os']}",
        f"Current user: {context['current_user']}",
        "",
        f"Input: {discovery.input_path}",
        "",
        "Summary:",
    ]
    for key, value in summary.items():
        if key == "indicator_category_counts":
            continue
        lines.append(f"- {key}: {value}")

    category_counts = summary.get("indicator_category_counts") or []
    if category_counts:
        lines.extend(["", "High-value indicator categories:"])
        for entry in category_counts:
            lines.append(f"- {entry['category']}: {entry['count']}")

    lines.extend(["", "Detected artifacts:"])
    for source in inventory["sources"]:
        lines.append(f"- {source['detected_tool']} / {source['artifact_type']} / {source['parse_status']}")
        lines.append(f"  {source['path']}")

    if inventory["issues"]:
        reason_counts: Counter[tuple[str, str]] = Counter()
        for issue in inventory["issues"]:
            reason_counts[(issue["status"], _normalize_reason(issue["reason"]))] += 1
        lines.extend(["", "Unparsed files (grouped by reason):"])
        for (status, reason), count in sorted(reason_counts.items(), key=lambda item: item[1], reverse=True):
            lines.append(f"- {status}: {count} file(s) - {reason}")

    lines.extend(["", "Ranked sessions:"])
    for row in ranked_sessions:
        title = row.get("session_title") or "(untitled)"
        lines.append(f"{row['blacklight_rank']}. {row['tool']} - score {row['blacklight_score']} - {title}")
        lines.append(
            f"   Requests: {row['request_count']}; responses: {row['response_count']}; "
            f"last activity: {row.get('last_activity') or 'unknown'}"
        )
        context_path = row.get("project_worktree_path") or "not present"
        indicators = ", ".join(row.get("indicator_categories", [])) or "none"
        lines.append(f"   Project/worktree: {context_path}; indicator categories: {indicators}")
        lines.append(f"   Source: {row.get('session_source_path') or row.get('primary_source_path')}")

    lines.extend(["", "External scanner targets:"])
    for target in scan_targets:
        lines.append(f"- {target['path']}")

    lines.extend(["", f"Reports: {output}"])
    return lines


def _write_session_report(
    discovery: SessionInputDiscovery,
    parse_statuses: dict[str, str],
    parse_details: dict[str, dict[str, Any]],
    ranked_sessions: list[dict[str, Any]],
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
        "scan_targets": scan_targets,
    }

    base_name = f"{safe_name(run_id)}_Session_Report"
    json_path = output / f"{base_name}.json"
    text_path = output / f"{base_name}.txt"
    json_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    text_lines = _session_report_text_lines(discovery, inventory, summary, ranked_sessions, scan_targets, run_id, output)
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
) -> dict[str, Any]:
    run_id = run_id or default_session_run_id()
    discovery = discover_session_inputs(
        Path(input_path).expanduser(),
        tool_hint=tool,
        max_files=max_files,
        max_file_size=max_file_size,
        includes=includes,
        excludes=excludes,
    )
    root = discovery.input_path
    output = Path(output_directory).expanduser().resolve() if output_directory else (root / "blacklight-reports" if root.is_dir() else root.parent / "blacklight-reports")
    if not discovery.sources:
        raise ValueError(f"No supported session artifacts were found under '{root}'.")
    output.mkdir(parents=True, exist_ok=True)
    detail = run_session_detail(
        run_id=run_id,
        output_directory=None,
        session_sources=discovery.sources,
        input_root=root,
    )
    high_value = run_session_high_value(
        run_id=run_id,
        output_directory=None,
        session_sources=discovery.sources,
        input_root=root,
    )
    targeting = build_session_targeting_report({"session_detail": detail})
    ranked_sessions = _rank_sessions(targeting, high_value)
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
    report_paths = _write_session_report(discovery, statuses, parse_details, ranked_sessions, scan_targets, summary, run_id, root, output)
    return {
        "run_id": run_id,
        "input_path": str(root),
        "output_directory": str(output),
        "summary": {
            "files_examined": discovery.files_examined,
            "supported_artifacts": len(discovery.sources),
            "parsed_artifacts": parsed_count,
            "ambiguous_files": discovery.ambiguous_count,
            "unsupported_files": discovery.unsupported_count,
            "parse_failures": parse_failure_count,
            "file_limit_reached": discovery.limit_reached,
            "skipped_link_count": discovery.skipped_links,
            "sessions_recovered": len(ranked_sessions),
        },
        "top_sessions": ranked_sessions[:10],
        "scan_targets": scan_targets,
        "reports": {"session_report": report_paths},
    }


def session_summary_lines(result: dict[str, Any]) -> list[str]:
    summary = result["summary"]
    lines = [
        "Blacklight Session Analysis",
        "",
        f"Input: {result['input_path']}",
        f"Files examined:       {summary['files_examined']}",
        f"Supported artifacts:  {summary['supported_artifacts']}",
        f"Parsed artifacts:     {summary['parsed_artifacts']}",
        f"Ambiguous files:      {summary['ambiguous_files']}",
        f"Parse failures:       {summary['parse_failures']}",
        f"File limit reached:   {summary['file_limit_reached']}",
        f"Links skipped:        {summary['skipped_link_count']}",
        f"Sessions recovered:   {summary['sessions_recovered']}",
        "",
        "Top sessions:",
    ]
    for row in result["top_sessions"]:
        title = row.get("session_title") or "(untitled)"
        lines.append(f"{row['blacklight_rank']}. {row['tool']} - score {row['blacklight_score']} - {title}")
        lines.append(f"   Requests: {row['request_count']}; responses: {row['response_count']}; last activity: {row.get('last_activity') or 'unknown'}")
        context = row.get("project_worktree_path") or "not present"
        indicators = ", ".join(row.get("indicator_categories", [])) or "none"
        lines.append(f"   Project/worktree: {context}; indicator categories: {indicators}")
        lines.append(f"   Source: {row.get('session_source_path') or row.get('primary_source_path')}")
    lines.extend(["", f"Reports: {result['output_directory']}"])
    return lines
