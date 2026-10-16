from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import blacklight.analyze as analyze_module
import hashlib

from blacklight.analyze import INDICATOR_RULES, _collect_grok_sessions, _collect_sessions, run_session_detail
from blacklight.cli import main as cli_main
from blacklight.session_input import discover_local_session_inputs, discover_session_inputs
from blacklight.sessions import run_sessions_analysis, session_summary_lines


class SessionInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_jsonl(path: Path, records: list[dict[str, object]], *, malformed: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(record) for record in records]
        if malformed:
            lines.insert(1, "{truncated")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def _write_cursor_store(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("create table blobs (id text primary key, data blob)")
            connection.execute("create table meta (key text primary key, value text)")
            meta = {"agentId": "cursor-one", "name": "Cursor session", "createdAt": 1776134919156}
            connection.execute("insert into meta values ('0', ?)", (json.dumps(meta).encode("utf-8").hex(),))
            connection.execute("insert into blobs values ('user', ?)", (json.dumps({"role": "user", "content": "inspect 10.1.2.3"}).encode("utf-8"),))
            connection.execute("insert into blobs values ('assistant', ?)", (json.dumps({"role": "assistant", "content": "done"}).encode("utf-8"),))
            connection.commit()

    @staticmethod
    def _write_antigravity_store(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("create table conversation_summaries (conversation_id text primary key, title text, summary blob)")
            connection.execute("insert into conversation_summaries values ('ag-one', 'Conversation', X'00')")
            connection.commit()

    def test_discovery_uses_schema_before_filename_and_recognizes_sqlite(self) -> None:
        renamed = self.root / "download_00042.bin"
        self._write_jsonl(
            renamed,
            [
                {"timestamp": "2026-07-14T10:00:00Z", "type": "session_meta", "payload": {"id": "codex-renamed", "cwd": "C:/work"}},
                {"timestamp": "2026-07-14T10:01:00Z", "type": "event_msg", "payload": {"role": "user", "content": "hello"}},
            ],
        )
        claude = self.root / "task-2" / "result.jsonl"
        self._write_jsonl(claude, [{"sessionId": "claude-one", "uuid": "m1", "parentUuid": None, "role": "user", "content": "hello"}])
        cursor = self.root / "task-3" / "renamed.db"
        self._write_cursor_store(cursor)
        antigravity = self.root / "task-4" / "transcript_full.jsonl"
        self._write_jsonl(antigravity, [{"role": "user", "timestamp": "2026-07-14T10:02:00Z", "content": "hello"}])
        antigravity_db = self.root / "task-5" / "download_007.bin"
        self._write_antigravity_store(antigravity_db)

        discovery = discover_session_inputs(self.root)
        by_path = {source.path: source for source in discovery.sources}
        self.assertEqual(by_path[renamed.resolve()].detected_tool, "Codex")
        self.assertEqual(by_path[renamed.resolve()].confidence, "strong")
        self.assertEqual(by_path[claude.resolve()].detected_tool, "Claude Code")
        self.assertEqual(by_path[cursor.resolve()].artifact_type, "chat_store_sqlite")
        self.assertEqual(by_path[antigravity.resolve()].detected_tool, "Antigravity CLI")
        self.assertEqual(by_path[antigravity_db.resolve()].artifact_type, "conversation_store_sqlite")

    def test_codex_envelopes_use_payload_identity_and_roles(self) -> None:
        rollout = self.root / "download_00042.bin"
        self._write_jsonl(
            rollout,
            [
                {"timestamp": "2026-07-14T10:00:00Z", "type": "session_meta", "payload": {"id": "codex-envelope", "cwd": "C:/work"}},
                {"timestamp": "2026-07-14T10:00:01Z", "type": "turn_context", "payload": {"cwd": "C:/work"}},
                {"timestamp": "2026-07-14T10:00:02Z", "type": "event_msg", "payload": {"type": "user_message", "message": "inspect 10.1.2.3"}},
                {"timestamp": "2026-07-14T10:00:03Z", "type": "response_item", "payload": {"type": "function_call", "name": "shell", "arguments": "{}"}},
                {"timestamp": "2026-07-14T10:00:04Z", "type": "response_item", "payload": {"type": "function_call_output", "output": "tool result"}},
                {"timestamp": "2026-07-14T10:00:05Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]}},
            ],
        )

        result = run_sessions_analysis(rollout, run_id="RUN-CODEX-ENVELOPE")

        self.assertEqual(result["summary"]["sessions_recovered"], 1)
        session = result["top_sessions"][0]
        self.assertEqual(session["session_id"], "codex-envelope")
        self.assertEqual(session["request_count"], 1)
        self.assertEqual(session["response_count"], 1)
        self.assertGreater(session["captured_tool_event_bytes"], 0)
        detail_rows, _, _ = _collect_sessions("Codex", [rollout])
        self.assertEqual(detail_rows[0]["tool_event_count"], 2)
        report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text(encoding="utf-8"))
        detail = report["sessions"][0]["high_value_detail"]
        self.assertEqual(detail["request_fragment_count"], 1)
        self.assertEqual(detail["response_fragment_count"], 1)
        self.assertEqual(detail["tool_event_fragment_count"], 1)

    def test_ambiguous_files_are_not_guessed_and_hint_does_not_override_schema(self) -> None:
        generic = self.root / "download.jsonl"
        self._write_jsonl(generic, [{"role": "user", "content": "generic record"}])
        discovery = discover_session_inputs(self.root)
        self.assertEqual(discovery.ambiguous_count, 1)
        self.assertEqual(discovery.sources, [])

        hinted = discover_session_inputs(self.root, tool_hint="codex")
        self.assertEqual(hinted.sources[0].detected_tool, "Codex")

        strong_claude = self.root / "strong.jsonl"
        self._write_jsonl(strong_claude, [{"sessionId": "claude", "parentUuid": "root", "content": "hello"}])
        incompatible = discover_session_inputs(strong_claude, tool_hint="codex")
        self.assertEqual(incompatible.issues[0].status, "unsupported")

    def test_flat_codex_session_index_is_detected_and_keeps_its_title(self) -> None:
        index = self.root / "session_index.jsonl"
        self._write_jsonl(index, [{"id": "codex-index", "thread_name": "Release checklist", "updated_at": "2026-07-14T10:00:00Z"}])

        discovery = discover_session_inputs(index)
        self.assertEqual(discovery.sources[0].detected_tool, "Codex")
        self.assertEqual(discovery.sources[0].artifact_type, "session_index_jsonl")
        result = run_sessions_analysis(index, run_id="RUN-CODEX-INDEX")
        session = result["top_sessions"][0]
        self.assertEqual(session["session_id"], "codex-index")
        self.assertEqual(session["session_title"], "Release checklist")
        self.assertEqual(session["response_status"], "absent_index_only")

    def test_nested_duplicate_names_remain_distinct_sources(self) -> None:
        first = self.root / "download-1" / "history.jsonl"
        second = self.root / "download-2" / "history.jsonl"
        self._write_jsonl(first, [{"session_id": "one", "role": "user", "content": "first"}])
        self._write_jsonl(second, [{"session_id": "two", "role": "user", "content": "second"}])
        discovery = discover_session_inputs(self.root)
        self.assertEqual({source.path for source in discovery.sources}, {first.resolve(), second.resolve()})

    def test_empty_malformed_and_unsupported_databases_are_reported(self) -> None:
        empty = self.root / "empty.jsonl"
        empty.write_bytes(b"")
        corrupt_sqlite = self.root / "corrupt.db"
        corrupt_sqlite.write_bytes(b"SQLite format 3\x00not-a-database")
        unsupported_db = self.root / "unsupported.db"
        with closing(sqlite3.connect(unsupported_db)) as connection:
            connection.execute("create table notes (value text)")
            connection.commit()

        discovery = discover_session_inputs(self.root)
        statuses = {issue.path: issue.status for issue in discovery.issues}
        self.assertEqual(statuses[empty.resolve()], "parse_failed")
        self.assertEqual(statuses[corrupt_sqlite.resolve()], "parse_failed")
        self.assertEqual(statuses[unsupported_db.resolve()], "unsupported")

    def test_antigravity_sqlite_is_metadata_only_in_session_analysis(self) -> None:
        store = self.root / "renamed-antigravity.bin"
        self._write_antigravity_store(store)

        result = run_sessions_analysis(store, run_id="RUN-AG-SQLITE")

        self.assertEqual(result["summary"]["supported_artifacts"], 1)
        self.assertEqual(result["summary"]["parsed_artifacts"], 1)
        self.assertEqual(result["summary"]["sessions_recovered"], 0)
        report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text(encoding="utf-8"))
        artifact_metadata = report["artifact_inventory"]["sources"][0]["parse_metadata"]
        self.assertFalse(artifact_metadata["body_columns_read"])
        self.assertEqual(artifact_metadata["table_counts"], {"conversation_summaries": 1})

    def test_limits_and_globs_bound_discovery(self) -> None:
        included = self.root / "keep" / "codex-session.jsonl"
        excluded = self.root / "skip" / "codex-session.jsonl"
        oversized = self.root / "keep" / "large-codex.jsonl"
        self._write_jsonl(included, [{"session_id": "keep", "role": "user", "content": "hello"}])
        self._write_jsonl(excluded, [{"session_id": "skip", "role": "user", "content": "hello"}])
        self._write_jsonl(oversized, [{"session_id": "large", "role": "user", "content": "x" * 200}])

        discovery = discover_session_inputs(self.root, includes=["keep/*"], excludes=["*large*"], max_files=1)
        self.assertEqual([source.path for source in discovery.sources], [included.resolve()])
        size_limited = discover_session_inputs(oversized, max_file_size=10)
        self.assertEqual(size_limited.issues[0].status, "unsupported")

    def test_top_level_symlink_input_is_rejected_before_resolution(self) -> None:
        outside = self.root / "outside" / "history.jsonl"
        self._write_jsonl(outside, [{"session_id": "outside", "role": "user", "content": "outside"}])
        selected = self.root / "selected.jsonl"
        try:
            selected.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
            discover_session_inputs(selected)
        with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
            run_sessions_analysis(selected, run_id="RUN-SYMLINK")

    def test_cursor_analysis_does_not_copy_adjacent_sidecars(self) -> None:
        store = self.root / "store.db"
        self._write_cursor_store(store)
        Path(f"{store}-wal").write_bytes(b"")
        Path(f"{store}-shm").write_bytes(b"")
        copied_sources: list[Path] = []
        copy2 = analyze_module.shutil.copy2

        def tracked_copy(source: str | Path, destination: str | Path, *args: object, **kwargs: object) -> str:
            copied_sources.append(Path(source).resolve())
            return str(copy2(source, destination, *args, **kwargs))

        with patch("blacklight.analyze.shutil.copy2", side_effect=tracked_copy):
            result = run_sessions_analysis(store, run_id="RUN-CURSOR-NO-SIDECARS")

        self.assertEqual(result["summary"]["sessions_recovered"], 1)
        self.assertEqual(copied_sources, [store.resolve(), store.resolve()])

    def test_targeting_does_not_discover_unselected_sibling_sessions(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        history = self.root / ".codex" / "history.jsonl"
        sibling = self.root / ".codex" / "sessions" / "2026" / "07" / "24" / f"rollout-{session_id}.jsonl"
        self._write_jsonl(history, [{"session_id": session_id, "role": "user", "content": "aggregate"}])
        self._write_jsonl(sibling, [{"session_id": session_id, "role": "user", "content": "unselected"}])

        result = run_sessions_analysis(history, run_id="RUN-SELECTED-HISTORY")

        self.assertEqual(Path(result["top_sessions"][0]["session_source_path"]), history.resolve())
        self.assertEqual({Path(target["path"]) for target in result["scan_targets"]}, {history.resolve()})
        self.assertNotEqual(Path(result["top_sessions"][0]["session_source_path"]), sibling.resolve())
        self.assertNotIn(str(sibling.resolve()), json.dumps(result))

    def test_file_limit_is_bounded_and_reported(self) -> None:
        downloads = self.root / "downloads"
        self._write_jsonl(downloads / "codex-first.jsonl", [{"session_id": "first", "role": "user", "content": "first"}])
        self._write_jsonl(downloads / "codex-second.jsonl", [{"session_id": "second", "role": "user", "content": "second"}])

        result = run_sessions_analysis(downloads, run_id="RUN-LIMIT", max_files=1)

        self.assertTrue(result["summary"]["file_limit_reached"])
        self.assertEqual(result["summary"]["files_examined"], 1)
        report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text(encoding="utf-8"))
        self.assertTrue(report["summary"]["file_limit_reached"])
        self.assertTrue(report["artifact_inventory"]["file_limit_reached"])
        self.assertEqual(report["artifact_inventory"]["skipped_link_count"], 0)

    def test_claude_cursor_and_antigravity_reach_the_shared_session_pipeline(self) -> None:
        claude = self.root / "claude-session.jsonl"
        self._write_jsonl(
            claude,
            [
                {"sessionId": "claude-one", "parentUuid": None, "type": "user", "userType": "external", "message": {"role": "user", "content": "inspect repository"}},
                {"sessionId": "claude-one", "parentUuid": "m1", "type": "assistant", "message": {"role": "assistant", "content": "done"}},
            ],
        )
        cursor = self.root / "cursor-chat.db"
        self._write_cursor_store(cursor)
        antigravity = self.root / "transcript_full.jsonl"
        self._write_jsonl(
            antigravity,
            [
                {"role": "user", "timestamp": "2026-07-14T10:02:00Z", "content": "inspect internal host"},
                {"role": "assistant", "timestamp": "2026-07-14T10:03:00Z", "content": "done"},
            ],
        )

        result = run_sessions_analysis(self.root, run_id="RUN-MIXED")

        self.assertEqual(result["summary"]["supported_artifacts"], 3)
        self.assertEqual(
            {row["tool"] for row in result["top_sessions"]},
            {"claude", "cursor", "antigravity_cli"},
        )
        self.assertTrue(all(row["request_count"] == 1 for row in result["top_sessions"]))
        self.assertTrue(all(row["response_count"] == 1 for row in result["top_sessions"]))

    def test_claude_machine_records_are_not_counted_as_human_requests(self) -> None:
        claude = self.root / "claude-machine-records.jsonl"
        self._write_jsonl(
            claude,
            [
                {"sessionId": "claude-one", "type": "user", "userType": "external", "message": {"role": "user", "content": "hello"}},
                {"sessionId": "claude-one", "type": "assistant", "message": {"role": "assistant", "content": "done"}},
                {"sessionId": "claude-one", "type": "progress", "data": {"status": "running"}},
                {"sessionId": "claude-one", "type": "file-history-snapshot", "snapshot": {}},
            ],
        )

        rows, _, _ = _collect_sessions("Claude Code", [claude])

        self.assertEqual(rows[0]["request_message_count"], 1)
        self.assertEqual(rows[0]["response_message_count"], 1)
        self.assertEqual(rows[0]["machine_context_count"], 2)

    def test_flat_cursor_transcript_does_not_gain_synthetic_project_context(self) -> None:
        transcript = self.root / "cursor-transcript.jsonl"
        self._write_jsonl(
            transcript,
            [
                {"agentId": "cursor-flat", "role": "user", "timestamp": "2026-07-14T10:00:00Z", "content": "hello"},
                {"agentId": "cursor-flat", "role": "assistant", "timestamp": "2026-07-14T10:01:00Z", "content": "done"},
            ],
        )
        result = run_sessions_analysis(self.root, run_id="RUN-CURSOR-FLAT")
        cursor_row = next(row for row in result["top_sessions"] if row["tool"] == "cursor")
        self.assertIsNone(cursor_row["project_worktree_path"])

    def test_sessions_analysis_writes_reports_and_preserves_real_paths(self) -> None:
        codex = self.root / "job-123" / "download_00042.bin"
        self._write_jsonl(
            codex,
            [
                {"session_id": "codex-one", "timestamp": "2026-07-14T10:00:00Z", "role": "user", "cwd": "C:/repo", "content": "check token=ABCD1234SECRET and 10.1.2.3"},
                {"session_id": "codex-one", "timestamp": "2026-07-14T10:01:00Z", "role": "assistant", "content": "done"},
            ],
            malformed=True,
        )
        unsupported = self.root / "notes.md"
        unsupported.write_text("not a session", encoding="utf-8")

        result = run_sessions_analysis(self.root, run_id="RUN-DOWNLOADS")
        self.assertEqual(result["summary"]["supported_artifacts"], 1)
        self.assertEqual(result["summary"]["sessions_recovered"], 1)
        self.assertEqual(result["summary"]["unsupported_files"], 1)
        self.assertEqual(result["summary"]["parse_failures"], 1)
        self.assertEqual(Path(result["top_sessions"][0]["session_source_path"]), codex.resolve())
        self.assertGreater(result["top_sessions"][0]["blacklight_score"], 0)

        report_root = self.root / "blacklight-reports"
        report_files = list(report_root.glob("*"))
        self.assertEqual(
            {path.name for path in report_files},
            {"RUN-DOWNLOADS_Session_Report.json", "RUN-DOWNLOADS_Session_Report.txt"},
        )

        report = json.loads((report_root / "RUN-DOWNLOADS_Session_Report.json").read_text(encoding="utf-8"))
        report_text = (report_root / "RUN-DOWNLOADS_Session_Report.txt").read_text(encoding="utf-8")
        self.assertNotIn(str(codex.resolve()), report_text)
        self.assertIn("Top sessions (1 of 1; up to 5 per tool)", report_text)
        self.assertEqual(report["summary"]["parse_failures"], 1)

        inventory_paths = {Path(source["path"]) for source in report["artifact_inventory"]["sources"]}
        self.assertEqual(inventory_paths, {codex.resolve()})
        self.assertFalse(any("blacklight-sessions-" in str(path) for path in inventory_paths))

        targets = report["scan_targets"]
        self.assertEqual(targets[0]["path"], str(codex.resolve()))
        self.assertEqual(targets[0]["parse_status"], "parsed_partial")
        self.assertIn("credential-like indicators", targets[0]["reasons"])

        session_row = report["sessions"][0]
        self.assertIn("credential_secret", session_row["indicator_categories"])
        self.assertIsNotNone(session_row["high_value_detail"])

        with redirect_stdout(io.StringIO()) as output:
            rc = cli_main(["sessions", str(self.root), "--run-id", "RUN-CLI"])
        self.assertEqual(rc, 0)
        self.assertIn("Blacklight Session Analysis", output.getvalue())

    def test_renamed_grok_chat_artifacts_are_detected_without_a_grok_path(self) -> None:
        folder = self.root / "incoming"
        acp = folder / "download_0001.bin"
        chat = folder / "download_0002.bin"
        prompts = folder / "download_0003.bin"
        summary = folder / "card.json"
        self._write_jsonl(
            acp,
            [
                {
                    "timestamp": "2026-07-14T10:00:00Z",
                    "method": "session/update",
                    "params": {
                        "sessionId": "session-alpha",
                        "update": {"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": "hello"}},
                    },
                },
                {
                    "timestamp": "2026-07-14T10:00:01Z",
                    "method": "_x.ai/session/update",
                    "params": {
                        "sessionId": "session-alpha",
                        "update": {"sessionUpdate": "turn_completed", "stop_reason": "end_turn"},
                    },
                },
            ],
        )
        self._write_jsonl(
            chat,
            [
                {"type": "system", "content": "You are a coding agent."},
                {"type": "user", "content": [{"type": "text", "text": "hello"}]},
                {
                    "type": "assistant",
                    "content": "done",
                    "tool_calls": [{"id": "call-1", "name": "bash", "arguments": "{\"command\":\"echo hi\"}"}],
                },
            ],
        )
        self._write_jsonl(
            prompts,
            [{"timestamp": "2026-07-14T10:00:00Z", "session_id": "session-alpha", "prompt": "hello", "is_bash": False}],
        )
        summary.parent.mkdir(parents=True, exist_ok=True)
        summary.write_text(
            json.dumps(
                {
                    "info": {"id": "session-alpha", "cwd": "D:/lab/widget"},
                    "created_at": "2026-07-14T09:00:00Z",
                    "updated_at": "2026-07-14T10:00:00Z",
                    "generated_title": "Widget inventory",
                    "session_summary": "Shorter summary",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        generic = folder / "notes.jsonl"
        self._write_jsonl(generic, [{"role": "user", "content": "generic record"}])
        codex = folder / "rollout.bin"
        self._write_jsonl(codex, [{"timestamp": "2026-07-14T10:00:00Z", "type": "session_meta", "payload": {"id": "codex-one", "cwd": "D:/work"}}])
        claude = folder / "claude.bin"
        self._write_jsonl(claude, [{"sessionId": "claude-one", "parentUuid": None, "type": "user", "content": "hello"}])

        discovery = discover_session_inputs(folder)
        by_name = {source.path.name: source for source in discovery.sources}
        self.assertEqual(by_name["download_0001.bin"].detected_tool, "Grok")
        self.assertEqual(by_name["download_0001.bin"].artifact_type, "grok_acp_jsonl")
        self.assertEqual(by_name["download_0002.bin"].detected_tool, "Grok")
        self.assertEqual(by_name["download_0002.bin"].artifact_type, "grok_chat_history_jsonl")
        self.assertEqual(by_name["download_0003.bin"].detected_tool, "Grok")
        self.assertEqual(by_name["download_0003.bin"].artifact_type, "grok_prompt_history_jsonl")
        self.assertEqual(by_name["card.json"].detected_tool, "Grok")
        self.assertEqual(by_name["card.json"].artifact_type, "grok_summary_json")
        self.assertEqual(by_name["card.json"].format, "JSON")
        self.assertEqual(by_name["rollout.bin"].detected_tool, "Codex")
        self.assertEqual(by_name["claude.bin"].detected_tool, "Claude Code")
        self.assertTrue(any(issue.path.name == "notes.jsonl" and issue.status == "ambiguous" for issue in discovery.issues))
        self.assertNotIn(".grok", str(folder))

    def test_renamed_grok_chat_without_tool_calls_uses_message_schema(self) -> None:
        renamed = self.root / "incoming" / "download_0042.bin"
        self._write_jsonl(renamed, [
            {"type": "system", "content": "agent context"},
            {"type": "user", "content": "hello"},
        ])
        discovery = discover_session_inputs(renamed)
        self.assertEqual(discovery.sources[0].artifact_type, "grok_chat_history_jsonl")
        result = run_sessions_analysis(renamed, run_id="RUN-GROK-RENAMED-CHAT")
        self.assertEqual(result["summary"]["sessions_recovered"], 1)
        self.assertEqual(result["top_sessions"][0]["request_count"], 1)

    def test_grok_tool_hint_only_disambiguates(self) -> None:
        generic = self.root / "notes.jsonl"
        self._write_jsonl(generic, [{"role": "user", "content": "generic record"}])
        self.assertEqual(discover_session_inputs(generic).sources, [])
        self.assertEqual(discover_session_inputs(generic, tool_hint="grok").sources[0].detected_tool, "Grok")
        self.assertEqual(discover_session_inputs(generic, tool_hint="grok-cli").sources[0].detected_tool, "Grok")

        codex = self.root / "rollout.bin"
        self._write_jsonl(codex, [{"timestamp": "2026-07-14T10:00:00Z", "type": "session_meta", "payload": {"id": "codex-one"}}])
        claude = self.root / "claude.bin"
        self._write_jsonl(claude, [{"sessionId": "claude-one", "parentUuid": "root", "content": "hello"}])
        self.assertEqual(discover_session_inputs(codex, tool_hint="grok").issues[0].status, "unsupported")
        self.assertEqual(discover_session_inputs(claude, tool_hint="grok-cli").issues[0].status, "unsupported")

    def test_grok_summary_is_index_only_and_keeps_generated_title(self) -> None:
        summary = self.root / "card.json"
        summary.write_text(
            json.dumps(
                {
                    "info": {"id": "session-index", "cwd": "D:/lab/widget"},
                    "created_at": "2026-07-14T09:00:00Z",
                    "updated_at": "2026-07-14T10:00:00Z",
                    "generated_title": "Widget inventory",
                    "session_summary": "Shorter summary",
                    "last_turn_summary": "Last turn recap should not win",
                    "git_root_dir": "D:/lab",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        fallback = self.root / "other" / "card.json"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.write_text(
            json.dumps(
                {
                    "info": {"id": "session-fallback", "cwd": "D:/lab/fallback"},
                    "created_at": "2026-07-14T09:00:00Z",
                    "updated_at": "2026-07-14T11:00:00Z",
                    "session_summary": "Fallback summary",
                    "last_turn_summary": "Recap should not win",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        result = run_sessions_analysis(self.root, run_id="RUN-GROK-INDEX")
        by_id = {row["session_id"]: row for row in result["top_sessions"]}
        self.assertEqual(set(by_id), {"session-index", "session-fallback"})
        self.assertEqual(by_id["session-index"]["tool"], "grok")
        self.assertEqual(by_id["session-index"]["session_title"], "Widget inventory")
        self.assertEqual(by_id["session-index"]["project_worktree_path"], "D:/lab/widget")
        self.assertEqual(by_id["session-index"]["request_count"], 0)
        self.assertEqual(by_id["session-index"]["response_count"], 0)
        self.assertEqual(by_id["session-index"]["response_status"], "absent_index_only")
        self.assertEqual(by_id["session-fallback"]["session_title"], "Fallback summary")
        self.assertNotIn("Last turn recap should not win", json.dumps(result))
        self.assertNotIn("Recap should not win", json.dumps(result))

    def test_grok_acp_counts_once_when_redundant_copies_are_selected(self) -> None:
        session_id = "session-alpha"
        folder = self.root / "bundle" / session_id
        secret_prompt = "inspect the widget"
        self._write_jsonl(
            folder / "updates.jsonl",
            [
                self._grok_acp(session_id, "user_message_chunk", secret_prompt, "2026-07-14T10:00:00Z"),
                self._grok_acp(session_id, "agent_thought_chunk", "thinking privately", "2026-07-14T10:00:01Z"),
                self._grok_acp(session_id, "agent_message_chunk", "the widget is ready", "2026-07-14T10:00:02Z"),
                self._grok_acp(session_id, "tool_call", "", "2026-07-14T10:00:03Z", raw_input={"command": "echo hello"}),
                self._grok_acp(session_id, "tool_call_update", "", "2026-07-14T10:00:04Z", raw_output={"stdout": "hello"}),
                {
                    "timestamp": "2026-07-14T10:00:05Z",
                    "method": "_x.ai/session/update",
                    "params": {"sessionId": session_id, "update": {"sessionUpdate": "turn_completed", "stop_reason": "end_turn"}},
                },
            ],
        )
        self._write_jsonl(
            folder / "chat_history.jsonl",
            [
                {"type": "system", "content": "System prompt should not be a human request."},
                {"type": "user", "content": [{"type": "text", "text": "extra user copy"}]},
                {
                    "type": "assistant",
                    "content": "extra reply copy",
                    "tool_calls": [
                        {"id": "call-a", "name": "bash", "arguments": "{\"command\":\"echo extra\"}"},
                        {"id": "call-b", "name": "bash", "arguments": "{\"command\":\"echo more\"}"},
                    ],
                },
            ],
        )
        self._write_jsonl(
            folder / "prompt_history.jsonl",
            [{"timestamp": "2026-07-14T10:00:00Z", "session_id": session_id, "prompt": "extra prompt copy", "is_bash": False}],
        )
        (folder / "card.json").write_text(
            json.dumps(
                {
                    "info": {"id": session_id, "cwd": "D:/lab/widget"},
                    "created_at": "2026-07-14T09:00:00Z",
                    "updated_at": "2026-07-14T10:00:00Z",
                    "generated_title": "Widget inventory",
                    "session_summary": "Shorter summary",
                    "last_turn_summary": "Last turn recap should not win",
                    "git_root_dir": "D:/lab",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        result = run_sessions_analysis(folder, run_id="RUN-GROK-ACP")
        self.assertEqual(result["summary"]["sessions_recovered"], 1)
        session = result["top_sessions"][0]
        self.assertEqual(session["tool"], "grok")
        self.assertEqual(session["session_id"], session_id)
        self.assertEqual(session["session_title"], "Widget inventory")
        self.assertEqual(session["project_worktree_path"], "D:/lab/widget")
        self.assertEqual(session["request_count"], 1)
        self.assertEqual(session["response_count"], 1)
        detail = session["high_value_detail"]
        self.assertEqual(detail["request_fragment_count"], 1)
        self.assertEqual(detail["response_fragment_count"], 1)
        self.assertEqual(detail["tool_event_fragment_count"], 2)
        self.assertEqual(detail["machine_context_fragment_count"], 1)
        rows, _, _ = _collect_grok_sessions(
            [
                folder / "updates.jsonl",
                folder / "chat_history.jsonl",
                folder / "prompt_history.jsonl",
                folder / "card.json",
            ]
        )
        self.assertEqual(rows[0]["request_message_count"], 1)
        self.assertEqual(rows[0]["response_message_count"], 1)
        self.assertEqual(rows[0]["tool_event_count"], 2)
        self.assertEqual(rows[0]["machine_context_count"], 1)
        self.assertEqual(rows[0]["response_capture_status"], "present")

    def test_grok_chat_and_prompt_supply_counts_only_without_acp(self) -> None:
        chat_dir = self.root / "chat-only" / "session-chat"
        self._write_jsonl(
            chat_dir / "chat_history.jsonl",
            [
                {"type": "system", "content": "System prompt should not be a human request."},
                {"type": "user", "content": "hello from the operator"},
                {
                    "type": "assistant",
                    "content": "visible reply",
                    "tool_calls": [
                        {"id": "call-a", "name": "bash", "arguments": "{\"command\":\"echo one\"}"},
                        {"id": "call-b", "name": "bash", "arguments": "{\"command\":\"echo two\"}"},
                    ],
                },
            ],
        )
        self._write_jsonl(
            chat_dir / "prompt_history.jsonl",
            [{"timestamp": "2026-07-14T10:00:00Z", "session_id": "session-chat", "prompt": "duplicate prompt", "is_bash": True}],
        )
        prompt_only = self.root / "prompt-only" / "prompts.jsonl"
        self._write_jsonl(
            prompt_only,
            [
                {"timestamp": "2026-07-14T11:00:00Z", "session_id": "session-prompt", "prompt": "first prompt", "is_bash": False},
                {"timestamp": "2026-07-14T11:01:00Z", "session_id": "session-prompt", "prompt": "second prompt", "is_bash": False},
            ],
        )

        result = run_sessions_analysis(self.root, run_id="RUN-GROK-COPIES")
        by_id = {row["session_id"]: row for row in result["top_sessions"]}
        self.assertEqual(by_id["session-chat"]["request_count"], 1)
        self.assertEqual(by_id["session-chat"]["response_count"], 1)
        self.assertEqual(by_id["session-chat"]["high_value_detail"]["tool_event_fragment_count"], 2)
        self.assertEqual(by_id["session-chat"]["high_value_detail"]["machine_context_fragment_count"], 1)
        self.assertIsNone(by_id["session-chat"]["session_title"])
        self.assertEqual(by_id["session-prompt"]["request_count"], 2)
        self.assertEqual(by_id["session-prompt"]["response_count"], 0)
        self.assertEqual(by_id["session-prompt"]["response_status"], "absent_no_assistant_records")

    def test_grok_malformed_line_keeps_the_rest_of_the_file(self) -> None:
        updates = self.root / "updates.jsonl"
        updates.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps(self._grok_acp("session-alpha", "user_message_chunk", "hello before", "2026-07-14T10:00:00Z")),
            "{truncated",
            json.dumps(self._grok_acp("session-alpha", "agent_message_chunk", "reply after", "2026-07-14T10:00:02Z")),
        ]
        updates.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = run_sessions_analysis(updates, run_id="RUN-GROK-MALFORMED")
        session = result["top_sessions"][0]
        self.assertEqual(session["session_id"], "session-alpha")
        self.assertEqual(session["request_count"], 1)
        self.assertEqual(session["response_count"], 1)
        self.assertGreater(session["parse_error_count"], 0)
        self.assertGreater(result["summary"]["parse_failures"], 0)

    def test_grok_directory_skips_non_chat_files_without_cross_tool_sessions(self) -> None:
        folder = self.root / ".grok" / "sessions" / "workspace" / "session-one"
        self._write_jsonl(folder / "updates.jsonl", [
            self._grok_acp("session-one", "user_message_chunk", "hello", "2026-07-14T10:00:00Z"),
        ])
        (folder / "summary.json").write_text(json.dumps({
            "info": {"id": "session-one", "cwd": "/work"},
            "created_at": "2026-07-14T09:00:00Z",
            "updated_at": "2026-07-14T10:00:00Z",
            "session_summary": "Session one",
        }, indent=2), encoding="utf-8")
        (folder / "prompt_context.json").write_text(json.dumps({"version": 1, "prompt_mode": "default"}, indent=2), encoding="utf-8")
        (folder / "usage.json").write_text(json.dumps({"sessionId": "session-one", "turns": []}, indent=2), encoding="utf-8")
        (folder / "events.jsonl").write_text('', encoding="utf-8")
        self._write_jsonl(folder / "hunk_records.jsonl", [{"sessionId": "session-one", "hunkId": "hunk-one"}])
        self._write_jsonl(folder / "rewind_points.jsonl", [{"prompt_index": 0, "file_snapshots": []}])
        (folder / "system_prompt.txt").write_text("system text", encoding="utf-8")
        database = folder / "session_search.sqlite"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("create table session_docs (session_id text, title text, content text)")
            connection.commit()

        result = run_sessions_analysis(self.root / ".grok" / "sessions", run_id="RUN-GROK-SCOPE")
        self.assertEqual(result["summary"]["files_examined"], 9)
        self.assertEqual(result["summary"]["session_candidates_examined"], 2)
        self.assertEqual(result["summary"]["skipped_non_session_files"], 7)
        self.assertEqual(result["summary"]["supported_artifacts"], 2)
        self.assertEqual(result["summary"]["parse_failures"], 0)
        self.assertEqual(result["summary"]["sessions_recovered"], 1)
        report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text(encoding="utf-8"))
        self.assertEqual(len(report["artifact_inventory"]["issues"]), 7)
        self.assertEqual({item["tool"] for item in report["sessions"]}, {"grok"})
        text_report = Path(result["reports"]["session_report"]["text"]).read_text(encoding="utf-8")
        self.assertNotIn("Detected artifacts:", text_report)
        self.assertNotIn("External scanner targets:", text_report)
        selected_database = discover_session_inputs(database)
        self.assertEqual(selected_database.skipped_non_session_count, 1)

    def test_invalid_named_grok_chat_is_a_candidate_failure(self) -> None:
        folder = self.root / ".grok" / "sessions" / "session-bad"
        folder.mkdir(parents=True)
        (folder / "chat_history.jsonl").write_text("{broken\n", encoding="utf-8")
        discovery = discover_session_inputs(folder)
        self.assertEqual(discovery.session_candidates_examined, 1)
        self.assertEqual(discovery.parse_failed_count, 1)
        self.assertEqual(discovery.skipped_non_session_count, 0)

    def test_grok_acp_combines_adjacent_chunks_and_tracks_turns(self) -> None:
        folder = self.root / "grok-chunks"
        session_id = "session-chunks"
        updates = [
            self._grok_acp(session_id, "user_message_chunk", "hel", "2026-07-14T10:00:00Z"),
            self._grok_acp(session_id, "user_message_chunk", "lo", "2026-07-14T10:00:01Z"),
            self._grok_acp(session_id, "agent_message_chunk", "first ", "2026-07-14T10:00:02Z"),
            self._grok_acp(session_id, "agent_message_chunk", "message", "2026-07-14T10:00:03Z"),
            self._grok_acp(session_id, "tool_call", "", "2026-07-14T10:00:04Z", raw_input={"command": "echo hi"}),
            self._grok_acp(session_id, "agent_message_chunk", "second ", "2026-07-14T10:00:05Z"),
            self._grok_acp(session_id, "agent_message_chunk", "message", "2026-07-14T10:00:06Z"),
            self._grok_acp(session_id, "turn_completed", "", "2026-07-14T10:00:07Z"),
            self._grok_acp(session_id, "user_message_chunk", "unfinished", "2026-07-14T10:00:08Z"),
        ]
        self._write_jsonl(folder / "updates.jsonl", updates)
        self._write_jsonl(folder / "copy-updates.bin", updates)
        self._write_jsonl(folder / "chat_history.jsonl", [
            {"type": "user", "content": "duplicate user"},
            {"type": "assistant", "content": "duplicate answer", "tool_calls": [{"id": "call-1", "name": "bash", "arguments": "{}"}]},
        ])

        result = run_sessions_analysis(folder, run_id="RUN-GROK-CHUNKS")
        row = result["top_sessions"][0]
        self.assertEqual((row["request_count"], row["response_count"]), (2, 2))
        self.assertEqual(row["completed_turn_count"], 1)
        self.assertEqual(row["user_message_chunk_count"], 3)
        self.assertEqual(row["assistant_message_chunk_count"], 4)
        self.assertEqual(row["captured_request_bytes"], len("hello".encode()) + len("unfinished".encode()))
        self.assertEqual(row["captured_response_bytes"], len("first message".encode()) + len("second message".encode()))
        self.assertEqual(row["high_value_detail"]["response_fragment_count"], 2)
        self.assertEqual(row["high_value_detail"]["request_fragment_count"], 2)
        self.assertEqual(row["high_value_detail"]["source_file_count"], 3)

    def test_grok_report_stores_indicator_hashes_without_raw_values(self) -> None:
        secret = "token=ABCD1234SECRETVALUE"
        grok_path = "/Users/analyst/.grok/sessions/lab"
        session_id = "session-secret"
        folder = self.root / "review"
        self._write_jsonl(
            folder / "updates.jsonl",
            [
                self._grok_acp(session_id, "user_message_chunk", f"please use {secret} now", "2026-07-14T10:00:00Z"),
                self._grok_acp(session_id, "agent_message_chunk", f"opened {grok_path} for review", "2026-07-14T10:00:01Z"),
                self._grok_acp(
                    session_id,
                    "tool_call",
                    "",
                    "2026-07-14T10:00:02Z",
                    raw_input={"command": f"echo {secret}"},
                ),
                self._grok_acp(
                    session_id,
                    "tool_call_update",
                    "",
                    "2026-07-14T10:00:03Z",
                    raw_output={"stdout": "done"},
                ),
            ],
        )
        (folder / "summary.json").write_text(
            json.dumps(
                {
                    "info": {"id": session_id, "cwd": "D:/lab/widget"},
                    "created_at": "2026-07-14T09:00:00Z",
                    "updated_at": "2026-07-14T10:00:00Z",
                    "generated_title": "Secret review",
                    "session_summary": "Review",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        result = run_sessions_analysis(folder, run_id="RUN-GROK-SECRET")
        report_path = Path(result["reports"]["session_report"]["json"])
        text_path = Path(result["reports"]["session_report"]["text"])
        report_text = report_path.read_text(encoding="utf-8") + text_path.read_text(encoding="utf-8")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        session = report["sessions"][0]
        self.assertEqual(session["tool"], "grok")
        indicators = session["high_value_detail"]["indicators"]
        categories = {item["category"] for item in indicators}
        self.assertIn("credential_secret", categories)
        self.assertIn("agent_filesystem", categories)
        for indicator in indicators:
            self.assertIn(indicator["severity_bucket"], {"critical", "high", "medium", "low"})
            self.assertGreater(indicator["match_count"], 0)
            self.assertEqual(len(indicator["matched_value_sha256"]), 64)
            self.assertNotIn("matched_value", indicator)
        self.assertNotIn(secret, report_text)
        self.assertNotIn(grok_path, report_text)
        self.assertNotIn("ABCD1234SECRETVALUE", report_text)
        secret_rule = next(rule for rule in INDICATOR_RULES if rule.rule_id == "credential.assignment")
        secret_match = secret_rule.pattern.search(f"please use {secret} now")
        self.assertIsNotNone(secret_match)
        secret_digest = hashlib.sha256(secret_match.group(0).strip().encode("utf-8")).hexdigest()
        path_rule = next(rule for rule in INDICATOR_RULES if rule.rule_id == "agent_fs.posix_agent_root")
        path_match = path_rule.pattern.search(f"opened {grok_path} for review")
        self.assertIsNotNone(path_match)
        canonical_path = path_match.group(0).strip().strip(".,;:)]}").lower()
        path_digest = hashlib.sha256(canonical_path.encode("utf-8")).hexdigest()
        self.assertIn(secret_digest, report_text)
        self.assertIn(path_digest, report_text)

    def test_explicit_grok_root_enumerates_chat_artifacts_only(self) -> None:
        session_id = "session-alpha"
        root = self.root / "grok-home"
        session_dir = root / "sessions" / "encoded-cwd" / session_id
        self._write_jsonl(
            session_dir / "updates.jsonl",
            [self._grok_acp(session_id, "user_message_chunk", "hello", "2026-07-14T10:00:00Z")],
        )
        self._write_jsonl(
            session_dir / "chat_history.jsonl",
            [
                {"type": "user", "content": "hello"},
                {"type": "assistant", "content": "done", "tool_calls": [{"id": "call-1", "name": "bash", "arguments": "{}"}]},
            ],
        )
        self._write_jsonl(
            session_dir.parent / "prompt_history.jsonl",
            [{"timestamp": "2026-07-14T10:00:00Z", "session_id": session_id, "prompt": "hello", "is_bash": False}],
        )
        (session_dir / "summary.json").write_text(
            json.dumps(
                {
                    "info": {"id": session_id, "cwd": "D:/lab/widget"},
                    "created_at": "2026-07-14T09:00:00Z",
                    "updated_at": "2026-07-14T10:00:00Z",
                    "generated_title": "Widget inventory",
                    "session_summary": "Shorter summary",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self._write_jsonl(session_dir / "events.jsonl", [{"type": "turn_started", "at": "2026-07-14T10:00:00Z"}])
        (root / "auth.json").write_text('{"access_token":"not-a-session"}\n', encoding="utf-8")

        missing = self.root / "missing-root"
        detail = run_session_detail(
            run_id="GROK-ROOT",
            grok_root=root,
            codex_root=missing / "codex",
            claude_root=missing / "claude",
            cursor_root=missing / "cursor",
            antigravity_cli_root=missing / "ag",
        )
        grok_tool = next(tool for tool in detail["tools"] if tool["tool_name"] == "Grok")
        artifact_paths = {Path(item["path"]).name for item in grok_tool["artifacts"]}
        self.assertEqual(artifact_paths, {"updates.jsonl", "chat_history.jsonl", "prompt_history.jsonl", "summary.json"})
        sessions = grok_tool["findings"][0]["value"]["sessions"]
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["session_id"], session_id)
        self.assertEqual(sessions[0]["request_message_count"], 1)
        targeted = run_session_detail(run_id="GROK-TARGET", target_root=root, target_tool="grok")
        targeted_grok = next(tool for tool in targeted["tools"] if tool["tool_name"] == "Grok")
        self.assertEqual(
            {Path(item["path"]).name for item in targeted_grok["artifacts"]},
            {"updates.jsonl", "chat_history.jsonl", "prompt_history.jsonl", "summary.json"},
        )
        self.assertEqual([tool["tool_name"] for tool in targeted["tools"]], ["Grok"])

    def test_sessions_command_reads_only_the_selected_grok_file(self) -> None:
        session_id = "session-alpha"
        folder = self.root / session_id
        prompts = folder / "prompt_history.jsonl"
        updates = folder / "updates.jsonl"
        self._write_jsonl(
            prompts,
            [{"timestamp": "2026-07-14T10:00:00Z", "session_id": session_id, "prompt": "selected prompt", "is_bash": False}],
        )
        self._write_jsonl(
            updates,
            [
                self._grok_acp(session_id, "user_message_chunk", "unselected prompt", "2026-07-14T10:00:00Z"),
                self._grok_acp(session_id, "agent_message_chunk", "unselected reply", "2026-07-14T10:00:01Z"),
            ],
        )

        result = run_sessions_analysis(prompts, run_id="RUN-GROK-SELECTED")
        session = result["top_sessions"][0]
        self.assertEqual(session["request_count"], 1)
        self.assertEqual(session["response_count"], 0)
        self.assertEqual({Path(target["path"]) for target in result["scan_targets"]}, {prompts.resolve()})
        self.assertNotIn(str(updates.resolve()), json.dumps(result["scan_targets"]))

    @staticmethod
    def _grok_acp(
        session_id: str,
        update_kind: str,
        text: str,
        timestamp: str,
        *,
        raw_input: dict[str, object] | None = None,
        raw_output: dict[str, object] | None = None,
    ) -> dict[str, object]:
        update: dict[str, object] = {"sessionUpdate": update_kind}
        if update_kind in {"user_message_chunk", "agent_message_chunk", "agent_thought_chunk"}:
            update["content"] = {"type": "text", "text": text}
        if raw_input is not None:
            update["rawInput"] = raw_input
        if raw_output is not None:
            update["rawOutput"] = raw_output
        return {
            "timestamp": timestamp,
            "method": "session/update",
            "params": {"sessionId": session_id, "update": update},
        }


class LocalSessionTests(unittest.TestCase):
    setUp = SessionInputTests.setUp
    tearDown = SessionInputTests.tearDown
    _write_jsonl = staticmethod(SessionInputTests._write_jsonl)
    _write_cursor_store = staticmethod(SessionInputTests._write_cursor_store)
    _write_antigravity_store = staticmethod(SessionInputTests._write_antigravity_store)
    def _five_roots(self) -> None:
        for index in range(6):
            self._write_jsonl(
                self.root / ".codex" / "sessions" / f"s{index}.jsonl",
                [{"session_id": f"codex-{index}", "role": "user", "content": "hi"},
                 {"session_id": f"codex-{index}", "role": "assistant", "content": "done"}],
            )
        self._write_jsonl(self.root / ".claude" / "projects" / "p" / "one.jsonl",
                          [{"sessionId": "claude-one", "uuid": "m1", "parentUuid": None, "role": "user", "content": "hi"}])
        self._write_cursor_store(self.root / ".cursor" / "chats" / "c" / "store.db")
        self._write_jsonl(self.root / ".cursor" / "projects" / "p" / "agent-transcripts" / "a" / "subagents" / "one.jsonl",
                          [{"agentId": "sub-one", "role": "user", "content": "hi"}])
        self._write_antigravity_store(self.root / ".gemini" / "antigravity-cli" / "conversations" / "one.db")
        log = self.root / ".gemini" / "antigravity-cli" / "brain" / "one" / ".system_generated" / "logs"
        self._write_jsonl(log / "transcript_full.jsonl", [{"source": "user_explicit", "text": "hi"}])
        self._write_jsonl(log / "transcript.jsonl", [{"source": "user_explicit", "text": "duplicate"}])
        self._write_jsonl(self.root / ".grok" / "sessions" / "one" / "prompt_history.jsonl",
                          [{"session_id": "grok-one", "timestamp": "2026-07-14T10:00:00Z", "prompt": "hi", "is_bash": False}])

    def test_local_selects_roots_and_top_five_per_tool(self) -> None:
        self._five_roots()
        for index in range(100):
            (self.root / "unrelated").mkdir(exist_ok=True)
            (self.root / "unrelated" / f"{index}.jsonl").write_text("{bad\n", encoding="utf-8")
        discovery = discover_local_session_inputs(self.root)
        self.assertEqual(discovery.files_examined, 12)
        self.assertEqual(len(discovery.sources), 12)
        self.assertEqual(discovery.parse_failed_count, 0)
        self.assertNotIn("transcript.jsonl", {source.path.name for source in discovery.sources})
        self.assertTrue(any("subagents" in source.path.parts for source in discovery.sources))
        result = run_sessions_analysis(self.root, local_mode=True, output_directory=self.root / "reports", run_id="LOCAL")
        report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text())
        self.assertEqual(len(report["sessions"]), result["summary"]["sessions_recovered"])
        self.assertEqual(len([row for row in result["top_sessions"] if row["tool"] == "codex"]), 5)
        self.assertEqual([row["tool_rank"] for row in result["top_sessions"] if row["tool"] == "codex"], [1, 2, 3, 4, 5])
        self.assertEqual(report["top_sessions"], result["top_sessions"])
        self.assertEqual(sum("score " in line for line in session_summary_lines(result)), len(result["top_sessions"]))

    def test_local_limit_filters_selector_and_missing_roots(self) -> None:
        self._five_roots()
        link = self.root / ".codex" / "sessions" / "linked.jsonl"
        link.symlink_to(self.root / ".codex" / "sessions" / "s0.jsonl")
        selected = discover_local_session_inputs(self.root, max_files=5)
        self.assertTrue(selected.limit_reached)
        self.assertEqual(selected.files_examined, 5)
        self.assertEqual(set(source.detected_tool for source in selected.sources),
                         {"Codex", "Claude Code", "Cursor", "Antigravity CLI", "Grok"})
        self.assertGreaterEqual(selected.skipped_links, 1)
        grok = discover_local_session_inputs(self.root, tool="grok", includes=["*prompt_history.jsonl"])
        self.assertEqual(grok.files_examined, 1)
        self.assertEqual(set(grok.local_roots), {"Grok"})
        self.assertEqual(discover_local_session_inputs(self.root, tool="grok", excludes=["*prompt_history.jsonl"]).files_examined, 0)
        self.assertEqual(discover_local_session_inputs(self.root, tool="grok", max_file_size=1).unsupported_count, 1)
        empty = discover_local_session_inputs(self.root / "absent-home")
        self.assertEqual(empty.files_examined, 0)
        self.assertTrue(all(row["status"] == "absent" for row in empty.local_roots.values()))

    def test_local_cli_alias_and_cursor_binary_blobs(self) -> None:
        self._five_roots()
        store = self.root / ".cursor" / "chats" / "c" / "store.db"
        with closing(sqlite3.connect(store)) as connection:
            connection.execute("insert into blobs values ('binary', ?)", (b"\x12\x06\x00\xff",))
            connection.commit()
        with patch("blacklight.cli.Path.home", return_value=self.root):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli_main(["sessions", "--tool", "cursor", "--output-directory", str(self.root / "cli-reports")]), 0)
        self.assertIn("Scope: local agent session roots", output.getvalue())
        self.assertIn("Parse failures:       0", output.getvalue())
        report = json.loads(next((self.root / "cli-reports").glob("*.json")).read_text())
        self.assertEqual(set(report["artifact_inventory"]["local_roots"]), {"Cursor"})

    def test_local_symlink_root_is_absent_from_candidates(self) -> None:
        self._five_roots()
        (self.root / ".claude-link").symlink_to(self.root / ".claude", target_is_directory=True)
        renamed = self.root / ".claude"
        renamed.rename(self.root / ".claude-real")
        renamed.symlink_to(self.root / ".claude-real", target_is_directory=True)
        result = discover_local_session_inputs(self.root, tool="claude")
        self.assertEqual(result.files_examined, 0)
        self.assertEqual(result.skipped_links, 1)
        self.assertEqual(result.local_roots["Claude Code"]["status"], "symlink_skipped")


if __name__ == "__main__":
    unittest.main()
