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
from blacklight.analyze import _collect_sessions
from blacklight.cli import main as cli_main
from blacklight.session_input import discover_session_inputs
from blacklight.sessions import run_sessions_analysis


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
        self.assertIn(str(codex.resolve()), report_text)
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


if __name__ == "__main__":
    unittest.main()
