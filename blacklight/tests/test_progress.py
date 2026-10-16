from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from blacklight import analyze
from blacklight.cli import main
from blacklight.progress import ProgressEvent, TerminalProgress
from blacklight.session_input import discover_local_session_inputs, discover_session_inputs
from blacklight.sessions import run_sessions_analysis
from blacklight.tests import test_sessions as fixtures


class InteractiveStream(io.StringIO):
    def isatty(self) -> bool:
        return True


class TerminalProgressTests(unittest.TestCase):
    def test_slow_work_keeps_refreshing_and_thread_stops(self) -> None:
        stream = InteractiveStream()
        refreshed = threading.Event()

        class ObservedProgress(TerminalProgress):
            def _render(self, status: str | None = None) -> None:
                super()._render(status)
                if self._frame >= 3:
                    refreshed.set()

        with ObservedProgress(stream=stream) as progress:
            progress.update(ProgressEvent("Scanning indicators", 0, 1))
            self.assertTrue(refreshed.wait(3), "Display stopped refreshing during slow work")
            self.assertIn("0/1 files", stream.getvalue())
            self.assertIn("files  /", stream.getvalue())
            self.assertIn("files  -", stream.getvalue())
            self.assertNotIn("Complete", stream.getvalue())
        self.assertFalse(progress._thread.is_alive())
        self.assertTrue(stream.getvalue().endswith("\n"))
        self.assertIn("Complete", stream.getvalue())

    def test_failure_and_interrupt_cleanup(self) -> None:
        for exception, label in [(ValueError("failure"), "Failed"), (KeyboardInterrupt(), "Interrupted")]:
            with self.subTest(label=label):
                stream = InteractiveStream()
                with self.assertRaises(type(exception)):
                    with TerminalProgress(stream=stream) as progress:
                        raise exception
                self.assertFalse(progress._thread.is_alive())
                self.assertIn(label, stream.getvalue())
                self.assertNotIn("Complete", stream.getvalue())

    def test_redirected_and_disabled_stderr_are_silent(self) -> None:
        for stream, enabled in [(io.StringIO(), True), (InteractiveStream(), False)]:
            with TerminalProgress(stream=stream, enabled=enabled) as progress:
                progress.update(ProgressEvent("Parsing sessions", 1, 1))
            self.assertIsNone(progress._thread)
            self.assertEqual(stream.getvalue(), "")

    def test_bar_elapsed_and_narrow_terminal(self) -> None:
        for width in [100, 40, 12]:
            with self.subTest(width=width):
                stream = InteractiveStream()
                with patch("blacklight.progress.shutil.get_terminal_size", return_value=os.terminal_size((width, 24))):
                    with patch("blacklight.progress.time.monotonic", return_value=84):
                        progress = TerminalProgress(stream=stream)
                        progress.update(ProgressEvent("Scanning indicators", 120, 300))
                        progress._render()
                self.assertLessEqual(len(stream.getvalue().lstrip("\r")), width - 1)
                if width == 100:
                    self.assertIn("[########------------] 40%  120/300 files  |  elapsed 01:24", stream.getvalue())


class AnalysisProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _mixed_sources(self) -> None:
        fixture = fixtures.LocalSessionTests()
        fixture.root = self.root
        fixture._five_roots()
        fixtures.SessionInputTests._write_jsonl(
            self.root / ".codex" / "sessions" / "partial.jsonl",
            [{"session_id": "partial", "role": "user", "content": "hello"}], malformed=True,
        )

    def _assert_phase(self, events: list[ProgressEvent], phase: str, total: int) -> None:
        rows = [event for event in events if event.phase == phase]
        self.assertTrue(rows)
        self.assertEqual(rows[0], ProgressEvent(phase, 0, total))
        self.assertEqual(rows[-1], ProgressEvent(phase, total, total))
        self.assertEqual([row.completed for row in rows], sorted(row.completed for row in rows))
        self.assertTrue(all(row.total == total and row.completed <= total for row in rows))

    def test_mixed_formats_phase_counts_and_unchanged_results(self) -> None:
        self._mixed_sources()
        for local_mode in [True, False]:
            with self.subTest(local_mode=local_mode):
                events = []
                options = dict(local_mode=local_mode, output_directory=self.root / "blacklight-reports", run_id="PROGRESS")
                result = run_sessions_analysis(self.root, progress_callback=events.append, **options)
                phases = list(dict.fromkeys(event.phase for event in events))
                self.assertEqual(phases, ["Discovering files", "Identifying supported artifacts", "Parsing sessions", "Scanning indicators", "Writing reports"])
                self._assert_phase(events, "Identifying supported artifacts", result["summary"]["files_examined"])
                for phase in ["Parsing sessions", "Scanning indicators"]:
                    self._assert_phase(events, phase, result["summary"]["supported_artifacts"])
                self.assertGreater(result["summary"]["parse_failures"], 0)
                self.assertEqual(result, run_sessions_analysis(self.root, **options))
                report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text())
                self.assertNotIn("progress", report)

    def test_discovery_limits_filters_and_empty_local(self) -> None:
        self._mixed_sources()
        for discover in [discover_local_session_inputs, discover_session_inputs]:
            for filters in [dict(max_files=2), dict(includes=["*partial.jsonl"]), dict(excludes=["*.jsonl"]), dict(includes=["missing"]), dict(max_file_size=1)]:
                with self.subTest(discover=discover.__name__, filters=filters):
                    events = []
                    result = discover(self.root, progress_callback=events.append, **filters)
                    self._assert_phase(events, "Identifying supported artifacts", result.files_examined)
        events = []
        result = run_sessions_analysis(self.root / "empty-home", local_mode=True, output_directory=self.root / "empty-report", progress_callback=events.append)
        self._assert_phase(events, "Parsing sessions", 0)
        self._assert_phase(events, "Scanning indicators", 0)
        self.assertEqual(result["summary"]["supported_artifacts"], 0)

    def test_handled_parser_failures_still_advance(self) -> None:
        self._mixed_sources()
        discovery = discover_local_session_inputs(self.root)
        # Remove inputs after discovery to exercise handled per-file read failures.
        for source in discovery.sources:
            source.path.unlink()
        for parser, phase in [(analyze.run_session_detail, "Parsing sessions"), (analyze.run_session_high_value, "Scanning indicators")]:
            events = []
            parser(run_id="FAILED", session_sources=discovery.sources, input_root=self.root, progress_callback=events.append)
            self._assert_phase(events, phase, len(discovery.sources))

    def test_cli_json_stdout_and_progress_switch(self) -> None:
        self._mixed_sources()
        for interactive, disabled in [(True, False), (True, True), (False, False)]:
            with self.subTest(interactive=interactive, disabled=disabled):
                stdout = io.StringIO()
                stderr = InteractiveStream() if interactive else io.StringIO()
                args = ["sessions", str(self.root), "--json", "--output-directory", str(self.root / "blacklight-reports")]
                if disabled:
                    args.append("--no-progress")
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue())["summary"]["supported_artifacts"], 14)
                if interactive and not disabled:
                    self.assertIn("Complete", stderr.getvalue())
                else:
                    self.assertEqual(stderr.getvalue(), "")

    def test_report_write_failure_never_shows_complete(self) -> None:
        self._mixed_sources()
        stderr = InteractiveStream()
        with redirect_stderr(stderr), patch("blacklight.sessions._write_session_report", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                main(["sessions", str(self.root), "--output-directory", str(self.root / "blacklight-reports")])
        self.assertIn("Failed", stderr.getvalue())
        self.assertNotIn("Complete", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
