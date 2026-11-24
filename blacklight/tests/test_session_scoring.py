from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import blacklight
from blacklight.sessions import _activity_time, _rank_sessions, _session_score, run_sessions_analysis


NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


def row(session_id="one", **changes):
    return {"tool": "codex", "session_id": session_id, "captured_total_bytes": 65536,
            "request_count": 10, "response_count": 10, "last_activity": NOW.isoformat(),
            "project_worktree_path": "/work", **changes}


def rank(rows):
    return _rank_sessions({"tools": [{"findings": [{"value": {"sessions": rows}}]}]}, NOW)


class SessionScoringTests(unittest.TestCase):
    def test_exact_formula_and_rounding(self):
        score = _session_score(row(last_activity=(NOW - timedelta(days=30)).isoformat()), NOW, 4)
        self.assertEqual([score[key] for key in ("size_points", "message_points", "recency_points", "frequency_points")], [20, 15, 10, 5])
        self.assertEqual(score["raw_score"], 50)
        self.assertEqual(score["blacklight_score"], 50)
        self.assertEqual(score["age_days"], 30)
        self.assertEqual(_session_score(row(request_count=11), NOW)["blacklight_score"], 55)

    def test_empty_negative_and_missing_data(self):
        score = _session_score({}, NOW)
        self.assertEqual(score["blacklight_score"], 0)
        self.assertIsNone(score["age_days"])
        self.assertEqual(_session_score(row(captured_total_bytes=-1, request_count=-1, response_count=-1, last_activity="bad"), NOW)["blacklight_score"], 0)
        for value in (None, "", "invalid", "9999-99-99", 123):
            self.assertIsNone(_activity_time(value))

    def test_timezones_naive_and_future(self):
        for stamp in ("2026-11-16T00:00:00Z", "2026-11-15T19:00:00-05:00", "2026-11-16T00:00:00", "2027-01-01T00:00:00Z"):
            self.assertEqual(_session_score(row(last_activity=stamp), NOW)["recency_points"], 20)
        self.assertEqual(_session_score(row(last_activity="2026-10-17T00:00:00Z"), NOW)["recency_points"], 10)

    def test_monotonicity_and_no_early_saturation(self):
        base = _session_score(row(), NOW, 1)["raw_score"]
        for changes, frequency in (({"captured_total_bytes": 131072}, 1), ({"request_count": 20}, 1), ({}, 2)):
            self.assertGreater(_session_score(row(**changes), NOW, frequency)["raw_score"], base)
        self.assertLess(_session_score(row(last_activity="2026-10-01T00:00:00Z"), NOW, 1)["raw_score"], base)
        scores = [_session_score(row(captured_total_bytes=b, request_count=q, response_count=r), NOW)["blacklight_score"]
                  for b, q, r in ((1048576, 1032, 156), (65536, 36, 70), (262144, 453, 151))]
        self.assertEqual(len(set(scores)), 3)
        self.assertTrue(all(score < 100 for score in scores))
        self.assertEqual(_session_score(row(captured_total_bytes=10**20, request_count=10**20), NOW, 10**20)["blacklight_score"], 99)

    def test_frequency_boundary_deduplication_and_isolation(self):
        rows = [row(), row("boundary", last_activity="2026-10-17T00:00:00Z"),
                row("boundary", last_activity="2026-10-17T00:00:00Z"),
                row("old", last_activity="2026-10-16T23:59:59Z"), row("invalid", last_activity="bad"),
                row("future", last_activity="2026-12-01T00:00:00Z"),
                row("other-tool", tool="grok"), row("other-project", project_worktree_path="/other"),
                row("worktree", project_worktree_path="/work/branch"), row("unknown", project_worktree_path=None)]
        by_id = {item["session_id"]: item["scoring"] for item in rank(rows)}
        self.assertEqual(by_id["one"]["recent_project_peer_session_count"], 2)
        self.assertEqual(by_id["old"]["recent_project_peer_session_count"], 3)
        for identity in ("other-tool", "other-project", "worktree", "unknown"):
            self.assertEqual(by_id[identity]["frequency_points"], 0)
        self.assertEqual(rank([row()])[0]["scoring"]["frequency_points"], 0)

    def test_rank_uses_unrounded_score_and_stable_ties(self):
        ranked = rank([row("a", captured_total_bytes=65536), row("b", captured_total_bytes=65537)])
        self.assertEqual(ranked[0]["session_id"], "b")
        self.assertEqual(ranked[0]["blacklight_score"], ranked[1]["blacklight_score"])
        tied = [row("b"), row("a")]
        self.assertEqual([item["session_id"] for item in rank(tied)], ["a", "b"])
        self.assertEqual(rank(tied), rank(list(reversed(tied))))
        self.assertEqual([item["tool_rank"] for item in rank(tied)], [1, 2])

    def test_content_and_metadata_do_not_award_points(self):
        self.assertEqual(_session_score(row(), NOW), _session_score(row(
            session_title="password=secret", response_status="present", parse_error_count=10,
            indicator_categories=["credential_secret"], high_value_detail={"unique_high_value_score": 100}), NOW))

    def test_selected_files_and_duplicate_artifacts_define_frequency_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stamp = datetime.now(timezone.utc).isoformat()
            first = root / "first.jsonl"
            first.write_text(json.dumps({"session_id": "one", "role": "user", "content": "hello",
                                         "cwd": "/work", "timestamp": stamp}) + "\n")
            (root / "copy.jsonl").write_text(first.read_text())
            (root / "second.jsonl").write_text(json.dumps({"session_id": "two", "role": "user",
                                                         "content": "hello", "cwd": "/work",
                                                         "timestamp": stamp}) + "\n")
            result = run_sessions_analysis(root, run_id="ALL")
            self.assertEqual(result["summary"]["sessions_recovered"], 2)
            self.assertTrue(all(session["scoring"]["recent_project_peer_session_count"] == 1
                                for session in result["top_sessions"]))
            selected = run_sessions_analysis(first, run_id="SELECTED")
            self.assertEqual(selected["top_sessions"][0]["scoring"]["frequency_points"], 0)

    def test_reports_explain_score_without_indicator_scan(self):
        self.assertFalse(hasattr(blacklight, "run_session_high_value"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sessions.jsonl"
            source.write_text(json.dumps({"session_id": "one", "role": "user", "content": "token=abcdefgh12345678", "timestamp": NOW.isoformat()}) + "\n")
            events = []
            with patch("blacklight.sessions.run_session_detail", wraps=blacklight.run_session_detail) as parse:
                result = run_sessions_analysis(source, run_id="SCORE", progress_callback=events.append)
                self.assertEqual(parse.call_count, 1)
            report = json.loads(Path(result["reports"]["session_report"]["json"]).read_text())
            self.assertEqual(result["scoring"], report["scoring"])
            self.assertEqual(report["scoring"]["version"], "activity-v1")
            self.assertNotIn("Scanning indicators", [event.phase for event in events])
            self.assertFalse(report["content_policy"]["sensitivity_scoring_included"])
            session = report["sessions"][0]
            contributions = session["scoring"]
            self.assertAlmostEqual(sum(contributions[k] for k in ("size_points", "message_points", "recency_points", "frequency_points")), contributions["raw_score"])
            self.assertEqual(contributions["blacklight_score"], session["blacklight_score"])
            self.assertNotIn("high_value_detail", session)
            self.assertNotIn("indicator_categories", session)
            self.assertIn("Scoring (activity-v1)", Path(result["reports"]["session_report"]["text"]).read_text())


if __name__ == "__main__":
    unittest.main()
