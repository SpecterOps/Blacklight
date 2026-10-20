from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from blacklight.sqlite_input import sqlite_snapshot
from blacklight.session_input import discover_local_session_inputs, discover_session_inputs
from blacklight.sessions import run_sessions_analysis


class SQLiteSnapshotTests(unittest.TestCase):
    def test_codex_state_backups_are_metadata_not_recovered_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            root = home / ".codex"
            root.mkdir()
            path = root / "state_5.sqlite.corrupt-fixture"
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
                connection.execute("INSERT INTO threads VALUES ('fixture', '/missing/rollout.jsonl')")
            discovery = discover_local_session_inputs(home, tool="codex")
            self.assertEqual([source.artifact_type for source in discovery.sources], ["codex_state_sqlite"])
            result = run_sessions_analysis(path, run_id="DB-ONLY", output_directory=home / "reports")
            self.assertEqual(result["summary"]["sessions_recovered"], 0)
            self.assertEqual(result["summary"]["parsed_artifacts"], 1)
            path.write_bytes(b"corrupt backup")
            broken = discover_session_inputs(path)
            self.assertEqual(broken.issues[0].status, "parse_failed")

    def test_uncheckpointed_rows_are_read_without_changing_selected_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state_5.sqlite"
            connection = sqlite3.connect(path)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
                connection.execute("INSERT INTO threads VALUES ('fixture', '/missing/rollout.jsonl')")
                connection.commit()
                selected = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
                before = {item: item.read_bytes() for item in selected}
                with sqlite_snapshot(path) as snapshot:
                    self.assertEqual(snapshot.execute("SELECT count(*) FROM threads").fetchone()[0], 1)
                    with self.assertRaises(sqlite3.OperationalError):
                        snapshot.execute("DELETE FROM threads")
                self.assertEqual({item: item.read_bytes() for item in selected}, before)
            finally:
                connection.close()

    def test_symlinked_sidecar_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.db"
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TABLE fixture (id TEXT)")
            other = Path(directory) / "other"
            other.write_bytes(b"unselected")
            Path(str(path) + "-wal").symlink_to(other)
            with self.assertRaisesRegex(OSError, "symbolic link"):
                with sqlite_snapshot(path):
                    self.fail("must not open a symlinked sidecar")
