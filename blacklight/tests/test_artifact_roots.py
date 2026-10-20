import json
import tempfile
import unittest
from pathlib import Path

from blacklight.artifact_roots import session_artifact_roots


class ArtifactRootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()

    def test_strands_registry_follows_directory_not_workspace(self):
        store = self.home / "project/.agent/sessions"
        store.mkdir(parents=True)
        registry = self.home / ".strands/cli/session-roots.json"
        registry.parent.mkdir(parents=True)
        valid = {"directory": str(store), "workspace": str(self.home / "project"), "lastSeenAt": "2026-10-17T00:00:00Z"}
        registry.write_text(json.dumps({"version": 1, "roots": [valid, valid, {**valid, "directory": "relative"}, {**valid, "directory": str(self.home / "gone")}, {}]}))
        self.assertEqual([store], session_artifact_roots("strands", self.home))
        registry.write_text(json.dumps({"version": 1, "roots": [{**valid, "directory": str(self.home / "link")}]}))
        (self.home / "link").symlink_to(store, target_is_directory=True)
        self.assertEqual([], session_artifact_roots("strands", self.home))
        registry.write_text(json.dumps({"version": 2, "roots": [valid]}))
        self.assertEqual([], session_artifact_roots("strands", self.home))
        registry.write_text("{")
        self.assertEqual([], session_artifact_roots("strands", self.home))

    def test_symlink_store_and_registry_are_skipped(self):
        store = self.home / "store"
        store.mkdir()
        link = self.home / "link"
        link.symlink_to(store, target_is_directory=True)
        registry = self.home / ".strands/cli/session-roots.json"
        registry.parent.mkdir(parents=True)
        target = self.home / "registry.json"
        target.write_text('{"version": 1, "roots": []}')
        registry.symlink_to(target)
        self.assertEqual([], session_artifact_roots("strands", self.home))

    def test_strands_registry_is_bounded(self):
        registry = self.home / ".strands/cli/session-roots.json"
        registry.parent.mkdir(parents=True)
        registry.write_bytes(b" " * (1024 * 1024 + 1))
        self.assertEqual([], session_artifact_roots("strands", self.home))
        registry.write_text(json.dumps({"version": 1, "roots": [{}] * 1025}))
        self.assertEqual([], session_artifact_roots("strands", self.home))

    def test_kiro_override_replaces_default_and_missing_is_empty(self):
        default = self.home / ".kiro/sessions/cli"
        default.mkdir(parents=True)
        override = self.home / "custom"
        override.mkdir()
        self.assertEqual([default], session_artifact_roots("kiro", self.home, environ={}))
        self.assertEqual([override], session_artifact_roots("kiro", self.home, environ={"KIRO_SESSIONS_DIR": str(override)}))
        self.assertEqual([], session_artifact_roots("kiro", self.home, environ={"KIRO_SESSIONS_DIR": str(self.home / "missing")}))
        with self.assertRaises(ValueError):
            session_artifact_roots("kiro", self.home, environ={"KIRO_SESSIONS_DIR": "relative"})
        linked = self.home / "linked"
        linked.symlink_to(override, target_is_directory=True)
        self.assertEqual([], session_artifact_roots("kiro", self.home, environ={"KIRO_SESSIONS_DIR": str(linked)}))

    def test_devin_override_and_default_do_not_infer_database_presence(self):
        default = self.home / ".local/share/devin/cli"
        default.mkdir(parents=True)
        self.assertEqual([default], session_artifact_roots("devin", self.home, environ={}))
        override = self.home / "override"
        override.mkdir()
        self.assertEqual([override], session_artifact_roots("devin", self.home, environ={"DEVIN_SESSIONS_DIR": str(override)}))
        self.assertEqual([], session_artifact_roots("devin", self.home, environ={"DEVIN_SESSIONS_DIR": str(self.home / "missing")}))
        for tool in ("kiro", "devin"):
            with self.assertRaises(ValueError):
                session_artifact_roots(tool, self.home, environ={f"{tool.upper()}_SESSIONS_DIR": "~/other"})
