from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts import set_version


class SetVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[2]
        cls.files = (
            "pyproject.toml",
            "uv.lock",
            "CHANGELOG.md",
            "blacklight-scout/native/ai_path_scout_windows.c",
            "blacklight-scout/managed/Program.cs",
            "blacklight-scout/managed/ai_path_scout-managed.csproj",
            "blacklight-scout/releases/metadata.json",
            "blacklight-scout/releases/ai_path_scout/metadata.json",
        )

    def fixture(self) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        for relative in self.files:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repo_root / relative, destination)
        return root

    def test_check_accepts_current_versions_and_does_not_write(self) -> None:
        root = self.fixture()
        before = {relative: (root / relative).read_bytes() for relative in self.files}
        version = set_version.project_version(root)

        self.assertEqual(set_version.check(root, version), [])
        self.assertEqual(before, {relative: (root / relative).read_bytes() for relative in self.files})

    def test_check_reports_stale_copy(self) -> None:
        root = self.fixture()
        native = root / "blacklight-scout/native/ai_path_scout_windows.c"
        native.write_text(native.read_text(encoding="utf-8").replace('"0.2.6"', '"0.2.5"', 1), encoding="utf-8")

        errors = set_version.check(root, set_version.project_version(root))

        self.assertTrue(any("ai_path_scout_windows.c" in error for error in errors))

    def test_check_reports_missing_changelog_heading(self) -> None:
        root = self.fixture()
        changelog = root / "CHANGELOG.md"
        changelog.write_text(changelog.read_text(encoding="utf-8").replace("## [0.2.6] - 2026-10-20", "## [0.2.5] - 2026-10-15"), encoding="utf-8")

        errors = set_version.check(root, set_version.project_version(root))

        self.assertTrue(any("CHANGELOG.md" in error for error in errors))

    def test_update_prepares_dated_heading(self) -> None:
        root = self.fixture()
        heading = set_version.expected_changelog(root, "0.2.7", date(2026, 10, 23))

        self.assertIn("## [Unreleased]\r\n## [0.2.7] - 2026-10-23", heading)


if __name__ == "__main__":
    unittest.main()
