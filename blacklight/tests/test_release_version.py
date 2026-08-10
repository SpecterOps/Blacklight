from __future__ import annotations

import json
import os
import re
import tomllib
import unittest
from pathlib import Path


class ReleaseVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[2]

    def test_python_scout_and_release_metadata_versions_match(self) -> None:
        expected = "0.2.0"
        project = tomllib.loads((self.repo_root / "pyproject.toml").read_text(encoding="utf-8"))
        native = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_windows.c").read_text(encoding="utf-8")
        managed = (self.repo_root / "blacklight-scout" / "managed" / "Program.cs").read_text(encoding="utf-8")
        release_index = json.loads(
            (self.repo_root / "blacklight-scout" / "releases" / "metadata.json").read_text(encoding="utf-8")
        )
        bundle = json.loads(
            (self.repo_root / "blacklight-scout" / "releases" / "ai_path_scout" / "metadata.json").read_text(encoding="utf-8")
        )

        self.assertEqual(project["project"]["version"], expected)
        self.assertEqual(re.search(r'#define BL_SCOUT_VERSION "([^"]+)"', native).group(1), expected)
        self.assertEqual(re.search(r'private const string Version = "([^"]+)"', managed).group(1), expected)
        self.assertEqual(release_index["bundles"][0]["version"], expected)
        self.assertEqual(bundle["version"], expected)

        release_tag = os.environ.get("RELEASE_TAG")
        if release_tag:
            self.assertEqual(release_tag.removeprefix("v"), expected)

    def test_release_metadata_declares_no_argument_posix_triage(self) -> None:
        release_index = json.loads(
            (self.repo_root / "blacklight-scout" / "releases" / "metadata.json").read_text(encoding="utf-8")
        )["bundles"][0]
        bundle = json.loads(
            (self.repo_root / "blacklight-scout" / "releases" / "ai_path_scout" / "metadata.json").read_text(encoding="utf-8")
        )

        self.assertEqual(bundle["output_contract_version"], "v1")
        self.assertIn("No-argument", release_index["windows_bof_contract"])
        self.assertIn("No-argument", bundle["execution_tiers"]["windows_bof"])
        self.assertIn("no-argument", release_index["posix_loader_contract"])
        self.assertIn("no-argument", bundle["execution_tiers"]["posix_loaders"])

    def test_release_index_points_to_canonical_checklist(self) -> None:
        release_root = self.repo_root / "blacklight-scout" / "releases"
        release_index = json.loads((release_root / "metadata.json").read_text(encoding="utf-8"))["bundles"][0]
        checklist = (release_root / release_index["checklist"]).resolve()

        self.assertEqual(checklist, (self.repo_root / "docs" / "RELEASE.md").resolve())
        self.assertTrue(checklist.is_file())


if __name__ == "__main__":
    unittest.main()
