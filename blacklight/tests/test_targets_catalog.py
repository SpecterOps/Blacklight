from __future__ import annotations

import json
import unittest
from pathlib import Path


class TargetCatalogAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[2]
        cls.catalog_path = cls.repo_root / "blacklight-scout" / "catalog" / "targets.json"
        cls.catalog = json.loads(cls.catalog_path.read_text(encoding="utf-8"))
        cls.release_metadata = json.loads(
            (cls.repo_root / "blacklight-scout" / "releases" / "ai_path_scout" / "metadata.json").read_text(encoding="utf-8")
        )

    def _catalog_tuples(self, platform: str) -> list[tuple[str, str, str]]:
        profile = self.catalog["platforms"][platform]
        return [(item["tool"], item["family"], item["pattern"]) for item in profile["targets"]]

    def test_catalog_tools_match_scope(self) -> None:
        self.assertEqual(self.catalog["tools"], ["codex", "claude_code", "cursor", "antigravity_cli", "grok"])
        self.assertEqual(self.release_metadata["tools"], self.catalog["tools"])

    def test_grok_support_is_actionable_recon_only(self) -> None:
        expected = {
            ("root", ".grok"),
            ("config", ".grok/config.toml"),
            ("auth", ".grok/auth.json"),
            ("sessions", ".grok/active_sessions.json"),
            ("sessions", ".grok/sessions"),
            ("sessions", ".grok/sessions/session_search.sqlite"),
            ("workspace", ".grok/memory-v2"),
            ("plugins", ".grok/installed-plugins"),
            ("plugins", ".grok/marketplace-cache"),
            ("skills", ".grok/skills"),
            ("logs", ".grok/logs"),
            ("logs", ".grok/memtrace"),
            ("worktrees", ".grok/grove"),
            ("worktrees", ".grok/worktrees.db"),
        }
        actual = {
            (family, pattern.replace("\\", "/").removeprefix("%USERPROFILE%/"))
            for tool, family, pattern in self._catalog_tuples("windows")
            if tool == "grok"
        }
        self.assertEqual(actual, expected)
        self.assertNotIn("grok", (self.repo_root / "blacklight" / "session_input.py").read_text(encoding="utf-8").lower())

    def test_windows_catalog_covers_core_tool_families(self) -> None:
        windows = self._catalog_tuples("windows")
        for tool in self.catalog["tools"]:
            with self.subTest(tool=tool):
                families = {family for entry_tool, family, _ in windows if entry_tool == tool}
                self.assertIn("root", families)
                self.assertIn("config", families)

    def test_claude_mcp_needs_auth_cache_is_not_auth_family(self) -> None:
        for platform in ("windows", "darwin", "linux"):
            matches = [
                (family, pattern)
                for tool, family, pattern in self._catalog_tuples(platform)
                if "mcp-needs-auth-cache" in pattern
            ]
            with self.subTest(platform=platform):
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0][0], "mcp")

    def test_posix_catalog_uses_home_prefix(self) -> None:
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform):
                for tool, family, pattern in self._catalog_tuples(platform):
                    self.assertTrue(pattern.startswith("$HOME/"), f"{tool}/{family}: {pattern}")
                    self.assertIn(tool, self.catalog["tools"])

    def test_catalog_relative_paths_are_cross_platform_aligned(self) -> None:
        def relative_patterns(platform: str) -> set[str]:
            home_var = self.catalog["platforms"][platform]["home_var"]
            return {pattern.replace("\\", "/").removeprefix(f"{home_var}/") for _tool, _family, pattern in self._catalog_tuples(platform)}

        windows = relative_patterns("windows")
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform):
                expected = windows | ({".codex/memories/extensions/skysight"} if platform == "darwin" else set())
                self.assertEqual(expected, relative_patterns(platform))

    def test_antigravity_mcp_uses_canonical_family(self) -> None:
        for platform in self.catalog["platforms"]:
            with self.subTest(platform=platform):
                matches = [
                    family
                    for tool, family, pattern in self._catalog_tuples(platform)
                    if tool == "antigravity_cli" and pattern.replace("\\", "/").endswith("/mcp_config.json")
                ]
                self.assertEqual(matches, ["mcp"])

    def test_release_metadata_preserves_execution_tiers(self) -> None:
        self.assertNotIn("loader_triage_contract", self.release_metadata)
        self.assertNotIn("select_contract", self.release_metadata)
        self.assertNotIn("standalone_hint_contract", self.release_metadata)
        self.assertEqual(
            self.release_metadata["execution_tiers"]["analysis_boundary"],
            "Executable inspection emits only allowlisted metadata and skips session bodies; downloaded session content parsing belongs to the Python sessions command",
        )

        arguments = {item["name"]: item for item in self.release_metadata["arguments"]}
        self.assertNotIn("summary", arguments)
        self.assertNotIn("paths", arguments)
        self.assertNotIn("analyze", arguments)
        self.assertNotIn("tsv", arguments)
        self.assertNotIn("jsonl", arguments)
        self.assertTrue(arguments["help"]["standalone_only"])
        self.assertTrue(arguments["version"]["standalone_only"])
        self.assertNotIn("include_families", arguments)
        self.assertNotIn("exclude_families", arguments)
        self.assertNotIn("include_path", arguments)
        self.assertNotIn("exclude_path", arguments)

        self.assertEqual(self.release_metadata["loader_arguments"], [])
        self.assertEqual(self.release_metadata["bof_arguments"], [])
        self.assertIn("No-argument", self.release_metadata["execution_tiers"]["windows_bof"])
        self.assertIn("no-argument", self.release_metadata["execution_tiers"]["posix_loaders"])
        self.assertTrue(arguments["include_tools"]["standalone_only"])
        self.assertTrue(arguments["exclude_tools"]["standalone_only"])

    def test_confirmed_artifacts_declare_assessment_coverage(self) -> None:
        catalog = json.loads(
            (self.repo_root / "blacklight-rules" / "catalog" / "confirmed_artifacts.json").read_text(encoding="utf-8")
        )
        allowed = {"explicitly_assessed", "recursively_discovered", "intentionally_deferred"}
        self.assertEqual(set(catalog["assessment_coverage_states"]), allowed)
        self.assertTrue(catalog["artifacts"])
        for artifact in catalog["artifacts"]:
            with self.subTest(artifact=artifact["id"]):
                self.assertIn(artifact.get("assessment_coverage"), allowed)
        by_id = {artifact["id"]: artifact for artifact in catalog["artifacts"]}
        for artifact_id in ("codex.rules_discovered", "claude.project_mcp_config", "cursor.project_mcp_config"):
            self.assertEqual(by_id[artifact_id]["assessment_coverage"], "recursively_discovered")
        self.assertEqual(by_id["cursor.plan_metadata"]["assessment_coverage"], "recursively_discovered")

    def test_cursor_durable_profile_artifacts_are_cataloged(self) -> None:
        catalog = json.loads(
            (self.repo_root / "blacklight-rules" / "catalog" / "confirmed_artifacts.json").read_text(encoding="utf-8")
        )
        by_id = {artifact["id"]: artifact for artifact in catalog["artifacts"]}
        expected = {
            "cursor.mcp_config": ("mcp", ".cursor/mcp.json", "file", "high"),
            "cursor.agents": ("config", ".cursor/agents", "directory", "medium"),
            "cursor.plugins": ("plugins", ".cursor/plugins", "directory", "medium"),
            "cursor.extensions_manifest": ("extensions", ".cursor/extensions/extensions.json", "file", "medium"),
        }
        for artifact_id, values in expected.items():
            with self.subTest(artifact_id=artifact_id):
                artifact = by_id[artifact_id]
                self.assertEqual(
                    (artifact["family"], artifact["relative_path"], artifact["path_kind"], artifact["priority"]),
                    values,
                )
                self.assertEqual(artifact["assessment_coverage"], "explicitly_assessed")

    def test_windows_bof_has_one_unfiltered_triage_path(self) -> None:
        source = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_bof.c").read_text(encoding="utf-8")
        self.assertNotIn("BeaconDataParse", source)
        self.assertNotIn("BeaconDataExtract", source)
        self.assertNotIn("bof_emit_path", source)
        self.assertNotIn("bl_loader_filter_tool", source)
        self.assertIn("bof_emit_triage", source)
        self.assertIn("print_bof_human_triage_summary(&results)", source)
        self.assertIn("g_session_artifact_counts", source)
        self.assertNotIn("PHASE 2: SESSION DOWNLOAD", source)
        self.assertIn("PRIORITIZED SESSION ARTIFACTS (newest first)", source)
        self.assertLess(source.index("last_write_time.dwHighDateTime"), source.index("left->size_bytes != right->size_bytes"))

    def test_macos_release_artifacts_are_documented_as_universal(self) -> None:
        darwin_arches = {
            item["object"]: item["arch"]
            for item in self.release_metadata["artifacts"]
            if item["platform"] == "darwin"
        }
        self.assertEqual(darwin_arches, {"libai_path_scout.dylib": "universal"})


if __name__ == "__main__":
    unittest.main()
