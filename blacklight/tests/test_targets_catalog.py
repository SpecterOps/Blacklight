from __future__ import annotations

import json
import importlib.util
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
        self.assertEqual(
            self.catalog["tools"],
            [
                "codex",
                "claude_code",
                "cursor",
                "antigravity_cli",
                "grok",
                "devin",
                "strands",
                "kiro",
                "opencode",
                "muse_code",
            ],
        )
        self.assertEqual(self.release_metadata["tools"], self.catalog["tools"])

    def test_collection_matrix_is_current_and_linked(self) -> None:
        generator_path = self.repo_root / "blacklight-scout" / "catalog" / "generate_targets.py"
        spec = importlib.util.spec_from_file_location("generate_targets", generator_path)
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        artifacts = json.loads(generator.ARTIFACTS_JSON.read_text(encoding="utf-8"))
        matrix = generator.MATRIX_OUT.read_text(encoding="utf-8")
        self.assertEqual(matrix, generator.render_matrix(self.catalog, artifacts))
        for tool in self.catalog["tools"]:
            self.assertIn(f"### {tool}", matrix)
        for artifact in artifacts["artifacts"]:
            self.assertIn(artifact["relative_path"].replace("|", "&#124;"), matrix)
        for platform, profile in self.catalog["platforms"].items():
            for target in profile["targets"]:
                self.assertIn(generator.relative_pattern(target["pattern"], profile["home_var"]), matrix)
        self.assertIn("(docs/matrix.md)", (self.repo_root / "README.md").read_text(encoding="utf-8"))

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
        session_input = (self.repo_root / "blacklight" / "session_input.py").read_text(encoding="utf-8").lower()
        self.assertIn("grok", session_input)
        self.assertNotIn("auth.json", session_input)
        self.assertNotIn("memory-v2", session_input)
        native_windows = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_windows.c").read_text(encoding="utf-8")
        managed_windows = (self.repo_root / "blacklight-scout" / "managed" / "Program.cs").read_text(encoding="utf-8")
        self.assertIn('target_tool_is(target, "grok")', native_windows)
        self.assertIn('EqualsCi(result.Tool, "grok")', managed_windows)
        self.assertIn("inspection=deferred", native_windows)
        self.assertIn("inspection=deferred", managed_windows)

    def test_devin_and_strands_support_is_existence_enum_only(self) -> None:
        expected_devin = {
            ("root", ".local/bin/devin"),
            ("root", ".local/share/devin"),
            ("root", ".local/share/devin/cli"),
            ("root", ".local/share/devin/cli/_versions"),
            ("root", ".local/share/devin/cli/_versions/current/bin/devin"),
            ("auth", ".local/share/devin/credentials.toml"),
            ("sessions", ".local/share/devin/cli/sessions.db"),
            ("sessions", "AppData/Local/devin/cli/sessions.db"),
            ("mcp", ".config/devin/mcp_config.json"),
            ("mcp", "AppData/Roaming/devin/mcp_config.json"),
            ("logs", ".local/share/devin/cli/logs"),
            ("root", ".local/share/cognition"),
            ("root", ".local/share/chisel"),
            ("config", ".config/devin"),
            ("config", ".config/cognition"),
            ("cache", ".cache/devin"),
            ("cache", ".cache/cognition"),
            ("root", "AppData/Local/devin"),
            ("root", "AppData/Local/devin/cli"),
            ("root", "AppData/Local/devin/cli/bin/devin.exe"),
            ("root", "AppData/Local/devin/cli/_versions"),
            ("root", "AppData/Local/devin/bin/devin.exe"),
            ("logs", "AppData/Roaming/devin/cli/logs"),
        }
        expected_strands = {
            ("root", ".strands"),
            ("root", ".strands/cli"),
            ("config", ".strands/cli/config.json"),
            ("sessions", ".strands/cli/session-roots.json"),
            ("root", ".local/bin/strands"),
            ("root", "AppData/Roaming/npm/strands.cmd"),
            ("root", "AppData/Roaming/npm/strands"),
        }
        for tool, expected in (("devin", expected_devin), ("strands", expected_strands)):
            actual = {
                (family, pattern.replace("\\", "/").removeprefix("%USERPROFILE%/"))
                for entry_tool, family, pattern in self._catalog_tuples("windows")
                if entry_tool == tool
            }
            with self.subTest(tool=tool):
                self.assertEqual(actual, expected)
        native_windows = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_windows.c").read_text(
            encoding="utf-8"
        )
        managed_windows = (self.repo_root / "blacklight-scout" / "managed" / "Program.cs").read_text(encoding="utf-8")
        self.assertIn('target_tool_is(target, "devin")', native_windows)
        self.assertIn('target_tool_is(target, "strands")', native_windows)
        self.assertIn('EqualsCi(result.Tool, "devin")', managed_windows)
        self.assertIn('EqualsCi(result.Tool, "strands")', managed_windows)
        session_input = (self.repo_root / "blacklight" / "session_input.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("devin", session_input)
        self.assertNotIn("strands", session_input)

    def test_kiro_and_opencode_support_is_existence_enum_only(self) -> None:
        expected_kiro = {
            ("root", ".kiro"),
            ("config", ".kiro/settings"),
            ("config", ".kiro/settings/cli.json"),
            ("mcp", ".kiro/settings/mcp.json"),
            ("config", ".kiro/agents"),
            ("skills", ".kiro/skills"),
            ("rules", ".kiro/steering"),
            ("config", ".kiro/hooks"),
            ("sessions", ".kiro/sessions"),
            ("sessions", ".kiro/sessions/cli"),
            ("history", ".kiro/memories"),
            ("root", ".local/bin/kiro-cli"),
            ("root", ".local/bin/kiro-cli-chat"),
            ("root", ".local/bin/q"),
            ("root", ".local/share/kiro-cli"),
            ("auth", ".local/share/kiro-cli/data.sqlite3"),
            ("root", "Library/Application Support/kiro-cli"),
            ("auth", "Library/Application Support/kiro-cli/data.sqlite3"),
            ("root", "AppData/Roaming/kiro-cli"),
            ("auth", "AppData/Roaming/kiro-cli/data.sqlite3"),
            ("root", "AppData/Local/kiro-cli"),
            ("root", "AppData/Local/Kiro-Cli"),
            ("root", ".local/share/amazon-q"),
            ("auth", ".local/share/amazon-q/data.sqlite3"),
            ("config", ".aws/amazonq"),
            ("mcp", ".aws/amazonq/mcp.json"),
            ("root", "AppData/Local/amazon-q"),
            ("root", "Library/Application Support/amazon-q"),
        }
        expected_opencode = {
            ("root", ".opencode"),
            ("root", ".opencode/bin"),
            ("root", ".opencode/bin/opencode"),
            ("root", ".local/share/opencode"),
            ("auth", ".local/share/opencode/auth.json"),
            ("auth", ".local/share/opencode/opencode.db"),
            ("auth", ".local/share/opencode/opencode.db-wal"),
            ("auth", ".local/share/opencode/opencode.db-shm"),
            ("logs", ".local/share/opencode/log"),
            ("sessions", ".local/share/opencode/project"),
            ("config", ".config/opencode"),
            ("config", ".config/opencode/opencode.json"),
            ("config", ".config/opencode/opencode.jsonc"),
            ("config", ".config/opencode/cli.json"),
            ("plugins", ".config/opencode/plugins"),
            ("cache", ".cache/opencode"),
            ("root", ".local/state/opencode"),
            ("config", ".local/share/opencode/opencode.json"),
            ("config", ".local/share/opencode/opencode.jsonc"),
        }
        for tool, expected in (("kiro", expected_kiro), ("opencode", expected_opencode)):
            actual = {
                (family, pattern.replace("\\", "/").removeprefix("%USERPROFILE%/"))
                for entry_tool, family, pattern in self._catalog_tuples("windows")
                if entry_tool == tool
            }
            with self.subTest(tool=tool):
                self.assertEqual(actual, expected)
        native_windows = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_windows.c").read_text(
            encoding="utf-8"
        )
        managed_windows = (self.repo_root / "blacklight-scout" / "managed" / "Program.cs").read_text(encoding="utf-8")
        self.assertIn('target_tool_is(target, "kiro")', native_windows)
        self.assertIn('target_tool_is(target, "opencode")', native_windows)
        self.assertIn('EqualsCi(result.Tool, "kiro")', managed_windows)
        self.assertIn('EqualsCi(result.Tool, "opencode")', managed_windows)
        session_input = (self.repo_root / "blacklight" / "session_input.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("kiro", session_input)
        self.assertIn("opencode", session_input)

    def test_muse_code_support_is_existence_enum_only(self) -> None:
        expected = {
            ("root", ".local/bin/muse"),
            ("root", "AppData/Local/Programs/muse"),
            ("config", ".config/muse"),
            ("config", ".config/muse/settings.json"),
            ("auth", ".config/muse/auth.json"),
            ("config", ".config/muse/trust.json"),
            ("skills", ".config/muse/skills"),
            ("root", ".local/share/muse"),
            ("sessions", ".local/share/muse/sessions"),
            ("sessions", ".local/share/muse/session-index.db"),
            ("workspace", ".local/share/muse/memory"),
            ("cache", ".local/share/muse/model-catalog"),
            ("logs", ".local/share/muse/crashes"),
            ("logs", ".local/share/muse/local-tracing"),
            ("plugins", ".local/share/muse/plugins"),
            ("workspace", ".muse/projects"),
        }
        actual = {
            (family, pattern.replace("\\", "/").removeprefix("%USERPROFILE%/"))
            for entry_tool, family, pattern in self._catalog_tuples("windows")
            if entry_tool == "muse_code"
        }
        self.assertEqual(actual, expected)
        for forbidden in (".agents/", ".muse/hooks.json", ".mcp.json", "AGENTS.md"):
            self.assertFalse(any(forbidden in path for _family, path in actual), forbidden)
        native_windows = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_windows.c").read_text(
            encoding="utf-8"
        )
        managed_windows = (self.repo_root / "blacklight-scout" / "managed" / "Program.cs").read_text(encoding="utf-8")
        native_core = (self.repo_root / "blacklight-scout" / "native" / "ai_path_scout_core.c").read_text(
            encoding="utf-8"
        )
        self.assertIn('target_tool_is(target, "muse_code")', native_windows)
        self.assertIn('EqualsCi(result.Tool, "muse_code")', managed_windows)
        self.assertIn('"MUSE CODE"', native_windows)
        self.assertIn('return "MUSE CODE"', managed_windows)
        self.assertIn('bl_ascii_equal_n(value, value_len, "muse")', native_core)
        self.assertIn('EqualsCi(filter, "muse")', managed_windows)
        session_input = (self.repo_root / "blacklight" / "session_input.py").read_text(encoding="utf-8").lower()
        self.assertIn("muse_code", session_input)
        self.assertIn("muse", session_input)

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
