from __future__ import annotations

import json
import re
import sqlite3
import unittest
from pathlib import Path


class BlacklightRulesContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[2]
        cls.rules_root = cls.repo_root / "blacklight-rules"
        cls.catalog = json.loads((cls.rules_root / "catalog" / "confirmed_artifacts.json").read_text(encoding="utf-8"))
        cls.scout_catalog = json.loads((cls.repo_root / "blacklight-scout" / "catalog" / "targets.json").read_text(encoding="utf-8"))

    def test_catalog_covers_all_scout_targets(self) -> None:
        catalog_paths = {item["relative_path"] for item in self.catalog["artifacts"]}
        scout_paths = {
            item["pattern"].replace("\\", "/").removeprefix("%USERPROFILE%/")
            for item in self.scout_catalog["platforms"]["windows"]["targets"]
        }
        self.assertEqual(set(), scout_paths - catalog_paths)

    def test_catalog_evidence_references_resolve(self) -> None:
        self.assertEqual("blacklight.rules.catalog.v2", self.catalog["schema_version"])
        sources = self.catalog["evidence_sources"]
        referenced = {ref for item in self.catalog["artifacts"] for ref in item["confirmed_by"]}
        self.assertEqual(set(), referenced - set(sources))
        for name, source in sources.items():
            with self.subTest(source=name):
                evidence_path = self.repo_root / source["path"]
                self.assertTrue(evidence_path.is_file())
                if symbol := source.get("symbol"):
                    self.assertRegex(evidence_path.read_text(encoding="utf-8"), rf"def\s+{re.escape(symbol)}\s*\(")

    def test_catalog_ids_are_unique(self) -> None:
        ids = [item["id"] for item in self.catalog["artifacts"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_grok_catalog_is_recon_only_and_detection_covered(self) -> None:
        grok = [item for item in self.catalog["artifacts"] if item["tool"] == "grok"]
        self.assertTrue(grok)
        for item in grok:
            with self.subTest(artifact=item["id"]):
                self.assertEqual(item["assessment_coverage"], "explicitly_assessed")
                self.assertNotIn("blacklight.analyze.run_session_detail", item["confirmed_by"])
        self.assertIn("\\.grok", self.catalog["detection_boundaries"]["windows_roots"])
        self.assertIn("/.grok", self.catalog["detection_boundaries"]["posix_roots"])

    def test_scout_and_rules_families_align_for_windows_targets(self) -> None:
        catalog_by_path = {item["relative_path"]: item["family"] for item in self.catalog["artifacts"]}
        scout_by_path = {
            item["pattern"].replace("\\", "/").removeprefix("%USERPROFILE%/"): item["family"]
            for item in self.scout_catalog["platforms"]["windows"]["targets"]
        }
        mismatches = {
            path: {"scout": family, "rules": catalog_by_path.get(path)}
            for path, family in scout_by_path.items()
            if catalog_by_path.get(path) != family
        }
        self.assertEqual({}, mismatches)

    def test_catalog_keeps_expected_parser_only_paths(self) -> None:
        catalog_ids = {item["id"] for item in self.catalog["artifacts"]}
        self.assertTrue(
            {
                "codex.sandbox_users",
                "codex.rules_default",
                "claude.projects_sessions_index",
                "claude.mcp_needs_auth",
                "cursor.ai_tracking",
                "cursor.chat_store",
                "cursor.agent_transcripts",
                "antigravity_cli.transcripts",
                "antigravity_cli.conversation_summaries",
            }.issubset(catalog_ids)
        )

    def test_rules_pack_has_expected_delivery_surfaces(self) -> None:
        expected_files = [
            "detection/windows/telemetry.md",
            "detection/linux/osquery-telemetry.md",
            "detection/macos/osquery-telemetry.md",
            "inventory/blacklight_artifact_inventory_windows.sql",
            "inventory/blacklight_artifact_inventory_posix.sql",
            "inventory/blacklight_exposed_artifacts_posix.sql",
            "powershell/Invoke-BlacklightWindowsTelemetry.ps1",
        ]
        for relative_path in expected_files:
            with self.subTest(relative_path=relative_path):
                self.assertTrue((self.rules_root / relative_path).is_file())

    def test_query_pack_names_five_hunt_surfaces(self) -> None:
        content = (self.rules_root / "detection" / "windows" / "telemetry.md").read_text(encoding="utf-8")
        for platform in ("Splunk SPL", "Microsoft Sentinel KQL", "Elastic Security KQL", "Google SecOps UDM Search", "Microsoft Defender XDR Advanced Hunting"):
            with self.subTest(platform=platform):
                self.assertIn(platform, content)

    def test_cursor_tracking_db_uses_telemetry_family_in_rule_surfaces(self) -> None:
        surfaces = [
            self.rules_root / "inventory" / "blacklight_artifact_inventory_windows.sql",
            self.rules_root / "inventory" / "blacklight_artifact_inventory_posix.sql",
            self.rules_root / "inventory" / "blacklight_exposed_artifacts_posix.sql",
        ]
        for path in surfaces:
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                self.assertIn("telemetry", content)
                self.assertNotRegex(content, r"cursor['\"]?\s*,\s*['\"]sessions['\"].*ai-code-tracking\.db")

    def test_osquery_inventory_covers_every_non_glob_catalog_artifact(self) -> None:
        windows = (self.rules_root / "inventory" / "blacklight_artifact_inventory_windows.sql").read_text(encoding="utf-8")
        posix = (self.rules_root / "inventory" / "blacklight_artifact_inventory_posix.sql").read_text(encoding="utf-8")
        for item in self.catalog["artifacts"]:
            if item["path_kind"] == "glob":
                continue
            with self.subTest(artifact=item["id"]):
                if "windows" in item.get("platforms", ["windows", "darwin", "linux"]):
                    self.assertIn("\\" + item["relative_path"].replace("/", "\\"), windows)
                self.assertIn("/" + item["relative_path"], posix)

    def test_codex_sqlite_families_are_metadata_only_and_version_flexible(self) -> None:
        expected = {
            "logs": "logs",
            "thread_history": "thread_history",
            "state": "state",
            "memories": "memories",
            "goals": "goals",
        }
        entries = {
            item["family"]: item
            for item in self.catalog["artifacts"]
            if item["id"].startswith("codex.") and item["id"].endswith("_sqlite")
        }
        self.assertEqual(set(entries), set(expected))
        for family, stem in expected.items():
            with self.subTest(family=family):
                item = entries[family]
                self.assertEqual(item["relative_path"], f".codex/{stem}_*.sqlite")
                self.assertEqual(item["path_kind"], "glob")
                self.assertEqual(item["platforms"], ["windows", "darwin", "linux"])
                self.assertEqual(item["assessment_coverage"], "recursively_discovered")
                self.assertIn("one or more ASCII digits", item["note"])
                self.assertIn("not opened or parsed", item["note"])

        sql = (self.rules_root / "inventory" / "blacklight_artifact_inventory_posix.sql").read_text(encoding="utf-8")
        self.assertIn("file.directory = user_homes.directory || '/.codex'", sql)
        self.assertIn("file.type = 'regular'", sql)
        for stem in expected.values():
            with self.subTest(stem=stem):
                self.assertIn(f"^{stem}_[0-9]+[.]sqlite$", sql)

    def test_posix_codex_sqlite_inventory_matches_only_direct_digit_named_files(self) -> None:
        sql = (self.rules_root / "inventory" / "blacklight_artifact_inventory_posix.sql").read_text(encoding="utf-8")
        connection = sqlite3.connect(":memory:")
        connection.create_function(
            "regex_match",
            3,
            lambda value, pattern, index: (match.group(int(index)) if (match := re.search(pattern, value or "")) else None),
        )
        connection.executescript(
            """
            CREATE TABLE users (username TEXT, directory TEXT);
            CREATE TABLE os_version (platform TEXT);
            CREATE TABLE file (
              path TEXT, directory TEXT, filename TEXT, type TEXT,
              uid INTEGER, gid INTEGER, mode TEXT, size INTEGER, mtime INTEGER
            );
            INSERT INTO users VALUES ('tester', '/home/tester');
            INSERT INTO os_version VALUES ('linux');
            """
        )
        root = "/home/tester/.codex"
        candidates = [
            ("logs_6.sqlite", root, "regular"),
            ("thread_history_6.sqlite", root, "regular"),
            ("state_5.sqlite", root, "regular"),
            ("memories_1.sqlite", root, "regular"),
            ("goals_1.sqlite", root, "regular"),
            ("logs.sqlite", root, "regular"),
            ("logs_abc.sqlite", root, "regular"),
            ("logs_2abc.sqlite", root, "regular"),
            ("logs_3.sqlite-wal", root, "regular"),
            ("logs_4.sqlite", root + "/nested", "regular"),
            ("logs_5.sqlite", root, "symlink"),
        ]
        for filename, directory, file_type in candidates:
            connection.execute(
                "INSERT INTO file VALUES (?, ?, ?, ?, 1000, 1000, '0600', 128, 1)",
                (directory + "/" + filename, directory, filename, file_type),
            )

        rows = connection.execute(sql).fetchall()
        matched = {(row[1], row[3].rsplit("/", 1)[-1]) for row in rows}
        self.assertEqual(
            matched,
            {
                ("logs", "logs_6.sqlite"),
                ("thread_history", "thread_history_6.sqlite"),
                ("state", "state_5.sqlite"),
                ("memories", "memories_1.sqlite"),
                ("goals", "goals_1.sqlite"),
            },
        )
        connection.close()

    def test_windows_telemetry_configuration_is_audit_first_and_reversible(self) -> None:
        windows = (self.rules_root / "powershell" / "Invoke-BlacklightWindowsTelemetry.ps1").read_text(encoding="utf-8")
        self.assertIn("[string]$Mode = 'Audit'", windows)
        self.assertIn("'Apply', 'Rollback'", windows)
        self.assertIn("/backup", windows)
        self.assertIn("/restore", windows)
        self.assertIn("blacklight.windows-telemetry-state.v2", windows)
        self.assertIn("AccessControlSections]::Audit", windows)
        self.assertNotIn(
            "SetSecurityDescriptorSddlForm([string]$Entry.Sddl, [System.Security.AccessControl.AccessControlSections]::All)",
            windows,
        )
        self.assertIn("SCENoApplyLegacyAuditPolicy", windows)
        self.assertIn("LegacyAuditPolicyOverride", windows)
        self.assertIn("Remove-TelemetryStateFiles", windows)
        self.assertIn("Remove-Item -LiteralPath", windows)
        self.assertIn("automatic rollback", windows)
        self.assertIn("Protect-AdminOnlyPath", windows)
        self.assertIn("RequireFailure", windows)
        self.assertIn("Invoke-Wevtutil", windows)
        self.assertIn("Get-CurrentUserHomeRoot", windows)
        self.assertNotIn("Win32_UserProfile", windows)
        self.assertNotIn("HomeRoots", windows)


if __name__ == "__main__":
    unittest.main()
