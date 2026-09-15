"""Native fixture checks; Linux can exercise the Darwin catalog, not macOS ABI."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCOUT = ROOT / "blacklight-scout"
PATTERN = "$HOME/.codex/memories/extensions/skysight"


class ComputerHistoryCatalogTests(unittest.TestCase):
    def test_platform_and_family(self):
        catalog = json.loads((SCOUT / "catalog/targets.json").read_text())
        for platform, profile in catalog["platforms"].items():
            matches = [t for t in profile["targets"] if "skysight" in t["pattern"]]
            self.assertEqual(matches, [{"tool": "codex", "family": "memories", "pattern": PATTERN}]
                             if platform == "darwin" else [])

    def test_generated_header_is_current(self):
        spec = importlib.util.spec_from_file_location("targets_generator", SCOUT / "catalog/generate_targets.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.render_c_header(module.load_catalog()),
                         (SCOUT / "catalog/static_targets_generated.h").read_text())


@unittest.skipUnless(os.name == "posix" and shutil.which("cc"), "requires POSIX C compiler")
class ComputerHistoryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="blacklight-memory-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / "scout"
        subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Wno-unused-parameter",
                        "-D__APPLE__", "-I", str(SCOUT / "native"),
                        str(SCOUT / "native/ai_path_scout_posix.c"),
                        str(SCOUT / "native/ai_path_scout_core.c"), "-o", str(cls.binary)], check=True)

    def test_roots_and_metadata_boundary(self):
        with tempfile.TemporaryDirectory(prefix="blacklight home ") as folder:
            home = Path(folder)
            default = home / ".codex/memories/extensions/skysight"
            override = home / "custom root/memories/extensions/skysight"
            env = dict(os.environ, HOME=str(home))
            env.pop("CODEX_HOME", None)
            def run():
                return subprocess.check_output([str(self.binary)], env=env, text=True)
            baseline = run()
            self.assertNotIn("skysight", baseline)
            for path in (default, override):
                path.mkdir(parents=True)
                (path / "private.md").write_text("BLACKLIGHT_PRIVATE_MEMORY_SENTINEL")
            for root, expected in ((None, default), ("", default), (str(home / "custom root"), override)):
                with self.subTest(root=root):
                    if root is None:
                        env.pop("CODEX_HOME", None)
                    else:
                        env["CODEX_HOME"] = root
                    output = run()
                    self.assertIn(str(expected), output)
                    self.assertIn("memories", output)
                    self.assertNotIn(str(override if expected == default else default), output)
                    self.assertNotIn("BLACKLIGHT_PRIVATE_MEMORY_SENTINEL", output)
                    self.assertNotIn("private.md", output)
                    self.assertEqual(re.findall(r"Session artifacts:\s*\d+", baseline),
                                     re.findall(r"Session artifacts:\s*\d+", output))
            env["CODEX_HOME"] = str(home / "missing root")
            self.assertNotIn("skysight", run())
