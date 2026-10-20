from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blacklight.session_input import discover_local_session_inputs


class GrokMemoryBoundaryTests(unittest.TestCase):
    def test_memory_v2_is_not_opened_by_local_session_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            memory = home / ".grok/memory-v2/global/MEMORY.md"
            memory.parent.mkdir(parents=True)
            memory.write_text("synthetic persistent memory", encoding="utf-8")
            chats = home / ".grok/sessions/fixture/chat_history.jsonl"
            chats.parent.mkdir(parents=True)
            chats.write_text('{"type":"user","content":"synthetic chat"}\n', encoding="utf-8")
            original_open = Path.open

            def selected_open(path: Path, *args: object, **kwargs: object):
                self.assertNotIn("memory-v2", path.parts)
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", selected_open):
                discovery = discover_local_session_inputs(home, tool="grok")
            self.assertEqual([source.path for source in discovery.sources], [chats.resolve()])
