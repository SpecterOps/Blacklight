import json
import tempfile
import unittest
from pathlib import Path

from blacklight.antigravity_indexes import fields, index_records
from blacklight.sessions import run_sessions_analysis
from blacklight.session_input import discover_local_session_inputs, discover_session_inputs


def field(number, value):
    def varint(value):
        out = bytearray()
        while value > 127:
            out.append((value & 127) | 128)
            value >>= 7
        return bytes(out) + bytes([value])
    return varint(number << 3 | 2) + varint(len(value)) + value


class AntigravityIndexTests(unittest.TestCase):
    def test_correlation_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identifier = '11111111-1111-1111-1111-111111111111'
            logs = root / 'brain' / identifier / '.system_generated' / 'logs'
            logs.mkdir(parents=True)
            (logs / 'transcript_full.jsonl').write_text(json.dumps({'role': 'user', 'content': 'hello'}) + '\n')
            (root / 'conversation_metadata.json').write_text(json.dumps({'conversations': {
                identifier: {'summary': {'Title': 'JSON title', 'Preview': 'preview', 'NumSteps': 4, 'WorkspaceURIs': ['file:///workspace'], 'UpdatedAt': '2026-01-01T00:00:00Z'}},
                'metadata-only': {'summary': {'Title': 'Index only'}}}}))
            summary = field(1, b'Proto title') + field(9, field(1, b'file:///workspace')) + field(99, b'unknown')
            (root / 'jetbox_summaries_proto.pb').write_bytes(field(1, field(1, identifier.encode()) + field(2, summary)))
            result = run_sessions_analysis(root, output_directory=root / 'reports')
            report = json.loads(Path(result['reports']['session_report']['json']).read_text())
            rows = {row['session_id']: row for row in report['sessions']}
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[identifier]['request_count'], 1)
            self.assertEqual(len(rows[identifier]['index_metadata']), 2)
            self.assertEqual(rows['metadata-only']['response_status'], 'absent_index_only')

    def test_malformed_wire(self):
        for data in (b'\x00', b'\x0a\x7fabc', b'\x08\x80', b'\x0f'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                fields(data)

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'conversation_metadata.json'
            path.write_text('{"conversations": []}')
            with self.assertRaises(ValueError):
                list(index_records(path))

    def test_local_discovery_limits_and_tool_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            root = home / '.gemini' / 'antigravity-cli'
            (root / 'cache').mkdir(parents=True)
            path = root / 'cache' / 'conversation_metadata.json'
            path.write_text('{"conversations": {}}')
            found = discover_local_session_inputs(home_path=home, tool='antigravity_cli')
            self.assertEqual([source.path for source in found.sources], [path.resolve()])
            self.assertFalse(discover_session_inputs(path, tool_hint='codex').sources)
            self.assertFalse(discover_session_inputs(path, max_file_size=1).sources)

    def test_parse_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'jetbox_summaries_proto.pb'
            path.write_bytes(b'\x0a\x7fbroken')
            result = run_sessions_analysis(path, output_directory=Path(directory) / 'reports')
            self.assertGreater(result['summary']['parse_failures'], 0)
            self.assertEqual(result['summary']['sessions_recovered'], 0)
