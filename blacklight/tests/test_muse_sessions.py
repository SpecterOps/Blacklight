from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from blacklight.muse_sessions import iter_muse_records
from blacklight.session_input import discover_local_session_inputs
from blacklight.sessions import run_sessions_analysis


def event(kind, payload):
    return {'schema_version': 1, 'id': kind, 'stream': {'kind': 'session', 'id': 'fixture'},
            'sequence': 1, 'recorded_at': 1700000000000000, 'record_type': 'event',
            'payload_type': kind, 'payload': payload}


class MuseSessionTests(unittest.TestCase):
    def test_unknown_events_are_skipped_and_started_prompt_is_not_duplicated(self):
        records = [
            {'record_type': 'future', 'payload': {'content': 'UNKNOWN-RECORD-BODY'}},
            event('runtime.session.metadata', {'record': {'workspace_root': '/work'}}),
            event('runtime.future', {'text': 'UNKNOWN-PAYLOAD-BODY'}),
            event('runtime.user_intent.accepted', {'model_messages': [{'content': [{'kind': 'text', 'text': 'inspect 10.2.3.4'}]}]}),
            event('runtime.session', {'kind': 'run', 'event': {'kind': 'started', 'prompt': 'inspect 10.2.3.4'}}),
            event('runtime.session', {'kind': 'run', 'event': {'kind': 'assistant_message_committed', 'text': 'done 10.2.3.4'}}),
            event('runtime.session', {'kind': 'run', 'event': {'kind': 'tool_result_batch_committed', 'results': [{'text': 'synthetic output'}]}}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            path = home / '.local/share/muse/sessions/2026/10/17/fixture/session.jsonl'
            path.parent.mkdir(parents=True)
            path.write_text(''.join(json.dumps(record) + '\n' for record in records))
            parsed = [record for _, record, error in iter_muse_records(path) if not error]
            self.assertEqual([record['role'] for record in parsed], ['system', 'user', 'assistant', 'tool'])
            self.assertNotIn('UNKNOWN', json.dumps(parsed))
            self.assertEqual(len(discover_local_session_inputs(home, tool='muse_code').sources), 1)
            result = run_sessions_analysis(path, run_id='MUSE', output_directory=home / 'reports')
            self.assertEqual(result['summary']['sessions_recovered'], 1)
            report = json.loads(Path(result['reports']['session_report']['json']).read_text())
            self.assertEqual(len(report['top_sessions']), 1)
            session = report['top_sessions'][0]
            self.assertEqual(session['request_count'], 1)
            self.assertEqual(session['response_count'], 1)
            self.assertIsNotNone(session['high_value_detail'])
            path.unlink()
            self.assertEqual(discover_local_session_inputs(home, tool='muse_code').sources, [])

    def test_unknown_only_records_do_not_invent_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.jsonl'
            path.write_text(json.dumps(event('runtime.future', {'text': 'future body'})) + '\n')
            self.assertEqual(list(iter_muse_records(path)), [])
            result = run_sessions_analysis(path, run_id='UNKNOWN', output_directory=Path(directory) / 'reports')
            self.assertEqual(result['summary']['sessions_recovered'], 0)
