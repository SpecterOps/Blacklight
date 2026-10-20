from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from blacklight.opencode_sessions import opencode_records
from blacklight.sessions import run_sessions_analysis


class OpenCodeSessionTests(unittest.TestCase):
    def test_both_generations_and_wal_are_analyzed_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'opencode.db'
            connection = sqlite3.connect(path)
            try:
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA wal_autocheckpoint=0')
                for table in ('session', 'session_v2'):
                    connection.execute(f'CREATE TABLE {table} (id TEXT,title TEXT,directory TEXT,time_created INTEGER)')
                    connection.execute(f'INSERT INTO {table} VALUES (?,?,?,?)', ('same', 'fixture', '/work', 1700000000000))
                connection.execute('CREATE TABLE message (id TEXT,session_id TEXT,time_created INTEGER,data TEXT)')
                connection.execute('CREATE TABLE part (id TEXT,message_id TEXT,time_created INTEGER,data TEXT)')
                connection.execute('CREATE TABLE session_message (id TEXT,session_id TEXT,type TEXT,seq INTEGER,time_created INTEGER,data TEXT)')
                connection.execute('CREATE TABLE credential (value TEXT)')
                connection.execute('INSERT INTO credential VALUES (?)', ('SYNTHETIC-CREDENTIAL-NOT-CHAT',))
                connection.execute('INSERT INTO message VALUES (?,?,?,?)', ('m1', 'same', 1700000000000, json.dumps({'role': 'user'})))
                connection.execute('INSERT INTO part VALUES (?,?,?,?)', ('p1', 'm1', 1700000000000, json.dumps({'type': 'text', 'text': 'inspect 10.2.3.4'})))
                connection.execute('INSERT INTO session_message VALUES (?,?,?,?,?,?)', ('m2', 'same', 'assistant', 1, 1700000000001, json.dumps({'content': [{'type': 'text', 'text': 'checked 10.2.3.4'}]})))
                connection.commit()
                records = list(opencode_records(path))
                self.assertEqual({r['session_id'] for r in records}, {'v1:same', 'v2:same'})
                self.assertEqual([r['role'] for r in records if r['content']], ['user', 'assistant'])
                result = run_sessions_analysis(path, run_id='OPENCODE', output_directory=root / 'reports')
                self.assertEqual(result['summary']['sessions_recovered'], 2)
                report = json.loads(Path(result['reports']['session_report']['json']).read_text())
                self.assertEqual(len(report['top_sessions']), 2)
                self.assertNotIn('SYNTHETIC-CREDENTIAL-NOT-CHAT', json.dumps(report))
            finally:
                connection.close()

    def test_invalid_message_payload_is_reported_as_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'opencode.db'
            with sqlite3.connect(path) as connection:
                connection.execute('CREATE TABLE session_v2 (id TEXT,title TEXT,directory TEXT,time_created INTEGER)')
                connection.execute('CREATE TABLE session_message (id TEXT,session_id TEXT,type TEXT,time_created INTEGER,data TEXT)')
                connection.execute("INSERT INTO session_v2 VALUES ('s','fixture','/work',1)")
                connection.execute("INSERT INTO session_message VALUES ('m','s','user',1,'broken')")
            result = run_sessions_analysis(path, run_id='BROKEN', output_directory=Path(directory) / 'reports')
            self.assertEqual(result['summary']['parse_failures'], 1)
