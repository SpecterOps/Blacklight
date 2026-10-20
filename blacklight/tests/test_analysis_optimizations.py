from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blacklight import analyze
from blacklight.common import first_value
from blacklight.sessions import run_sessions_analysis


def exhaustive_matches(fragment):
    matches = []
    for rule in analyze.INDICATOR_RULES:
        for match in rule.pattern.finditer(fragment):
            value = match.group(0)
            context = fragment[max(0, match.start() - 80):match.end() + 80]
            if analyze._valid_indicator_match(rule, value, context):
                matches.append((rule, value))
    return tuple(matches)


class AnalysisOptimizationTests(unittest.TestCase):
    def test_prefilters_preserve_every_rule_and_unicode_case_matching(self):
        examples = [
            'api-key = abcdefgh12345678',
            'AKIA1234567890ABCDEF',
            '-----BEGIN PRIVATE KEY-----',
            'postgres://user:password@db.example/database',
            'server=db.example;database=example',
            '10.1.2.3 172.16.2.3 192.168.1.2',
            'localhost 127.0.0.1 ::1',
            'db.internal',
            'ssh host prod-server',
            'arn:aws:iam::123456789012:role/example',
            'aws account_id=123456789012',
            'tenant_id=12345678-1234-1234-1234-123456789abc',
            'account@project-name.iam.gserviceaccount.com',
            'db.example:443',
            '10.1.2.3:443',
            'https://example.com/repo.git',
            '/Users/example/.codex/sessions/example.jsonl',
            r'C:\Users\example\.codex\sessions\example.jsonl',
        ]
        covered = set()
        for example in examples:
            variants = [example, example.upper(), example.lower()]
            for character, replacement in [('i', 'İ'), ('i', 'ı'), ('s', 'ſ'), ('k', 'K')]:
                variants.append(example.replace(character, replacement))
            for fragment in variants:
                with self.subTest(fragment=fragment):
                    expected = exhaustive_matches(fragment)
                    covered.update(rule.rule_id for rule, _ in expected)
                    self.assertEqual(analyze._indicator_matches(fragment), expected)
        self.assertEqual(covered, {rule.rule_id for rule in analyze.INDICATOR_RULES})
        combined = '\n'.join(examples * 2)
        self.assertEqual(analyze._indicator_matches(combined), exhaustive_matches(combined))
        self.assertEqual(analyze._indicator_matches('ordinary text without indicators'), ())

    def test_cached_fragments_preserve_session_role_counts_and_large_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = 'token=abcdefgh12345678 ssh db.internal:443'
            records = [
                {'session_id': session, 'role': role, 'content': text}
                for session in ('one', 'two')
                for role in ('user', 'assistant', 'tool')
                for _ in range(2)
            ]
            records.append({'session_id': 'two', 'role': 'user', 'content': ' ' * 65537 + text})
            source = root / 'codex.jsonl'
            source.write_text('\n'.join(json.dumps(record) for record in records))
            def scan():
                run_sessions_analysis(source, run_id='test', output_directory=root / 'reports')
                report = json.loads((root / 'reports/test_Session_Report.json').read_text())
                report.pop('collected_at_utc')
                return report
            cached = scan()
            with patch.object(analyze, 'lru_cache', side_effect=lambda **kwargs: lambda fn: fn), patch.object(
                analyze, '_indicator_matches', side_effect=exhaustive_matches
            ):
                self.assertEqual(cached, scan())
            self.assertEqual(cached['summary']['sessions_recovered'], 2)

    def test_first_value_preserves_precedence_scalars_and_iterable_keys(self):
        value = {'nested': [{'NAME': 'nested'}], 'Name': {'child': 'container'}}
        self.assertEqual(first_value(value, iter(['NAME'])), {'child': 'container'})
        self.assertEqual(first_value(value, ['name'], scalar_only=True), 'nested')
        self.assertEqual(first_value([None, '', 4, {'NAME': False}], ['name']), False)
        self.assertEqual(first_value({'Name': '', 'nested': {'name': 0}}, ['name']), 0)
        self.assertIsNone(first_value(['name', 42, {'other': 'value'}], ['name']))
