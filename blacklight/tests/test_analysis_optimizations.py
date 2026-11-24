from __future__ import annotations

import unittest

from blacklight.common import first_value


class AnalysisOptimizationTests(unittest.TestCase):
    def test_first_value_preserves_precedence_scalars_and_iterable_keys(self):
        value = {'nested': [{'NAME': 'nested'}], 'Name': {'child': 'container'}}
        self.assertEqual(first_value(value, iter(['NAME'])), {'child': 'container'})
        self.assertEqual(first_value(value, ['name'], scalar_only=True), 'nested')
        self.assertEqual(first_value([None, '', 4, {'NAME': False}], ['name']), False)
        self.assertEqual(first_value({'Name': '', 'nested': {'name': 0}}, ['name']), 0)
        self.assertIsNone(first_value(['name', 42, {'other': 'value'}], ['name']))
