from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CursorInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[2]
        if os.name != 'posix' or not shutil.which('cc'):
            raise unittest.SkipTest('POSIX Scout inventory tests require cc')
        cls.build = tempfile.TemporaryDirectory(prefix='blacklight-cursor-test-')
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / 'scout'
        native = cls.repo / 'blacklight-scout/native'
        subprocess.run(['cc', '-std=c99', '-Os', '-I'+str(native),
                        '-I'+str(native.parent / 'catalog'), '-o', str(cls.binary),
                        str(native / 'ai_path_scout_posix.c'), str(native / 'ai_path_scout_core.c')],
                       check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='blacklight-cursor-home-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.ide = 'Library/Application Support/Cursor' if sys.platform == 'darwin' else '.config/Cursor'

    def put(self, path, content='SYNTHETIC_SECRET_NOT_FOR_OUTPUT'):
        p = self.home / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def scan(self, verbose=True):
        env = {k: v for k, v in os.environ.items() if k not in
               {'DEVIN_SESSIONS_DIR', 'DEVIN_SESSION_STORE', 'KIRO_HOME', 'KIRO_SESSIONS_DIR'}}
        env['HOME'] = str(self.home)
        return subprocess.run([str(self.binary)] + (["--verbose"] if verbose else []), env=env, check=True,
                              capture_output=True, text=True, timeout=15).stdout

    def test_antigravity_collection_leads_and_companions(self):
        base = '.gemini/antigravity-cli/'
        for name in ('jetbox_summaries_proto.pb', 'cache/conversation_metadata.json',
                     'conversation_summaries.db', 'conversation_summaries.db-wal',
                     'conversation_summaries.db-shm'):
            self.put(base + name)
        for name in ('annotations', 'crashes', 'persistent_terminals'):
            (self.home / base / name).mkdir()
        output = self.scan(verbose=False)
        self.assertIn('jetbox_summaries_proto.pb', output)
        self.assertIn('conversation_metadata.json', output)
        self.assertIn('WAL present', output)
        self.assertIn('SHM present', output)
        self.assertNotIn('SYNTHETIC_SECRET_NOT_FOR_OUTPUT', output)
        self.assertNotIn('3 session artifacts', output)

    def test_project_outputs_and_companions_are_metadata_only(self):
        paths = ['.cursor/projects/project/terminals/1.txt',
                 '.cursor/projects/project/agent-tools/nested/result.json',
                 '.cursor/chats/workspace/session/store.db-wal',
                 '.cursor/chats/workspace/session/store.db-shm']
        for path in paths:
            self.put(path)
        ignored = ['.cursor/projects/project/worker.log',
                   '.cursor/projects/project/other/result.txt',
                   '.cursor/chats/workspace/session/unrelated.db-wal']
        for path in ignored:
            self.put(path)
        output = self.scan()
        for path in paths:
            self.assertIn(str(self.home / path), output)
        for path in ignored:
            self.assertNotIn(str(self.home / path), output)
        self.assertNotIn('SYNTHETIC_SECRET_NOT_FOR_OUTPUT', output)

    def test_ide_global_and_workspace_inventory(self):
        names = ['state.vscdb', 'state.vscdb.backup', 'state.vscdb-wal', 'state.vscdb-shm',
                 'state.vscdb.backup-wal', 'state.vscdb.backup-shm']
        paths = [self.ide+'/User/globalStorage/'+name for name in names +
                 ['conversation-search.db', 'conversation-search.db-wal', 'conversation-search.db-shm']]
        paths += [self.ide+'/User/workspaceStorage/workspace/'+name for name in names]
        for path in paths:
            self.put(path)
        unrelated = self.put(self.ide+'/User/workspaceStorage/workspace/unrelated.db')
        output = self.scan()
        for path in paths:
            self.assertIn(str(self.home / path), output)
        self.assertNotIn(str(unrelated), output)
        self.assertNotIn('SYNTHETIC_SECRET_NOT_FOR_OUTPUT', output)

    def test_absent_companions_are_optional(self):
        main = self.put(self.ide+'/User/globalStorage/state.vscdb')
        output = self.scan()
        self.assertIn(str(main), output)
        self.assertNotIn(str(main)+'-wal', output)
        self.assertNotIn(str(main)+'-shm', output)

    def test_symlink_files_and_directories_are_not_followed(self):
        outside = self.put('outside/secret.txt')
        root = self.home / '.cursor/projects/project'
        root.mkdir(parents=True)
        (root / 'terminals').symlink_to(outside.parent, target_is_directory=True)
        outputs = root / 'agent-tools'
        outputs.mkdir()
        (outputs / 'linked.txt').symlink_to(outside)
        self.assertNotIn('linked.txt', self.scan())
        self.assertNotIn('terminals/secret.txt', self.scan())
        chats = self.home / '.cursor/chats'
        chats.symlink_to(outside.parent, target_is_directory=True)
        self.put('outside/store.db-wal')
        self.assertNotIn('/.cursor/chats/store.db-wal', self.scan())

    def test_depth_and_output_caps_are_reported(self):
        deep = self.put('.cursor/projects/project/agent-tools/' + 'nested/' * 8 + 'result.txt')
        output = self.scan()
        self.assertNotIn(str(deep), output)
        self.assertIn('Results are incomplete', output)
        for i in range(300):
            self.put(f'.cursor/projects/project/terminals/{i}.txt')
        self.assertIn('Result storage cap reached', self.scan())

    def test_entry_cap_is_reported_without_unbounded_walk(self):
        for i in range(850):
            self.put(f'.cursor/projects/project/unrelated/{i}.txt')
        self.assertIn('Discovery cap reached', self.scan())

    def test_compact_output_groups_companions_and_hides_path_flood(self):
        for i in range(100):
            (self.home / f'.cursor/projects/project-{i}/mcps').mkdir(parents=True)
        for name in ['state.vscdb', 'state.vscdb-wal', 'state.vscdb-shm', 'conversation-search.db']:
            self.put(self.ide+'/User/globalStorage/'+name)
        output = self.scan(verbose=False)
        self.assertLess(len(output.splitlines()), 20)
        self.assertIn('WAL present; SHM present', output)
        self.assertIn('inventory only', output)
        self.assertNotIn('state.vscdb-wal', output)
        self.assertNotIn('/mcps', output)
        verbose = self.scan()
        self.assertIn('state.vscdb-wal', verbose)
        self.assertIn('/mcps', verbose)
        self.assertNotIn('SYNTHETIC_SECRET_NOT_FOR_OUTPUT', output + verbose)

    def test_platform_roots_and_catalog_status(self):
        catalog = json.loads((self.repo / 'blacklight-scout/catalog/targets.json').read_text())
        roots = {'windows': 'AppData/Roaming/Cursor', 'darwin': 'Library/Application Support/Cursor', 'linux': '.config/Cursor'}
        for platform, root in roots.items():
            profile = catalog['platforms'][platform]
            patterns = {t['pattern'] for t in profile['targets'] if t['tool'] == 'cursor'}
            self.assertIn(profile['home_var']+'/'+root+'/User/globalStorage/state.vscdb', patterns)
            self.assertIn(profile['home_var']+'/'+root+'/User/globalStorage/conversation-search.db', patterns)
            for other in roots.values():
                if other != root:
                    self.assertFalse(any('/'+other in path for path in patterns))
        artifacts = json.loads((self.repo / 'blacklight-rules/catalog/confirmed_artifacts.json').read_text())
        by_id = {a['id']: a for a in artifacts['artifacts']}
        self.assertEqual(by_id['cursor.projects_worker_log']['assessment_coverage'], 'intentionally_deferred')
        for key in ['cursor.projects_terminals', 'cursor.projects_agent_tools',
                    'cursor.chats_store_db_wal', 'cursor.chats_store_db_shm']:
            self.assertEqual(by_id[key]['assessment_coverage'], 'recursively_discovered')
