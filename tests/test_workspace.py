"""Actual local Git objects/ref CAS; no GitHub effects or gate authority."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from universal.workspace import Candidate, LocalWorkspace, REMOTE, RepositoryBinding, WorkspaceConflict


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='coguni-git-test-')
        self.source = Path(self.temp.name) / 'source'
        self.source.mkdir()
        self.env = {'PATH': os.defpath, 'HOME': self.temp.name, 'GIT_CONFIG_NOSYSTEM': '1',
                    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}
        self.git('init', '--quiet', '--initial-branch=main', '--object-format=sha1')
        self.git('remote', 'add', 'origin', REMOTE)
        (self.source / 'a.txt').write_text('base\n')
        (self.source / 'keep.txt').write_text('unchanged\n')
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base')
        self.sha = self.git('rev-parse', 'HEAD')
        self.tree = self.git('rev-parse', 'HEAD^{tree}')
        self.binding = RepositoryBinding(1418009675, 'R_kgDOVIUcSw', 'sylvainride/CoGUni',
                                         265171248, REMOTE, self.sha, self.tree)
        self.now = [100.0]

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.source), '-c', 'core.hooksPath=/dev/null',
                                        *args], env=self.env, stderr=subprocess.PIPE).decode().strip()

    def workspace(self, **extra):
        return LocalWorkspace(self.source, self.binding, run_id='run-1', allowed_paths=('a.txt', 'new.txt'),
                              expires_unix=200, clock=lambda: self.now[0], **extra)

    def test_preparation_and_cas_use_real_oids_and_never_mutate_source_main(self):
        with self.workspace() as ws:
            candidate = ws.prepare({'a.txt': 'changed\n'}, expected_head=self.sha, expected_tree=self.tree)
            self.assertEqual(ws.head(), self.sha)
            self.assertNotEqual(candidate.tree, self.tree)
            self.assertEqual(ws._git('show', candidate.commit + ':a.txt'), b'changed\n')
            self.assertEqual(ws._git('show', candidate.commit + ':keep.txt'), b'unchanged\n')
            self.assertEqual(ws.advance(candidate, validated_tree=candidate.tree), candidate.commit)
            self.assertEqual(ws.head(), candidate.commit)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.sha)
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertEqual((self.source / 'a.txt').read_text(), 'base\n')

    def test_two_git_process_writers_one_winner_one_conflict(self):
        with self.workspace() as ws:
            candidates = [ws.prepare({'a.txt': text}, expected_head=self.sha, expected_tree=self.tree)
                          for text in ['author-one\n', 'author-two\n']]
            barrier = threading.Barrier(2)
            def advance(candidate):
                barrier.wait(timeout=5)
                try:
                    return ('winner', ws.advance(candidate, validated_tree=candidate.tree))
                except WorkspaceConflict:
                    return ('conflict', candidate.commit)
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(advance, candidates))
            self.assertEqual(sorted(x[0] for x in outcomes), ['conflict', 'winner'])
            winner = next(x[1] for x in outcomes if x[0] == 'winner')
            self.assertEqual(ws.head(), winner)
            self.assertEqual(ws.tree(winner), next(c.tree for c in candidates if c.commit == winner))

    def test_wrong_repository_transfer_owner_remote_or_branch_is_refused(self):
        for field, value in [('repository_id', 42), ('repository_id', True), ('owner_id', 42),
                             ('node_id', 'R_OTHER'), ('full_name', 'other/CoGUni'),
                             ('remote', 'https://github.com/other/CoGUni.git'), ('branch', 'other')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(self.binding, **{field: value})
        self.git('remote', 'set-url', 'origin', 'https://github.com/other/CoGUni.git')
        with self.assertRaises(ValueError):
            self.workspace()

    def test_changed_source_head_or_false_tree_binding_is_refused(self):
        bad = replace(self.binding, base_tree='0' * 40)
        with self.assertRaises(WorkspaceConflict):
            LocalWorkspace(self.source, bad, run_id='run', allowed_paths=('a.txt',),
                           expires_unix=200, clock=lambda: 100)
        (self.source / 'keep.txt').write_text('changed\n')
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'new base')
        with self.assertRaises(WorkspaceConflict):
            self.workspace()

    def test_stale_base_and_tree_fail_before_or_after_preparation(self):
        with self.workspace() as ws:
            with self.assertRaises(WorkspaceConflict):
                ws.prepare({'a.txt': 'x'}, expected_head=self.sha, expected_tree='0' * 40)
            old = ws.prepare({'a.txt': 'old'}, expected_head=self.sha, expected_tree=self.tree)
            fresh = ws.prepare({'new.txt': 'new'}, expected_head=self.sha, expected_tree=self.tree)
            ws.advance(fresh, validated_tree=fresh.tree)
            with self.assertRaises(WorkspaceConflict):
                ws.advance(old, validated_tree=old.tree)
            with self.assertRaises(WorkspaceConflict):
                ws.prepare({'a.txt': 'x'}, expected_head=self.sha, expected_tree=self.tree)
            self.assertEqual(ws.head(), fresh.commit)

    def test_wrong_validated_tree_or_forged_commit_parent_cannot_advance(self):
        with self.workspace() as ws:
            candidate = ws.prepare({'a.txt': 'x'}, expected_head=self.sha, expected_tree=self.tree)
            for value in (self.tree, '0' * 40):
                with self.assertRaises(WorkspaceConflict):
                    ws.advance(candidate, validated_tree=value)
            with self.assertRaises(WorkspaceConflict):
                ws.advance(Candidate(self.sha, candidate.tree, self.sha), validated_tree=candidate.tree)
            self.assertEqual(ws.head(), self.sha)

    def test_same_output_value_but_different_path_or_bytes_changes_tree(self):
        with self.workspace() as ws:
            first = ws.prepare({'a.txt': 'same'}, expected_head=self.sha, expected_tree=self.tree)
            renamed = ws.prepare({'new.txt': 'same'}, deletions=('a.txt',), expected_head=self.sha, expected_tree=self.tree)
            altered = ws.prepare({'a.txt': 'same\n'}, expected_head=self.sha, expected_tree=self.tree)
            self.assertEqual(len({first.tree, renamed.tree, altered.tree}), 3)
            with self.assertRaises(WorkspaceConflict):
                ws.advance(renamed, validated_tree=first.tree)

    def test_path_traversal_binary_and_unlisted_deletion_are_refused(self):
        with self.workspace() as ws:
            for files in ({'../a.txt': 'x'}, {'/a.txt': 'x'}, {'.git/config': 'x'},
                          {'keep.txt': 'x'}, {'a.txt': b'binary'}, {'a.txt': 'a\0b'}):
                with self.subTest(files=str(files)), self.assertRaises(ValueError):
                    ws.prepare(files, expected_head=self.sha, expected_tree=self.tree)
            with self.assertRaises(ValueError):
                ws.prepare({}, deletions=('keep.txt',), expected_head=self.sha, expected_tree=self.tree)
            self.assertEqual(ws.head(), self.sha)

    def test_symlink_source_and_allowlisted_symlink_or_binary_base_are_refused(self):
        link = Path(self.temp.name) / 'linked-source'
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            LocalWorkspace(link, self.binding, run_id='run', allowed_paths=('a.txt',),
                           expires_unix=200, clock=lambda: 100)
        for kind in ('symlink', 'binary'):
            (self.source / 'a.txt').unlink()
            if kind == 'symlink':
                (self.source / 'a.txt').symlink_to('/tmp/outside')
            else:
                (self.source / 'a.txt').write_bytes(b'\x00binary')
            self.git('add', 'a.txt')
            self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', kind)
            binding = replace(self.binding, base_sha=self.git('rev-parse', 'HEAD'), base_tree=self.git('rev-parse', 'HEAD^{tree}'))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                LocalWorkspace(self.source, binding, run_id='run', allowed_paths=('a.txt',),
                               expires_unix=200, clock=lambda: 100)

    def test_worker_filesystem_symlink_swap_cannot_redirect_object_patch(self):
        outside = Path(self.temp.name) / 'outside'
        outside.write_text('PRIVATE-UNCHANGED')
        with self.workspace() as ws:
            (self.source / 'a.txt').unlink()
            (self.source / 'a.txt').symlink_to(outside)
            candidate = ws.prepare({'a.txt': 'safe object data'}, expected_head=self.sha, expected_tree=self.tree)
            ws.advance(candidate, validated_tree=candidate.tree)
            self.assertEqual(outside.read_text(), 'PRIVATE-UNCHANGED')
            self.assertTrue((self.source / 'a.txt').is_symlink())

    def test_expiry_during_git_io_prevents_local_ref_transition(self):
        with self.workspace() as ws:
            candidate = ws.prepare({'a.txt': 'x'}, expected_head=self.sha, expected_tree=self.tree)
            original = ws.tree
            def expire(commit):
                value = original(commit)
                self.now[0] = 200
                return value
            with patch.object(ws, 'tree', side_effect=expire), self.assertRaises(WorkspaceConflict):
                ws.advance(candidate, validated_tree=candidate.tree)
            self.assertEqual(ws.head(), self.sha)

    def test_invalid_run_lease_and_clock_regression_are_refused(self):
        for run in ('../run', 'main', 'a/b', ''):
            # 'main' is a harmless run label; only its namespaced private ref exists.
            if run == 'main':
                continue
            with self.assertRaises(ValueError):
                LocalWorkspace(self.source, self.binding, run_id=run, allowed_paths=('a.txt',),
                               expires_unix=200, clock=lambda: 100)
        with self.workspace() as ws:
            self.now[0] = 99
            with self.assertRaises(WorkspaceConflict):
                ws.prepare({'a.txt': 'x'}, expected_head=self.sha, expected_tree=self.tree)

    def test_isolated_runs_cleanup_only_their_own_private_database(self):
        first = self.workspace()
        with self.workspace() as second:
            path = first.root
            self.assertNotEqual(first.root, second.root)
            first.close()
            self.assertFalse(path.exists())
            self.assertTrue(second.root.exists())
            self.assertEqual(second.head(), self.sha)
            self.assertEqual(self.git('rev-parse', 'HEAD'), self.sha)

    def test_merged_tree_includes_both_authors_and_differs_from_head_proof(self):
        self.git('checkout', '-qb', 'work/left')
        (self.source / 'a.txt').write_text('left\n')
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'left')
        left = self.git('rev-parse', 'HEAD')
        left_tree = self.git('rev-parse', 'HEAD^{tree}')
        self.git('checkout', '-qb', 'work/right', self.sha)
        (self.source / 'keep.txt').write_text('right\n')
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'right')
        right = self.git('rev-parse', 'HEAD')
        merge_tree = self.git('merge-tree', '--write-tree', left, right)
        self.assertNotEqual(merge_tree, left_tree)
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'merge', '--no-ff', '-m', 'merge', left)
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), merge_tree)
        self.assertEqual((self.source / 'a.txt').read_text(), 'left\n')
        self.assertEqual((self.source / 'keep.txt').read_text(), 'right\n')

    def test_git_revert_keeps_later_unrelated_file_and_creates_new_commit(self):
        self.git('checkout', '-qb', 'work/revert')
        (self.source / 'a.txt').write_text('changed\n')
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'change')
        change = self.git('rev-parse', 'HEAD')
        (self.source / 'later.txt').write_text('later-author\n')
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'later')
        before_revert = self.git('rev-parse', 'HEAD')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'revert', '--no-edit', change)
        self.assertEqual((self.source / 'a.txt').read_text(), 'base\n')
        self.assertEqual((self.source / 'later.txt').read_text(), 'later-author\n')
        self.assertNotEqual(self.git('rev-parse', 'HEAD'), self.sha)
        self.assertEqual(self.git('rev-parse', 'HEAD^'), before_revert)

    def test_revert_conflict_is_visible_and_never_resets_later_author(self):
        self.git('checkout', '-qb', 'work/revert-conflict')
        commits = []
        for text in ('first\n', 'second-author\n'):
            (self.source / 'a.txt').write_text(text)
            self.git('add', '.')
            self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', text.strip())
            commits.append(self.git('rev-parse', 'HEAD'))
        with self.assertRaises(subprocess.CalledProcessError):
            self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'revert', '--no-edit', commits[0])
        self.assertEqual(self.git('rev-parse', 'HEAD'), commits[1])
        self.assertIn('UU a.txt', self.git('status', '--porcelain'))
        self.git('revert', '--abort')
        self.assertEqual((self.source / 'a.txt').read_text(), 'second-author\n')
