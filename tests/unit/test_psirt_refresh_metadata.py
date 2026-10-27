"""Isolated metadata cache checks; no service, credentials or API requests."""
import copy
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework.metadata import MetadataCache, SOURCES
from psirt_casework.service import latest_run, view_metadata
from psirt_casework.store import Invalid
from psirt_daily.pipeline import encoded, sha


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / '.psirt-ops').write_bytes(encoded({'schema': 'psirt-ops/1', 'mode': 'snapshot-replay'}))
        self.calls = []
        self.run = self.publish('run-1')

    def publish(self, name):
        run = self.root / 'runs' / name
        run.mkdir(parents=True)
        capture = {'captured_at': '2026-10-21T09:00:00+08:00', 'origin_mode': 'snapshot-replay',
                   'synthetic': True,
                   'sources': {key: {'status': 'SUCCESS', 'complete': True,
                                     'observed_at': '2026-10-21T09:00:00+08:00',
                                     'raw': [{'private_fixture': 'never exposed'}]} for key in SOURCES}}
        artifacts = {'capture.json': encoded(capture), 'index.html': b'<html>snapshot</html>',
                     'report_presentation_used.json': encoded({'schema': 'test-presentation'})}
        for filename, raw in artifacts.items():
            (run / filename).write_bytes(raw)
        manifest = encoded({'schema': 'psirt-ops-manifest/1', 'run_id': name,
                            'artifacts_sha256': {key: sha(raw) for key, raw in artifacts.items()}})
        (run / 'manifest.json').write_bytes(manifest)
        (self.root / 'state.json').write_bytes(encoded({'latest_run': str(run),
                                                      'manifest_sha256': sha(manifest), 'synthetic': True}))
        return run

    def loader(self, state):
        self.calls.append(copy.deepcopy(state))
        run, _ = latest_run(self.root, state)
        return view_metadata(self.root, run)

    def test_same_identity_loads_once_and_returns_independent_small_values(self):
        cache = MetadataCache(self.root, self.loader)
        first = cache.get()
        first['sources']['dt']['status'] = 'FAILED'
        first['run_id'] = 'caller-mutation'
        second = cache.get()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(second['run_id'], 'run-1')
        self.assertEqual(second['sources']['dt']['status'], 'SUCCESS')
        self.assertNotIn('raw', json.dumps(second))
        self.assertNotIn('never exposed', json.dumps(second))

    def test_cache_hit_reads_state_but_not_large_artifacts(self):
        cache = MetadataCache(self.root, self.loader)
        cache.get()
        original = Path.open
        opened = []
        def watch(path, *args, **kwargs):
            opened.append(path.name)
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', watch):
            cache.get()
        self.assertEqual(opened, ['state.json'])
        self.assertEqual(len(self.calls), 1)

    def test_new_run_replaces_the_single_entry(self):
        cache = MetadataCache(self.root, self.loader)
        cache.get()
        self.publish('run-2')
        self.assertEqual(cache.get()['run_id'], 'run-2')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(cache.get()['run_id'], 'run-2')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(cache.entry[1]['run_id'], 'run-2')

    def test_tampering_each_verified_artifact_revalidates_and_rejects(self):
        for name in ('manifest.json', 'capture.json', 'index.html', 'report_presentation_used.json'):
            with self.subTest(artifact=name):
                cache = MetadataCache(self.root, self.loader)
                cache.get()
                count = len(self.calls)
                path = self.run / name
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                try:
                    with self.assertRaises(Invalid):
                        cache.get()
                    self.assertEqual(len(self.calls), count + 1)
                    self.assertIsNone(cache.entry)
                finally:
                    path.write_bytes(original)

    def test_same_size_tamper_with_restored_mtime_is_caught_by_ctime(self):
        cache = MetadataCache(self.root, self.loader)
        cache.get()
        path = self.run / 'index.html'
        before = path.stat()
        path.write_bytes(b'<html>tampered</html>')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(path.stat().st_size, before.st_size)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
        with self.assertRaises(Invalid):
            cache.get()
        self.assertEqual(len(self.calls), 2)

    def test_atomic_replace_and_marker_change_both_invalidate(self):
        cache = MetadataCache(self.root, self.loader)
        cache.get()
        path = self.run / 'index.html'
        replacement = self.root / 'replacement'
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
        cache.get()
        self.assertEqual(len(self.calls), 2)
        (self.root / '.psirt-ops').write_bytes(encoded({'schema': 'psirt-ops/1', 'mode': 'live'}))
        self.assertFalse(cache.get()['offline'])
        self.assertEqual(len(self.calls), 3)

    def test_loader_result_is_narrowed_before_caching(self):
        returned = []
        def loader(state):
            value = self.loader(state)
            value['capture'] = {'token': 'private-fixture-token'}
            value['session'] = 'private-fixture-session'
            value['sources']['dt']['raw'] = [{'token': 'private-fixture-token'}]
            returned.append(value)
            return value
        cache = MetadataCache(self.root, loader)
        result = cache.get()
        self.assertNotIn('private-fixture', json.dumps(result))
        self.assertNotIn('private-fixture', json.dumps(cache.entry))
        returned[0]['sources']['dt']['status'] = 'FAILED'
        self.assertEqual(cache.get()['sources']['dt']['status'], 'SUCCESS')

    def test_root_escape_is_rejected_before_loader(self):
        path = self.root / 'state.json'
        initial = json.loads(path.read_text())
        for run in (str(self.root / 'outside'), 'runs/run-1', str(self.root / 'runs' / '..' / 'outside')):
            with self.subTest(run=run):
                path.write_bytes(encoded({**initial, 'latest_run': run}))
                with self.assertRaises(Invalid):
                    MetadataCache(self.root, self.loader).get()
        self.assertFalse(self.calls)

    def test_symlinks_are_rejected_even_after_a_cached_success(self):
        for name in ('state.json', '.psirt-ops', *('runs/run-1/' + n for n in
                     ('manifest.json', 'capture.json', 'index.html', 'report_presentation_used.json'))):
            with self.subTest(path=name):
                cache = MetadataCache(self.root, self.loader)
                cache.get()
                count = len(self.calls)
                path = self.root / name
                replacement = self.root / 'symlink-target'
                path.rename(replacement)
                path.symlink_to(replacement)
                try:
                    with self.assertRaises(ValueError):
                        cache.get()
                    self.assertEqual(len(self.calls), count)
                finally:
                    path.unlink()
                    replacement.rename(path)
        alias = self.root / 'root-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            MetadataCache(alias, self.loader)

    def test_run_changed_while_loading_is_retried_once_with_new_pinned_state(self):
        def loader(state):
            value = self.loader(state)
            if len(self.calls) == 1:
                self.publish('run-2')
            return value
        cache = MetadataCache(self.root, loader)
        self.assertEqual(cache.get()['run_id'], 'run-2')
        self.assertEqual([Path(s['latest_run']).name for s in self.calls], ['run-1', 'run-2'])
        self.assertEqual(cache.get()['run_id'], 'run-2')
        self.assertEqual(len(self.calls), 2)

    def test_repeated_change_is_rejected_without_caching_an_unverified_entry(self):
        def loader(state):
            value = self.loader(state)
            self.publish('run-' + str(len(self.calls) + 1))
            return value
        cache = MetadataCache(self.root, loader)
        with self.assertRaisesRegex(Invalid, 'MetadataChangedDuringValidation'):
            cache.get()
        self.assertEqual(len(self.calls), 2)
        self.assertIsNone(cache.entry)

    def test_concurrent_pollers_share_one_validation(self):
        entered, release = threading.Event(), threading.Event()
        results, errors = [], []
        def loader(state):
            entered.set()
            if not release.wait(2):
                raise AssertionError('test loader timed out')
            return self.loader(state)
        cache = MetadataCache(self.root, loader)
        def poll():
            try:
                results.append(cache.get())
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=poll) for _ in range(4)]
        try:
            for thread in threads:
                thread.start()
            self.assertTrue(entered.wait(2))
        finally:
            release.set()
            for thread in threads:
                thread.join(3)
        self.assertFalse(errors)
        self.assertEqual(len(results), 4)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all(not thread.is_alive() for thread in threads))


if __name__ == '__main__':
    unittest.main()
