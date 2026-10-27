"""Regression for observed mail needing re-review after its source changes."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework import service
from psirt_casework.inbox import build, identity, merge
from psirt_daily.pipeline import sha
from psirt_casework.store import encoded
from psirt_ops.pipeline import compare
from psirt_sf_fixtures import sample


class RefreshConsistency(unittest.TestCase):
    def root(self, folder):
        root = Path(folder)
        (root / 'human_review.json').write_text(encoded({'schema': 'psirt-human-review/1', 'reviews': {}}))
        (root / '.psirt-ops').write_text(encoded({'schema': 'psirt-ops/1', 'mode': 'snapshot-replay'}))
        return root

    @staticmethod
    def source(at, mail_id, *, jira_status='SUCCESS', summary='Synthetic case'):
        capture = sample()
        capture['captured_at'] = at
        capture['config']['cutoff'] = at
        for source in capture['sources'].values():
            source['observed_at'] = at
        sf = capture['sources']['salesforce']
        sf['scope']['instance'] = 'https://sf.synthetic.invalid'
        sf['emails'] = [dict(sf['emails'][0], Id=mail_id, MessageDate=at)]
        jira = capture['sources']['jira']
        jira['raw'] = [{'id': 'DEMO-1', 'key': 'DEMO-1', 'fields': {
            'summary': summary, 'status': {'name': 'In Progress', 'statusCategory': {'key': 'indeterminate'}}}}]
        if jira_status != 'SUCCESS':
            jira.update(status=jira_status, complete=False, raw=None)
        return capture

    @staticmethod
    def archive(root, run_id, capture, *, completed_at, ledger=None, baseline=None):
        """Write a small valid isolated history, without invoking collection."""
        run = root / 'runs' / run_id
        run.mkdir(parents=True)
        artifacts = {
            'capture.json': encoded(capture).encode(),
            'index.html': b'<html><head></head><body><main>Synthetic</main></body></html>',
            'report_presentation_used.json': b'{}'}
        if ledger is not None:
            artifacts['sf-inbox.json'] = encoded(ledger).encode()
        for name, value in artifacts.items():
            (run / name).write_bytes(value)
        manifest = {'schema': 'psirt-ops-manifest/1', 'run_id': run_id,
                    'mode': 'snapshot-replay', 'synthetic': True,
                    'started_at': completed_at, 'completed_at': completed_at,
                    'artifacts_sha256': {name: sha(value) for name, value in artifacts.items()},
                    'comparisons': {name: compare(name, value) for name, value in capture['sources'].items()}}
        manifest_bytes = encoded(manifest).encode()
        (run / 'manifest.json').write_bytes(manifest_bytes)
        state = {'latest_run': str(run), 'manifest_sha256': sha(manifest_bytes),
                 'synthetic': True, 'baselines': {'jira': baseline} if baseline else {}}
        own_baseline = {'path': str((run / 'capture.json').relative_to(root)),
                        'sha256': sha(artifacts['capture.json']), 'source': 'jira'}
        return run, state, own_baseline

    @staticmethod
    def ledger(captures):
        rows = {}
        for run_id, capture in captures:
            merge(rows, capture, run_id)
        return {'schema': 'psirt-sf-inbox/1', 'synthetic': True,
                'history_runs': [run_id for run_id, _ in captures],
                'rows': [{'id': key, 'source': value} for key, value in rows.items()]}

    def pin_while_publishing(self, root, pinned, future, function):
        """Publish immediately after the caller's first state read; count re-reads."""
        state_path = root / 'state.json'
        state_path.write_text(encoded(pinned))
        actual_latest, actual_read = service.latest_run, Path.read_bytes
        reads = []

        def read(path):
            if path == state_path:
                reads.append(path)
            return actual_read(path)

        def publish(path, state=None):
            self.assertEqual(state, pinned, 'Caller must pass its original state to latest_run')
            state_path.write_text(encoded(future))
            return actual_latest(path, state)

        with patch.object(Path, 'read_bytes', read), patch.object(service, 'latest_run', side_effect=publish):
            result = function(root)
        self.assertEqual(len(reads), 1, 'A response must not re-read a newer state partway through')
        self.assertEqual(json.loads(state_path.read_text()), future)
        self.assertFalse((root / 'casework/worklog.sqlite3').exists())
        return result

    def test_changed_evidence_on_done_mail_is_visible_before_first_page_boundary(self):
        source = sample()
        sf = source['sources']['salesforce']
        instance = 'https://sf.synthetic.invalid'
        sf['scope']['instance'] = instance
        messages = [dict(sf['emails'][0], Id='pending-' + str(n)) for n in range(16)]
        changed = dict(sf['emails'][0], Id='done-but-changed', TextBody='New synthetic evidence')
        stable = dict(sf['emails'][0], Id='done-stable', TextBody='Unchanged synthetic evidence')
        sf['emails'] = messages + [changed, stable]
        changed_id, stable_id = identity(instance, changed['Id']), identity(instance, stable['Id'])
        records = [
            {'kind': 'sf_email', 'id': changed_id, 'version': 1,
             'payload': {'state': 'done', 'source_digest': '0' * 64, 'outcome': 'Previous conclusion', 'reviewer': 'DEMO'}},
            {'kind': 'sf_email', 'id': stable_id, 'version': 1,
             'payload': {'state': 'done', 'source_digest': sha(encoded(stable).encode()),
                         'outcome': 'Reviewed unchanged evidence', 'reviewer': 'DEMO'}}]
        manual = {'records': records, 'revisions': copy.deepcopy(records)}
        before = copy.deepcopy(manual)
        comparison = {'comparison': 'COMPARABLE', 'email_changes': {'added': [], 'modified': [], 'removed': []}}
        with tempfile.TemporaryDirectory() as folder:
            result = build(Path(folder), source, manual, comparison, 'synthetic-review', '2026-10-21T09:00:00+08:00')
        self.assertEqual(result['needs_recheck'], 1)
        self.assertEqual(result['rows'][0]['id'], changed_id)
        self.assertTrue(result['rows'][0]['needs_recheck'])
        self.assertEqual(result['rows'][0]['state'], 'done')  # Old record is preserved, never silently reopened.
        self.assertEqual(result['rows'][0]['record'], records[0])
        self.assertEqual(result['rows'][-1]['id'], stable_id)
        attention = [r for r in result['rows'] if r['state'] != 'done' or r['needs_recheck']]
        self.assertEqual(len(attention), 17)
        self.assertIn(changed_id, [r['id'] for r in attention[:15]])
        self.assertEqual(result['counts']['done'], 2)
        self.assertEqual(manual, before)

    def test_casework_response_keeps_capture_and_jira_fallback_from_same_pinned_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.root(folder)
            old = self.source('2026-10-21T08:00:00+08:00', 'old-mail', summary='Previous known case')
            old_run, _, old_ref = self.archive(root, 'old-success', old, completed_at='2026-10-21T08:01:00+08:00')
            pinned_capture = self.source('2026-10-21T09:00:00+08:00', 'pinned-mail', jira_status='FAILED')
            pinned_run, pinned, _ = self.archive(root, 'pinned-failure', pinned_capture,
                completed_at='2026-10-21T09:01:00+08:00', baseline=old_ref)
            new = self.source('2026-10-21T10:00:00+08:00', 'future-mail', summary='Future case must not leak')
            _, _, new_ref = self.archive(root, 'future-success', new, completed_at='2026-10-21T10:01:00+08:00')
            future_capture = self.source('2026-10-21T11:00:00+08:00', 'future-later', jira_status='FAILED')
            _, future, _ = self.archive(root, 'future-failure', future_capture,
                completed_at='2026-10-21T11:01:00+08:00', baseline=new_ref)

            run, capture, result = self.pin_while_publishing(root, pinned, future, service.context)
            self.assertEqual(run, pinned_run)
            self.assertEqual(capture, pinned_capture)
            self.assertEqual(result['run_id'], pinned_run.name)
            self.assertEqual(result['source']['status'], 'FAILED')
            self.assertTrue(result['source']['historical'])
            self.assertEqual(result['source']['observed_at'], pinned_capture['sources']['jira']['observed_at'])
            self.assertEqual(result['source']['displayed_at'], old['sources']['jira']['observed_at'])
            self.assertEqual(result['cases'][0]['summary'], 'Previous known case')
            self.assertIn(old_run.name, result['cases'][0]['source_ref'])
            self.assertNotIn('Future case', json.dumps(result))

    def test_sf_response_uses_pinned_cumulative_ledger_during_new_publish(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.root(folder)
            first = self.source('2026-10-21T09:00:00+08:00', 'old-mail')
            pinned_run, pinned, _ = self.archive(root, 'pinned', first,
                completed_at='2026-10-21T09:01:00+08:00', ledger=self.ledger([('pinned', first)]))
            later = self.source('2026-10-21T10:00:00+08:00', 'future-mail')
            _, future, _ = self.archive(root, 'future', later,
                completed_at='2026-10-21T10:01:00+08:00', ledger=self.ledger([('pinned', first), ('future', later)]))

            run, capture, result = self.pin_while_publishing(root, pinned, future, service.sf_context)
            inbox = result['inbox']
            self.assertEqual(run, pinned_run)
            self.assertEqual(capture, first)
            self.assertEqual(inbox['run_id'], pinned_run.name)
            self.assertEqual([row['source']['email_id'] for row in inbox['rows']], ['old-mail'])
            self.assertEqual(inbox['history_runs'], ['pinned'])
            self.assertEqual(inbox['source']['observed_at'], first['sources']['salesforce']['observed_at'])

    def test_sf_legacy_bootstrap_excludes_runs_completed_after_pinned_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.root(folder)
            earlier = self.source('2026-10-21T08:00:00+08:00', 'earlier-mail')
            self.archive(root, 'earlier', earlier, completed_at='2026-10-21T08:01:00+08:00')
            first = self.source('2026-10-21T09:00:00+08:00', 'pinned-mail')
            pinned_run, pinned, _ = self.archive(root, 'pinned', first,
                completed_at='2026-10-21T09:01:00+08:00')
            later = self.source('2026-10-21T10:00:00+08:00', 'future-mail')
            # UTC representation must still compare after 09:01 +08:00.
            _, future, _ = self.archive(root, 'future', later,
                completed_at='2026-10-21T02:01:00+00:00')

            run, capture, result = self.pin_while_publishing(root, pinned, future, service.sf_context)
            inbox = result['inbox']
            self.assertEqual(run, pinned_run)
            self.assertEqual(capture, first)
            self.assertEqual({row['source']['email_id'] for row in inbox['rows']}, {'earlier-mail', 'pinned-mail'})
            self.assertEqual(inbox['known_total'], 2)
            self.assertEqual(inbox['history_runs'], ['earlier', 'pinned'])
            self.assertNotIn('future-mail', json.dumps(inbox))


if __name__ == '__main__':
    unittest.main()
