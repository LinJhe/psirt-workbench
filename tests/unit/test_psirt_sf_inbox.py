"""Offline acceptance of observed mail retention and explicit personal handling."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from psirt_casework.inbox import build, identity, merge, validate_record
from psirt_casework.projection import build as build_casework
from psirt_casework.store import Conflict, Invalid, Store, encoded


INSTANCE = 'https://synthetic-salesforce.invalid'
MONDAY = '2026-10-19T20:00:00+08:00'
TUESDAY = '2026-10-20T09:00:00+08:00'
EMPTY_REVIEW = {'schema': 'psirt-human-review/1', 'reviews': {}}


def mail(email_id='mail-1', *, incoming=True, body='Synthetic report', parent='case-1'):
    return {'Id': email_id, 'ParentId': parent, 'Incoming': incoming,
            'Subject': 'Synthetic security report', 'TextBody': body,
            'MessageDate': '2026-10-19T19:30:00+08:00', 'Status': '0'}


def capture(messages, *, observed=MONDAY, start='2026-10-19T00:00:00+08:00',
            status='SUCCESS', complete=True, instance=INSTANCE, synthetic=True):
    source = {'status': status, 'complete': complete, 'observed_at': observed,
              'scope': {'instance': instance, 'case_filter': 'Synthetic owner',
                        'email_window_start': start},
              'raw': [{'Id': 'case-1', 'CaseNumber': 'Q-202610-90001', 'IsClosed': True},
                      {'Id': 'case-2', 'CaseNumber': 'Q-202610-90002'}],
              'emails': copy.deepcopy(messages)}
    return {'capture_schema': 'psirt-ops/1', 'synthetic': synthetic,
            'captured_at': observed, 'config': {'window_start': start, 'cutoff': observed},
            'sources': {'salesforce': source,
                        'jira': {'status': 'SUCCESS', 'complete': True,
                                 'observed_at': observed, 'scope': {'project': 'DEMO'},
                                 'raw': [{'id': 'DEMO-177', 'key': 'DEMO-177',
                                          'fields': {'summary': 'Synthetic case',
                                                     'status': {'name': 'In Progress',
                                                                'statusCategory': {'key': 'indeterminate'}}}}]}}}


def comparison(added=(), state='COMPARABLE'):
    return {'comparison': state,
            'email_changes': {'added': list(added), 'modified': [], 'removed': []}
            if state == 'COMPARABLE' else None}


class SFInboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'output'
        self.root.mkdir()
        self.store = Store(self.root / 'casework', synthetic=True)

    def project(self, source, *, comp=None, run_id='current'):
        return build(self.root, source, self.store.snapshot(),
                     comparison() if comp is None else comp, run_id, TUESDAY)

    def archive(self, source, run_id, inbox=None):
        """Create only isolated immutable-input fixtures; never run collection."""
        run = self.root / 'runs' / run_id
        run.mkdir(parents=True)
        artifacts = {'capture.json': source}
        if inbox is not None:
            artifacts['sf-inbox.json'] = inbox
        hashes = {}
        for name, value in artifacts.items():
            raw = encoded(value).encode()
            (run / name).write_bytes(raw)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        manifest = encoded({'run_id': run_id, 'synthetic': source['synthetic'],
                            'artifacts_sha256': hashes}).encode()
        (run / 'manifest.json').write_bytes(manifest)
        (self.root / 'state.json').write_text(encoded({
            'latest_run': str(run), 'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
            'synthetic': source['synthetic'], 'baselines': {}}))
        return run

    @staticmethod
    def by_mail(inbox):
        return {row['source']['email_id']: row for row in inbox['rows']}

    @staticmethod
    def payload(row, state='pending', **extra):
        source = row['source']
        payload = {'instance': source['instance'], 'email_id': source['email_id'],
                   'source_digest': source['evidence_sha256'], 'state': state,
                   'next_action': 'Review the synthetic evidence', 'outcome': '',
                   'followup_at': '', 'reviewer': 'DEMO reviewer'}
        payload.update(extra)
        return payload

    def test_after_hours_mail_survives_next_day_window_and_scope_change(self):
        monday = capture([mail()])
        first = self.project(monday, comp=comparison([mail()]), run_id='monday')
        prior = self.archive(monday, 'monday', first)
        old_bytes = {p.name: p.read_bytes() for p in prior.iterdir()}
        manual = self.store.snapshot()
        tuesday = capture([], observed=TUESDAY, start='2026-10-20T00:00:00+08:00')
        tuesday['sources']['salesforce']['scope']['case_filter'] = 'Different synthetic owner'
        tuesday['sources']['salesforce']['raw'] = []
        later = self.project(tuesday)
        self.assertEqual(later['new_incoming'], 0)
        self.assertEqual(later['known_total'], 1)
        self.assertEqual(later['counts']['unreviewed'], 1)
        row = later['rows'][0]
        self.assertFalse(row['in_current_capture'])
        self.assertIsNone(row['record'])
        self.assertEqual(row['source']['message_date'], mail()['MessageDate'])
        self.assertIn('runs/monday/capture.json#', row['source']['evidence_ref'])
        self.assertEqual(self.store.snapshot(), manual)
        self.assertEqual(old_bytes, {p.name: p.read_bytes() for p in prior.iterdir()})

    def test_fetch_delta_zero_never_acknowledges_observed_mail(self):
        incoming, outgoing = mail(), mail('outbound-1', incoming=False)
        source = capture([incoming, outgoing])
        first = self.project(source, comp=comparison([incoming, outgoing]), run_id='first')
        self.assertEqual(first['new_incoming'], 1)
        self.assertEqual(first['known_total'], 1)
        self.archive(source, 'first', first)
        for run_id in ('same-fetch', 'report-rebuild'):
            with self.subTest(run_id=run_id):
                again = self.project(source, run_id=run_id)
                self.assertEqual(again['new_incoming'], 0)
                self.assertEqual(again['counts']['unreviewed'], 1)
                self.assertIsNone(again['rows'][0]['record'])
        self.assertEqual(self.store.records('sf_email'), [])

    def test_union_is_by_message_id_and_instance_not_body_or_case(self):
        rows = {}
        source = capture([mail(), mail(), mail('mail-2', parent='case-2'),
                          mail('outbound', incoming=False), mail('unspecified', incoming=None)])
        merge(rows, source, 'first')
        merge(rows, source, 'duplicate-replay')
        self.assertEqual(len(rows), 2)
        self.assertEqual({r['email_id'] for r in rows.values()}, {'mail-1', 'mail-2'})
        other = capture([mail()], instance='https://other-synthetic.invalid')
        merge(rows, other, 'another-instance')
        self.assertEqual(len(rows), 3)
        self.assertNotEqual(identity(INSTANCE, 'mail-1'),
                            identity('https://other-synthetic.invalid', 'mail-1'))

    def test_legacy_capture_bootstrap_unions_ids_and_skips_unfinished_run(self):
        self.archive(capture([mail()]), 'first-legacy')
        self.archive(capture([mail(), mail('mail-2')], observed=TUESDAY), 'second-legacy')
        unfinished = self.root / 'runs' / 'unfinished'
        unfinished.mkdir()
        (unfinished / 'capture.json').write_text(encoded(capture([mail('not-committed')])))
        result = self.project(capture([], observed=TUESDAY))
        self.assertEqual(set(self.by_mail(result)), {'mail-1', 'mail-2'})
        self.assertEqual(result['counts']['unreviewed'], 2)
        self.assertNotIn('unfinished', result['history_runs'])

    def test_failed_or_partial_source_keeps_old_mail_and_new_is_unknown(self):
        original = capture([mail()])
        self.archive(original, 'old', self.project(original, run_id='old'))
        for status, messages, expected_total in [('FAILED', None, 1),
                                                  ('PARTIAL', [mail('mail-2')], 2)]:
            with self.subTest(status=status):
                source = capture(messages, observed=TUESDAY, status=status, complete=False)
                if status == 'FAILED':
                    source['sources']['salesforce']['raw'] = None
                    source['sources']['salesforce']['scope'] = {'requested_config': 'synthetic-scope'}
                result = self.project(source, comp=comparison([mail('mail-2')]))
                self.assertIsNone(result['new_incoming'])
                self.assertEqual(result['source']['status'], status)
                self.assertNotEqual(result['coverage'], 'COMPLETE_IN_CONFIGURED_WINDOW')
                self.assertEqual(result['known_total'], expected_total)
                self.assertEqual(result['counts']['unreviewed'], expected_total)
                self.assertIn('mail-1', self.by_mail(result))

    def test_first_baseline_missing_emails_and_incompatible_window_do_not_report_zero_new(self):
        for status, complete, messages, comp in [
                ('SUCCESS', True, [mail()], comparison(state='FIRST_BASELINE')),
                ('SUCCESS', True, [mail()], comparison(state='INCOMPATIBLE_BASELINE')),
                ('SUCCESS', True, None, comparison()),
                ('FAILED', False, None, comparison())]:
            with self.subTest(status=status, complete=complete, comparison=comp['comparison'], messages=messages):
                result = self.project(capture(messages, status=status, complete=complete), comp=comp)
                self.assertIsNone(result['new_incoming'])
                if messages is None:
                    self.assertNotEqual(result['coverage'], 'COMPLETE_IN_CONFIGURED_WINDOW')

    def test_store_reopen_idempotency_conflict_and_update_reason(self):
        source = capture([mail()])
        row = self.project(source)['rows'][0]
        payload = self.payload(row)
        saved = self.store.save('sf_email', row['id'], payload, 0, 'mail-save-operation')
        self.assertEqual(saved, self.store.save('sf_email', row['id'], payload, 0, 'mail-save-operation'))
        reopened = Store(self.root / 'casework', synthetic=True)
        self.assertEqual(reopened.get('sf_email', row['id']), saved)
        self.assertEqual(self.project(source)['counts']['pending'], 1)
        changed = {**payload, 'state': 'following', 'followup_at': '2026-10-22T09:00:00+08:00',
                   'correction_reason': 'Await requested evidence'}
        with self.assertRaises(Conflict):
            reopened.save('sf_email', row['id'], changed, 0, 'stale-mail-operation')
        with self.assertRaises(Conflict):
            reopened.save('sf_email', row['id'], changed, 1, 'mail-save-operation')
        missing_reason = {k: v for k, v in changed.items() if k != 'correction_reason'}
        with self.assertRaises(Invalid):
            reopened.save('sf_email', row['id'], missing_reason, 1, 'missing-reason-operation')
        self.assertEqual(len(reopened.history('sf_email', row['id'])), 1)
        updated = reopened.save('sf_email', row['id'], changed, 1, 'followup-mail-operation')
        self.assertEqual(updated['version'], 2)
        self.assertEqual(self.project(source)['counts']['following'], 1)
        self.assertEqual(reopened.history('sf_email', row['id'])[0]['payload'], payload)

    def test_committed_operation_replays_after_source_and_record_change_without_new_revision(self):
        original = capture([mail()])
        row = self.project(original)['rows'][0]
        request = {'kind': 'sf_email', 'id': row['id'], 'payload': self.payload(row),
                   'expected_version': 0, 'operation_id': 'retry-committed-mail'}
        self.assertIsNone(self.store.replay_operation(**request))
        committed = self.store.save(**request)

        changed = capture([mail(body='Additional synthetic evidence')], observed=TUESDAY)
        latest_inbox = self.project(changed)
        with self.assertRaises(Conflict):
            validate_record(request, latest_inbox)
        latest_row = latest_inbox['rows'][0]
        latest = self.store.save(
            'sf_email', row['id'],
            self.payload(latest_row, 'following', correction_reason='Reviewed updated evidence'),
            1, 'later-mail-operation')
        reopened = Store(self.root / 'casework', synthetic=True)
        before = reopened.snapshot()

        # A lost acknowledgement can be recovered even after a newer source and
        # another committed edit; the response identifies the original operation.
        self.assertEqual(reopened.replay_operation(**request), committed)
        self.assertEqual(reopened.get('sf_email', row['id']), latest)
        self.assertEqual(len(reopened.history('sf_email', row['id'])), 2)
        different = copy.deepcopy(request)
        different['payload']['next_action'] = 'A different action must not reuse the operation'
        with self.assertRaises(Conflict):
            reopened.replay_operation(**different)
        with self.assertRaises(Conflict):
            reopened.replay_operation(**{**request, 'expected_version': 1})
        self.assertIsNone(reopened.replay_operation(
            **{**request, 'operation_id': 'not-yet-committed-operation'}))
        self.assertEqual(reopened.snapshot(), before)

    def test_workflow_validation_rejects_unsubstantiated_completion(self):
        row = self.project(capture([mail()]))['rows'][0]
        base = self.payload(row)
        for index, extra in enumerate([
                {'state': 'done', 'outcome': ''},
                {'state': 'pending', 'next_action': ''},
                {'state': 'following', 'next_action': ''},
                {'state': 'invented'}, {'reviewer': ''}, {'source_digest': 'invalid'},
                {'state': 'following', 'followup_at': '2026-10-22T09:00:00'}]):
            with self.subTest(extra=extra), self.assertRaises(Invalid):
                self.store.save('sf_email', row['id'], {**base, **extra}, 0, 'invalid-mail-operation-' + str(index))
        done = self.payload(row, 'done', outcome='Reviewed report and recorded the next owner')
        self.store.save('sf_email', row['id'], done, 0, 'done-mail-operation')
        self.assertEqual(self.project(capture([mail()]))['counts']['done'], 1)

    def test_completed_mail_stays_done_while_new_mail_in_same_case_is_unreviewed(self):
        source = capture([mail()])
        row = self.project(source)['rows'][0]
        self.store.save('sf_email', row['id'], self.payload(row, 'done', outcome='Recorded handling result'),
                        0, 'complete-first-mail')
        self.archive(source, 'completed', self.project(source, run_id='completed'))
        later = capture([mail(), mail('mail-2')], observed=TUESDAY)
        result = self.project(later, comp=comparison([mail('mail-2')]))
        self.assertEqual(result['new_incoming'], 1)
        self.assertEqual(result['counts']['done'], 1)
        self.assertEqual(result['counts']['unreviewed'], 1)
        self.assertEqual(self.by_mail(result)['mail-1']['state'], 'done')
        self.assertIsNone(self.by_mail(result)['mail-2']['record'])

    def test_changed_evidence_requires_recheck_without_rewriting_completion(self):
        source = capture([mail()])
        row = self.project(source)['rows'][0]
        saved = self.store.save('sf_email', row['id'], self.payload(row, 'done', outcome='Reviewed original evidence'),
                                0, 'completed-original-mail')
        self.archive(source, 'original', self.project(source, run_id='original'))
        changed = capture([mail(body='Synthetic report with additional evidence')], observed=TUESDAY)
        result = self.project(changed, run_id='newer-source')
        current = result['rows'][0]
        self.assertEqual(current['state'], 'done')
        self.assertTrue(current['needs_recheck'])
        self.assertNotEqual(current['source']['evidence_sha256'], saved['payload']['source_digest'])
        self.assertEqual(current['record'], saved)
        self.archive(changed, 'newer-source', result)
        replay = self.project(source, run_id='late-replay-of-old-source')
        self.assertEqual(replay['rows'][0]['source']['evidence_sha256'], current['source']['evidence_sha256'])
        self.assertTrue(replay['rows'][0]['needs_recheck'])
        self.assertEqual(len(self.store.history('sf_email', row['id'])), 1)

    def test_late_older_capture_corrects_first_observed_without_replacing_latest_evidence(self):
        newer = capture([mail(body='Newer synthetic evidence')], observed=TUESDAY)
        first = self.project(newer, run_id='newer-first')
        prior = self.archive(newer, 'newer-first', first)
        old_bytes = {p.name: p.read_bytes() for p in prior.iterdir()}
        expected = copy.deepcopy(first['rows'][0]['source'])
        self.assertEqual(expected['first_observed_at'], TUESDAY)

        # The earlier snapshot arrives after the cumulative report was saved.
        older = capture([mail(body='Earlier synthetic evidence')], observed=MONDAY,
                        status='PARTIAL', complete=False)
        replay = self.project(older, run_id='older-arrived-later')
        expected['first_observed_at'] = MONDAY
        self.assertEqual(replay['known_total'], 1)
        self.assertEqual(replay['rows'][0]['source'], expected)
        self.assertEqual(replay['counts']['unreviewed'], 1)
        self.assertEqual(old_bytes, {p.name: p.read_bytes() for p in prior.iterdir()})

    def test_record_must_match_observed_mail_identity_and_evidence(self):
        inbox = self.project(capture([mail()]))
        row = inbox['rows'][0]
        request = {'id': row['id'], 'payload': self.payload(row)}
        validate_record(request, inbox)
        with self.assertRaises(Invalid):
            validate_record({**request, 'id': 'not-observed'}, inbox)
        wrong_source = copy.deepcopy(request)
        wrong_source['payload']['instance'] = 'https://wrong-synthetic.invalid'
        with self.assertRaises(Invalid):
            validate_record(wrong_source, inbox)
        stale_source = copy.deepcopy(request)
        stale_source['payload']['source_digest'] = '0' * 64
        with self.assertRaises(Conflict):
            validate_record(stale_source, inbox)
        with self.assertRaises(Invalid):
            self.store.save('sf_email', 'invented-record-id', request['payload'], 0, 'wrong-identity-operation')

    def test_tampered_history_is_rejected_and_manual_state_is_not_changed(self):
        source = capture([mail()])
        archive = self.archive(source, 'history', self.project(source, run_id='history'))
        before = self.store.snapshot()
        (archive / 'sf-inbox.json').write_text('{}')
        with self.assertRaises(Invalid):
            self.project(capture([], observed=TUESDAY))
        self.assertEqual(self.store.snapshot(), before)

    def test_synthetic_and_real_cumulative_history_cannot_mix(self):
        source = capture([mail()])
        self.archive(source, 'synthetic', self.project(source, run_id='synthetic'))
        with self.assertRaises(Invalid):
            self.project(capture([], synthetic=False))

    def test_sf_workflow_does_not_change_casework_stage_effort_or_jira(self):
        source = capture([mail()])
        case = {'case_id': 'DEMO-177', 'stage': 'analysis', 'stage_confirmation': 'confirmed',
                'entered_at': '2026-10-19T09:00:00+08:00', 'entry_evidence': 'Synthetic event',
                'evidence': 'Synthetic review', 'reviewer': 'DEMO reviewer',
                'owner_kind': 'unknown', 'acceptance': 'pending', 'dates': {}}
        self.store.save('case', 'DEMO-177', case, 0, 'independent-case-operation')
        before = build_casework(source, self.store.snapshot(), EMPTY_REVIEW, TUESDAY)
        case_history = self.store.history('case', 'DEMO-177')
        row = self.project(source)['rows'][0]
        self.store.save('sf_email', row['id'], self.payload(row, 'done', outcome='Handled this message only'),
                        0, 'independent-mail-operation')
        after = build_casework(source, self.store.snapshot(), EMPTY_REVIEW, TUESDAY)
        for field in ('cases', 'counts', 'stages', 'effort', 'weekly', 'source'):
            self.assertEqual(before[field], after[field], field)
        self.assertEqual(self.store.history('case', 'DEMO-177'), case_history)
        self.assertEqual(after['cases'][0]['jira_status'], 'In Progress')
        self.assertEqual(after['cases'][0]['stage'], 'analysis')


if __name__ == '__main__':
    unittest.main()
