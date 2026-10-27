"""R1: unanswered work remains visible after local completion and reopening.

Only new temporary synthetic records and immutable fixture snapshots are used.
No HTTP service or company data is opened by this module.
"""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from psirt_casework.inbox import build, validate_record
from psirt_casework.mail_triage import validate_review
from psirt_casework.store import Store
import test_psirt_sf_inbox as fixtures
from test_psirt_sf_inbox import capture, comparison, mail, TUESDAY


class OutstandingAnswerTests(unittest.TestCase):
    archive = fixtures.SFInboxTests.archive

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = Store(self.root / 'casework', synthetic=True)
        incoming = mail(body='Please confirm the policy and the technical result.')
        outgoing = {**mail('reply-1', incoming=False, body='Policy confirmed; technical result pending.'),
                    'MessageDate': '2026-10-19T19:45:00+08:00'}
        self.source = capture([incoming, outgoing])

    def project(self, source=None, run_id='current'):
        source = self.source if source is None else source
        return build(self.root, source, self.store.snapshot(), comparison(), run_id, source['captured_at'])

    def save_review(self, answer, **changes):
        view = self.project()
        row = view['rows'][0]
        previous = row.get('record') or {}
        source = row['source']
        payload = {'instance': source['instance'], 'email_id': source['email_id'],
                   'source_digest': source['evidence_sha256'], 'state': 'done',
                   'next_action': 'Obtain the remaining technical evidence',
                   'outcome': 'This local review step was completed', 'followup_at': '',
                   'reviewer': 'DEMO reviewer', 'review_version': '1',
                   'analysis_digest': row['triage']['input_digest'],
                   'reviewed_category': 'inquiry', 'reviewed_summary': 'Synthetic two-question review',
                   'reviewed_attention': 'normal', 'answer_assessment': answer,
                   'reply_ids': 'reply-1', 'reply_note': 'Synthetic sent human reply verified',
                   'reviewed_reply_fact': 'sent_human',
                   'answer_note': 'Synthetic comparison against the two questions',
                   **changes}
        if previous:
            payload['correction_reason'] = 'Explicit synthetic review correction'
        request = {'id': row['id'], 'payload': payload}
        validate_record(request, view)
        validate_review(payload, row, view)
        return self.store.save('sf_email', row['id'], payload, previous.get('version', 0),
                               'r1-save-' + str(previous.get('version', 0)))

    def test_done_exit_requires_answered_or_not_required_without_other_recheck(self):
        for answer, attention in (('partial', True), ('unanswered', True), ('unchecked', True),
                                  ('answered', False), ('not_required', False)):
            with self.subTest(answer=answer):
                saved = self.save_review(answer)
                manual = self.store.snapshot()
                row = self.project()['rows'][0]
                self.assertEqual(row['triage']['needs_attention'], attention)
                self.assertEqual(row['triage']['answer_assessment'], answer)
                self.assertTrue(row['triage']['review_current'])
                self.assertEqual(row['state'], 'done')
                self.assertEqual(row['record'], saved)
                self.assertEqual(self.store.snapshot(), manual)
        self.assertEqual(len(self.store.history('sf_email', saved['id'])), 5)

    def test_partial_and_unanswered_survive_store_reopen_and_next_day_zero_new_mail(self):
        for answer in ('partial', 'unanswered'):
            with self.subTest(answer=answer):
                saved = self.save_review(answer)
                first = self.project(run_id=answer)
                run = self.archive(self.source, answer, first)
                report_bytes = {p.name: p.read_bytes() for p in run.iterdir()}
                manual = self.store.snapshot()
                self.store = Store(self.root / 'casework', synthetic=True)
                next_day = capture([], observed=TUESDAY, start='2026-10-20T00:00:00+08:00')
                next_day['sources']['salesforce']['raw'] = []
                result = self.project(next_day, run_id=answer + '-next-day')
                row = result['rows'][0]
                self.assertEqual(result['new_incoming'], 0)
                self.assertEqual(result['known_total'], 1)
                self.assertFalse(row['in_current_capture'])
                self.assertTrue(row['triage']['needs_attention'])
                self.assertTrue(row['triage']['review_current'])
                self.assertFalse(row['needs_recheck'])
                self.assertEqual(row['record'], saved)
                self.assertEqual(row['triage']['input_digest'], saved['payload']['analysis_digest'])
                self.assertEqual(self.store.snapshot(), manual)
                self.assertEqual(report_bytes, {p.name: p.read_bytes() for p in run.iterdir()})

    def test_rerun_keeps_answered_review_but_new_reply_or_changed_source_reopens_attention(self):
        for answer in ('answered', 'not_required'):
            with self.subTest(answer=answer):
                saved = self.save_review(answer)
                manual = self.store.snapshot()
                rerun = copy.deepcopy(self.source)
                rerun['captured_at'] = rerun['sources']['salesforce']['observed_at'] = TUESDAY
                rerun['config']['cutoff'] = TUESDAY
                current = self.project(rerun)['rows'][0]
                self.assertFalse(current['triage']['needs_attention'])
                self.assertFalse(current['needs_recheck'])
                self.assertEqual(current['triage']['input_digest'], saved['payload']['analysis_digest'])
                new_reply = copy.deepcopy(rerun)
                new_reply['sources']['salesforce']['emails'].append({
                    **mail('reply-2', incoming=False, body='Additional technical evidence'),
                    'MessageDate': '2026-10-20T08:30:00+08:00'})
                changed_body = copy.deepcopy(rerun)
                changed_body['sources']['salesforce']['emails'][0]['TextBody'] += ' One more question.'
                for source in (new_reply, changed_body):
                    changed = self.project(source)['rows'][0]
                    self.assertTrue(changed['triage']['needs_attention'])
                    self.assertTrue(changed['needs_recheck'])
                    self.assertEqual(changed['triage']['answer_assessment'], 'unchecked')
                    self.assertEqual(changed['record'], saved)
                self.assertEqual(self.store.snapshot(), manual)


if __name__ == '__main__':
    unittest.main()
