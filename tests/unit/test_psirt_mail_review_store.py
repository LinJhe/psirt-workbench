"""Independent mail-review persistence and source-validation integration tests.

Only temporary synthetic stores are used; no company API or service process.
"""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework.inbox import build, validate_record
from psirt_casework.mail_triage import annotate, merge_index, validate_review
from psirt_casework.store import Conflict, Invalid, Store
from test_psirt_sf_inbox import capture, comparison, mail, TUESDAY


FIELDS = {'review_version', 'analysis_digest', 'reviewed_category', 'reviewed_summary',
          'reviewed_attention', 'answer_assessment', 'reply_ids', 'answer_note',
          'reviewed_reply_fact', 'reply_note'}


class MailReviewStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'casework', synthetic=True)
        incoming = mail(body='Can you provide the PGP public key?')
        outgoing = {**mail('reply-1', incoming=False, body='Synthetic policy reply'),
                    'MessageDate': '2026-10-19T20:30:00+08:00', 'Status': 'UNVERIFIED_SOURCE_VALUE'}
        unrelated = {**mail('other-case-outgoing', incoming=False, parent='case-2'),
                     'MessageDate': '2026-10-19T21:30:00+08:00'}
        self.source = capture([incoming, outgoing, unrelated], observed=TUESDAY)
        self.initial = self.project()
        self.row = self.initial['rows'][0]
        self.id = self.row['id']

    def project(self, source=None):
        source = self.source if source is None else source
        view = build(self.root, source, self.store.snapshot(), comparison(), 'fixture-run', TUESDAY)
        index = {}
        merge_index(index, source, 'fixture-run')
        view['triage_contexts'] = annotate(view['rows'], index)
        return view

    def legacy(self, **changes):
        source = self.row['source']
        return {'instance': source['instance'], 'email_id': source['email_id'],
                'source_digest': source['evidence_sha256'], 'state': 'pending',
                'next_action': 'Review synthetic PGP question', 'outcome': '',
                'followup_at': '', 'reviewer': 'DEMO reviewer', **changes}

    def payload(self, **changes):
        return {**self.legacy(), 'review_version': '1',
                'analysis_digest': self.row['triage']['input_digest'],
                'reviewed_category': 'inquiry', 'reviewed_summary': 'Researcher asks for PGP key',
                'reviewed_attention': 'normal', 'answer_assessment': 'unchecked',
                'reply_ids': '', 'answer_note': '', 'reviewed_reply_fact': 'unknown',
                'reply_note': '', **changes}

    def save(self, payload, version=0, operation='review-operation-01'):
        return self.store.save('sf_email', self.id, payload, version, operation)

    def assert_unchanged(self, before):
        self.assertEqual(before, self.store.snapshot())

    def test_all_ten_fields_roundtrip_and_reopen_preserves_review_separate_from_rules(self):
        payload = self.payload(reviewed_category='notification', reviewed_summary='Human correction')
        request = {'id': self.id, 'payload': payload}
        validate_record(request, self.initial)
        validate_review(payload, self.row, self.initial)
        saved = self.save(payload)
        reopened = Store(self.root / 'casework', synthetic=True)
        self.assertEqual(reopened.get('sf_email', self.id), saved)
        self.assertEqual({k: saved['payload'][k] for k in FIELDS}, {k: payload[k] for k in FIELDS})
        row = self.project()['rows'][0]
        self.assertEqual(row['triage']['suggested_category'], 'inquiry')
        self.assertEqual(row['triage']['category'], 'notification')
        self.assertEqual(row['triage']['summary'], 'Human correction')
        self.assertEqual(row['record'], saved)

    def test_partial_new_schema_or_nested_values_rejected_without_mutation(self):
        original = self.payload()
        before = self.store.snapshot()
        for missing in FIELDS:
            payload = {k: v for k, v in original.items() if k != missing}
            with self.subTest(missing=missing), self.assertRaises(Invalid):
                self.save(payload)
        for key, value in [('review_version', '2'), ('analysis_digest', 'not-a-digest'),
                           ('reviewed_category', 'made_up'), ('reviewed_attention', 'urgent'),
                           ('answer_assessment', 'closed'), ('reviewed_reply_fact', 'sent'),
                           ('reply_ids', ['reply-1']), ('reviewed_summary', {'text': 'nested'}),
                           ('reply_ids', 'reply-1,reply-1'), ('reply_ids', 'reply/unsafe')]:
            with self.subTest(key=key, value=value), self.assertRaises(Invalid):
                self.save(self.payload(**{key: value}))
        self.assert_unchanged(before)

    def test_legacy_record_remains_readable_and_can_upgrade_with_history(self):
        old = self.save(self.legacy(), operation='legacy-operation-01')
        self.assertNotIn('review_version', old['payload'])
        prior = self.project()['rows'][0]
        self.assertEqual(prior['record'], old)
        self.assertFalse(prior['triage']['review_current'])
        upgraded = self.save(self.payload(correction_reason='Explicitly reviewed the new classification'),
                             1, 'upgrade-operation-01')
        self.assertEqual(upgraded['version'], 2)
        self.assertEqual(self.store.history('sf_email', self.id)[0]['payload'], old['payload'])
        self.assertEqual(self.project()['rows'][0]['triage']['review_current'], True)

    def test_legacy_form_cannot_erase_new_review_even_with_latest_record_version(self):
        saved = self.save(self.payload())
        before = self.store.snapshot()
        legacy = self.legacy(state='following', correction_reason='Old form attempted update')
        with self.assertRaises(Conflict):
            self.save(legacy, saved['version'], 'legacy-overwrite-01')
        self.assert_unchanged(before)
        self.assertEqual(self.store.get('sf_email', self.id), saved)

    def test_old_committed_operation_is_replayable_after_upgrade_without_downgrading(self):
        original = {'kind': 'sf_email', 'id': self.id, 'payload': self.legacy(),
                    'expected_version': 0, 'operation_id': 'legacy-replay-001'}
        first = self.store.save(**original)
        latest = self.save(self.payload(correction_reason='Upgrade after old response lost'), 1, 'upgrade-operation-02')
        before = self.store.snapshot()
        self.assertEqual(self.store.replay_operation(**original), first)
        self.assertEqual(self.store.save(**original), first)
        self.assertEqual(self.store.get('sf_email', self.id), latest)
        self.assert_unchanged(before)

    def test_new_operation_replay_and_version_conflicts_preserve_latest_review(self):
        payload = self.payload()
        original = {'kind': 'sf_email', 'id': self.id, 'payload': payload,
                    'expected_version': 0, 'operation_id': 'new-review-replay-01'}
        first = self.store.save(**original)
        latest = self.save(self.payload(reviewed_summary='Explicit corrected summary',
                            correction_reason='Correct the interpretation'), 1, 'new-review-update-01')
        before = self.store.snapshot()
        self.assertEqual(self.store.replay_operation(**original), first)
        self.assertEqual(self.store.save(**original), first)
        with self.assertRaises(Conflict):
            self.save(self.payload(correction_reason='Stale competing edit'), 1, 'new-stale-operation')
        altered = copy.deepcopy(original)
        altered['payload']['reviewed_summary'] = 'Different request must not reuse token'
        with self.assertRaises(Conflict):
            self.store.replay_operation(**altered)
        self.assertEqual(self.store.get('sf_email', self.id), latest)
        self.assert_unchanged(before)

    def test_answered_cannot_claim_draft_automatic_internal_or_unknown_reply(self):
        before = self.store.snapshot()
        for fact in ('draft_or_failed', 'automated', 'internal', 'unknown', 'not_found'):
            payload = self.payload(answer_assessment='answered', reviewed_reply_fact=fact,
                                   reply_ids='reply-1', reply_note='Synthetic source observation',
                                   answer_note='Claimed answer')
            with self.subTest(fact=fact), self.assertRaises(Invalid):
                self.save(payload)
        self.assert_unchanged(before)

    def test_partial_and_answered_require_selected_reply_and_both_evidence_notes(self):
        before = self.store.snapshot()
        for answer in ('partial', 'answered'):
            valid = self.payload(answer_assessment=answer, reviewed_reply_fact='sent_human',
                                 reply_ids='reply-1', reply_note='Manually checked sent human reply',
                                 answer_note='Policy question addressed; technical result not claimed')
            for missing in ('reply_ids', 'reply_note', 'answer_note'):
                with self.subTest(answer=answer, missing=missing), self.assertRaises(Invalid):
                    self.save({**valid, missing: ''})
            validate_review(valid, self.row, self.initial)
        self.assert_unchanged(before)
        saved = self.save(valid)
        self.assertEqual(saved['payload']['answer_assessment'], 'answered')

    def test_incoming_unknown_or_wrong_case_reply_id_rejected_by_source_validation(self):
        for reply_id in ('mail-1', 'not-observed', 'other-case-outgoing'):
            payload = self.payload(answer_assessment='partial', reviewed_reply_fact='sent_human',
                                   reply_ids=reply_id, reply_note='Human note', answer_note='Partial answer')
            with self.subTest(reply_id=reply_id), self.assertRaises(Invalid):
                validate_review(payload, self.row, self.initial)
        self.assertEqual(self.store.records('sf_email'), [])

    def test_manual_not_required_and_done_leave_attention_queue_with_evidence_preserved(self):
        payload = self.payload(state='done', reviewed_category='other', reviewed_attention='reference',
                               answer_assessment='not_required', answer_note='Verified synthetic marketing, no question needs a reply',
                               outcome='Reviewed and retained as reference; no deletion', next_action='')
        validate_review(payload, self.row, self.initial)
        saved = self.save(payload)
        result = self.project()
        row = result['rows'][0]
        self.assertFalse(row['triage']['needs_attention'])
        self.assertEqual(row['triage']['answer_assessment'], 'not_required')
        self.assertEqual(row['record'], saved)
        self.assertEqual(result['known_total'], 1)
        self.assertEqual(len(self.store.history('sf_email', self.id)), 1)
        for key in ('answer_note', 'outcome'):
            with self.subTest(missing=key), self.assertRaises(Invalid):
                self.save({**payload, key: ''}, 1, 'invalid-completion-01')

    def test_new_outgoing_invalidates_answer_review_and_rejects_old_digest_without_clearing_record(self):
        payload = self.payload(state='done', answer_assessment='answered', reviewed_reply_fact='sent_human',
                               reply_ids='reply-1', reply_note='Human checked evidence',
                               answer_note='Answered this PGP question', outcome='Recorded answer evidence')
        saved = self.save(payload)
        changed = copy.deepcopy(self.source)
        changed['sources']['salesforce']['emails'].append({**mail('reply-2', incoming=False),
                'MessageDate': '2026-10-19T21:00:00+08:00'})
        updated = self.project(changed)
        row = updated['rows'][0]
        self.assertTrue(row['triage']['needs_attention'])
        self.assertTrue(row['triage']['needs_recheck'])
        self.assertEqual(row['triage']['answer_assessment'], 'unchecked')
        self.assertEqual(row['record'], saved)
        with self.assertRaises(Conflict):
            validate_review(payload, row, updated)
        self.assertEqual(len(self.store.history('sf_email', self.id)), 1)


if __name__ == '__main__':
    unittest.main()
