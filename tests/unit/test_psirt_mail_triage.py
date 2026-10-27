"""Local-only mail suggestion, evidence continuity, and review contract tests."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework import inbox, mail_triage
from psirt_casework.store import Conflict, Invalid
import test_psirt_sf_inbox as fixtures
from test_psirt_sf_inbox import capture, comparison, mail, MONDAY, TUESDAY


class MailTriageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    archive = fixtures.SFInboxTests.archive

    def build(self, source, manual=None, run_id='current'):
        return inbox.build(self.root, source, manual or {'records': [], 'revisions': []},
                           comparison(), run_id, TUESDAY)

    @staticmethod
    def outgoing(mid='reply-1', **values):
        return {**mail(mid, incoming=False, body='We received this message.'),
                'MessageDate': '2026-10-19T20:30:00+08:00', **values}

    @staticmethod
    def review(row, **values):
        return {'review_version': '1', 'analysis_digest': row['triage']['input_digest'],
                'reviewed_category': 'inquiry', 'reviewed_summary': '人工內容',
                'reviewed_attention': 'normal', 'answer_assessment': 'unchecked',
                'reply_ids': '', 'answer_note': '', 'reviewed_reply_fact': 'unknown', 'reply_note': '',
                'reviewer': 'DEMO reviewer', 'state': 'done', 'outcome': 'Reviewed locally',
                'source_digest': row['source']['evidence_sha256'], **values}

    @staticmethod
    def manual(row, payload):
        record = {'kind': 'sf_email', 'id': row['id'], 'version': 1, 'payload': payload}
        return {'records': [record], 'revisions': [copy.deepcopy(record)]}

    def test_full_body_after_display_limit_is_analyzed_and_timeline_is_compact(self):
        message = mail(body='Context.\n' * 300 + 'A buffer overflow vulnerability is being exploited.')
        result = self.build(capture([message]))
        row = result['rows'][0]
        self.assertEqual(row['triage']['suggested_category'], 'vulnerability')
        self.assertEqual(row['triage']['attention'], 'priority')
        self.assertGreater(len(result['message_index'][row['id']]['analysis_text']), 1800)
        self.assertLessEqual(len(result['triage_contexts'][row['triage']['context_id']]['timeline'][0]['excerpt']), 1800)

    def test_quoted_urgent_history_and_signature_do_not_become_new_claims(self):
        for body in ('What is your bounty policy?\nOn Monday someone wrote:\nData breach and public PoC',
                     'What is your bounty policy?\nBest regards\npublic exploit'):
            with self.subTest(body=body):
                row = self.build(capture([mail(body=body)]))['rows'][0]
                self.assertEqual(row['triage']['category'], 'inquiry')
                self.assertEqual(row['triage']['attention'], 'normal')
                self.assertNotIn('public', row['triage']['suggested_summary'])
                self.assertTrue(set(row['triage']['flags']) & {'quoted_content', 'signature_removed'})

    def test_common_negated_urgent_terms_keep_original_sentence_and_normal_queue(self):
        for body in ('We have not published any public PoC.', 'This was not actively exploited.',
                     'There is no evidence of data breach.', '目前沒有資料外洩。'):
            with self.subTest(body=body):
                row = self.build(capture([mail(body=body)]))['rows'][0]
                self.assertEqual(row['triage']['attention'], 'normal')
                self.assertIn(body, row['triage']['attention_reason'])
                self.assertTrue(row['triage']['needs_attention'])

    def test_negation_does_not_hide_a_separate_positive_urgent_clause(self):
        for body in ('We have not published any public PoC. This is being exploited.',
                     'This was not actively exploited, but a public PoC is available.',
                     'It is not mitigated and is being exploited.'):
            with self.subTest(body=body):
                row = self.build(capture([mail(body=body)]))['rows'][0]
                self.assertEqual(row['triage']['attention'], 'priority')
                self.assertIn('不代表已發生', row['triage']['attention_reason'])

    def test_html_only_is_safe_text_and_encrypted_body_is_explicitly_unread(self):
        html = mail(body='') | {'HtmlBody': '<script>data breach</script><img src="https://tracking.invalid/pixel"><p>What is your PGP public key?</p>'}
        rowset = self.build(capture([html]))
        row = rowset['rows'][0]
        indexed = rowset['message_index'][row['id']]
        self.assertEqual(indexed['html_read_state'], 'converted_to_safe_text')
        self.assertEqual(row['triage']['category'], 'inquiry')
        self.assertEqual(row['triage']['attention'], 'normal')
        self.assertNotIn('tracking.invalid', indexed['text'])
        self.assertNotIn('data breach', indexed['text'])
        self.assertIn('PGP public key', row['triage']['body_excerpt'])
        encrypted = self.build(capture([mail(body='-----BEGIN PGP MESSAGE-----\nSECRET-CIPHERTEXT\n-----END PGP MESSAGE-----')]))
        r = encrypted['rows'][0]
        self.assertIn('encrypted_unread', r['triage']['flags'])
        self.assertEqual(r['triage']['category'], 'unknown')
        self.assertNotIn('SECRET-CIPHERTEXT', str(encrypted['message_index']))
        self.assertIn('不要求研究員重寄', r['triage']['suggested_next_action'])

    def test_four_rule_categories_and_unknown_never_automatically_downgrade_reference(self):
        for body, expected in [('A vulnerability and a PoC are attached.', 'vulnerability'),
                               ('What is your bounty policy?', 'inquiry'),
                               ('A service outage notification.', 'notification'),
                               ('Join our marketing webinar.', 'other'), ('Just a message.', 'unknown')]:
            with self.subTest(expected=expected):
                row = self.build(capture([mail(body=body)]))['rows'][0]
                self.assertEqual(row['triage']['category'], expected)
                self.assertNotEqual(row['triage']['attention'], 'reference')

    def test_outgoing_numeric_status_is_never_sent_or_answered(self):
        for status in ('0', '3', '5'):
            with self.subTest(status=status):
                result = self.build(capture([mail(), self.outgoing(Status=status)]))
                row = result['rows'][0]
                self.assertEqual(row['triage']['reply_candidate_ids'], ['reply-1'])
                self.assertEqual(row['triage']['reply_fact']['state'], 'candidates')
                self.assertEqual(row['triage']['answer_assessment'], 'unchecked')
                context = result['triage_contexts'][row['triage']['context_id']]
                self.assertTrue(all(m['sending_state'] == 'unknown' for m in context['timeline']))

    def test_new_outgoing_invalidates_analysis_but_preserves_completed_manual_revision(self):
        source = capture([mail()])
        row = self.build(source)['rows'][0]
        payload = self.review(row, answer_assessment='not_required', answer_note='Reference only')
        manual = self.manual(row, payload)
        before = copy.deepcopy(manual)
        updated = self.build(capture([mail(), self.outgoing()], observed=TUESDAY), manual)['rows'][0]
        self.assertEqual(updated['state'], 'done')
        self.assertTrue(updated['needs_recheck'])
        self.assertTrue(updated['triage']['needs_attention'])
        self.assertEqual(updated['triage']['answer_assessment'], 'unchecked')
        self.assertEqual(updated['source']['evidence_sha256'], row['source']['evidence_sha256'])
        self.assertEqual(manual, before)

    def test_observed_time_window_and_unrelated_case_do_not_invalidate_digest(self):
        initial = capture([mail(), self.outgoing()])
        old = self.build(initial)['rows'][0]
        newer = capture([mail(), self.outgoing(), self.outgoing('other', ParentId='case-2')],
                        observed=TUESDAY, start=TUESDAY)
        newer['sources']['salesforce']['emails'][0]['attributes'] = {'url': '/different/api/path'}
        row = self.build(newer)['rows'][0]
        self.assertEqual(row['triage']['input_digest'], old['triage']['input_digest'])
        # Original raw-source hash remains deliberately unchanged in meaning.
        self.assertNotEqual(row['source']['evidence_sha256'], old['source']['evidence_sha256'])

    def test_status_attachment_and_rules_changes_invalidate_analysis(self):
        original = capture([mail(), self.outgoing()])
        row = self.build(original)['rows'][0]
        for field, value in [('Status', '3'), ('HasAttachment', True), ('attachments_read_state', 'verified_text')]:
            changed = copy.deepcopy(original)
            changed['sources']['salesforce']['emails'][1][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(self.build(changed)['rows'][0]['triage']['input_digest'], row['triage']['input_digest'])
        with patch.object(mail_triage, 'RULE_VERSION', 'test-rule/2'):
            self.assertNotEqual(self.build(original)['rows'][0]['triage']['input_digest'], row['triage']['input_digest'])

    def test_confirmed_not_required_done_leaves_queue_and_human_summary_is_separate(self):
        source = capture([mail(body='Unclassified text')])
        row = self.build(source)['rows'][0]
        payload = self.review(row, reviewed_category='unknown', reviewed_attention='reference',
                              answer_assessment='not_required', answer_note='Confirmed no response required')
        mail_triage.validate_review(payload, row, {'rows': [row]})
        final = self.build(source, self.manual(row, payload))['rows'][0]
        self.assertFalse(final['triage']['needs_attention'])
        self.assertEqual(final['triage']['attention'], 'reference')
        self.assertEqual(final['triage']['summary'], '人工內容')
        self.assertNotEqual(final['triage']['suggested_summary'], '人工內容')

    def test_review_requires_current_digest_valid_reply_and_explicit_human_sending_evidence(self):
        source = capture([mail(), self.outgoing(), self.outgoing('other', ParentId='case-2'),
                          self.outgoing('earlier', MessageDate='2026-10-19T10:00:00+08:00')])
        result = self.build(source)
        row = result['rows'][0]
        good = self.review(row, reply_ids='reply-1', reviewed_reply_fact='sent_human',
                           reply_note='Verified original sent record and named author',
                           answer_assessment='answered', answer_note='Question matched to reply paragraph')
        mail_triage.validate_review(good, row, result)
        final = self.build(source, self.manual(row, good))['rows'][0]
        self.assertEqual(final['triage']['reply_fact']['state'], 'human_verified')
        for values, error in [({'analysis_digest': '0' * 64}, Conflict),
                              ({'reply_ids': 'other'}, Invalid), ({'reply_ids': 'earlier'}, Invalid),
                              ({'reply_ids': row['source']['email_id']}, Invalid),
                              ({'reply_ids': 'reply-1,reply-1'}, Invalid),
                              ({'reviewed_reply_fact': 'draft_or_failed'}, Invalid),
                              ({'reply_note': ''}, Invalid), ({'answer_note': ''}, Invalid)]:
            with self.subTest(values=values), self.assertRaises(error):
                mail_triage.validate_review(good | values, row, result)

    def test_legacy_artifact_bootstraps_full_outgoing_once_and_modern_index_carries_it(self):
        initial = capture([mail(), self.outgoing()])
        old = self.build(initial, run_id='old')
        for key in ('message_index', 'message_index_schema', 'triage_contexts', 'triage_rule_version'):
            old.pop(key, None)
        prior = self.archive(initial, 'old', old)
        before = {p.name: p.read_bytes() for p in prior.iterdir()}
        empty = capture([], observed=TUESDAY, start=TUESDAY, status='FAILED', complete=False)
        original_read = Path.read_bytes
        reads = []
        def read(path):
            if path == prior/'capture.json':
                reads.append(path)
            return original_read(path)
        with patch.object(Path, 'read_bytes', read):
            first = self.build(empty, run_id='new')
            second = self.build(empty, run_id='new')
            self.assertEqual(len(reads), 1)
        self.assertEqual(first, second)
        self.assertEqual(first['rows'][0]['triage']['reply_candidate_ids'], ['reply-1'])
        self.assertIsNone(first['new_incoming'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in prior.iterdir()})
        self.archive(empty, 'new', first)
        with patch.object(inbox, '_bootstrap', side_effect=AssertionError('Modern artifact must not rescan captures')):
            carried = self.build(empty)
        self.assertEqual(carried['rows'][0]['triage']['reply_candidate_ids'], ['reply-1'])

    def test_historical_incoming_and_other_instance_outgoing_never_join(self):
        original = capture([mail()])
        self.archive(original, 'old', self.build(original, run_id='old'))
        other = capture([self.outgoing()], instance='https://other.invalid', observed=TUESDAY)
        result = self.build(other)
        self.assertEqual(result['rows'][0]['triage']['reply_candidate_ids'], [])
        self.assertEqual(len(result['triage_contexts']), 2)

    def test_safe_source_health_keeps_failure_unknown_and_filters_raw_error_details(self):
        source = capture([mail()], status='FAILED', complete=False)
        source['sources']['salesforce'].update(auth_blocked=True, auth_error_code='INVALID_OPERATION_WITH_EXPIRED_PASSWORD',
            attempted=False, attempted_at=TUESDAY, auth_blocked_at=MONDAY,
            errors=[{'type': 'HTTPError', 'http_status': 401, 'error_code': 'INVALID_OPERATION_WITH_EXPIRED_PASSWORD',
                     'message': 'secret raw body', 'token': 'do not expose'}])
        result = self.build(source)
        self.assertIsNone(result['new_incoming'])
        self.assertTrue(result['source']['auth_blocked'])
        self.assertNotIn('secret raw body', str(result['source']))
        self.assertNotIn('token', result['source']['errors'][0])

    def test_last_success_is_current_success_but_keeps_previous_when_failed_or_skipped(self):
        comp = comparison() | {'last_successful_at': MONDAY}
        for status, complete, expected in [('SUCCESS', True, TUESDAY), ('FAILED', False, MONDAY),
                                            ('PARTIAL', False, MONDAY)]:
            with self.subTest(status=status):
                source = capture([], observed=TUESDAY, status=status, complete=complete)
                source['sources']['salesforce']['skipped_reason'] = 'AUTH_BLOCKED' if status == 'FAILED' else None
                result = inbox.build(self.root, source, {'records': [], 'revisions': []}, comp, 'current', TUESDAY)
                self.assertEqual(result['source']['last_successful_at'], expected)
                self.assertEqual(result['source']['skipped_reason'], source['sources']['salesforce']['skipped_reason'])

    def test_legacy_success_without_emails_has_stable_health_but_unknown_mail_coverage(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                source = capture(None, observed=TUESDAY)
                if missing:
                    del source['sources']['salesforce']['emails']
                first = inbox.build(self.root, source, {'records': [], 'revisions': []},
                    comparison(state='FIRST_BASELINE'), 'first', TUESDAY)
                repeated = inbox.build(self.root, source, {'records': [], 'revisions': []},
                    comparison() | {'last_successful_at': MONDAY}, 'repeated', TUESDAY)
                self.assertEqual(first['source'], repeated['source'])
                self.assertEqual(first['source']['last_successful_at'], TUESDAY)
                for result in (first, repeated):
                    self.assertEqual(result['coverage'], 'UNKNOWN')
                    self.assertIsNone(result['new_incoming'])

    def test_cached_bootstrap_revalidates_changed_capture_and_rejects_symlinks(self):
        initial = capture([mail(), self.outgoing()])
        old = self.build(initial, run_id='old')
        old.pop('message_index_schema')
        prior = self.archive(initial, 'old', old)
        self.build(capture([], observed=TUESDAY))
        path = prior/'capture.json'
        saved = path.read_bytes()
        path.write_bytes(saved + b' ')
        with self.assertRaises(Invalid):
            self.build(capture([], observed=TUESDAY))
        path.unlink()
        outside = self.root/'external.json'
        outside.write_bytes(saved)
        path.symlink_to(outside)
        with self.assertRaises((Invalid, ValueError)):
            self.build(capture([], observed=TUESDAY))


if __name__ == '__main__':
    unittest.main()
