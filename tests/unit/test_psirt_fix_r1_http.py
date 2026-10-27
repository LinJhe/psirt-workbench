"""R1 acceptance through a new synthetic loopback service, never a daily root."""
import copy
import unittest

import test_psirt_mail_triage_http as fixtures
from psirt_casework.service import start, stop
from psirt_casework.store import read_snapshot
from psirt_mail_triage_fixtures import review_request


class OutstandingMailHTTP(unittest.TestCase):
    # Reuse only the inspected isolated service/fixture helpers, not its tests.
    setUpClass = classmethod(fixtures.MailReviewHTTP.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.MailReviewHTTP.tearDownClass.__func__)
    run_capture = classmethod(fixtures.MailReviewHTTP.run_capture.__func__)
    request = fixtures.MailReviewHTTP.request
    state = fixtures.MailReviewHTTP.state
    row = fixtures.MailReviewHTTP.row

    def test_done_unanswered_and_partial_save_reopen_and_zero_new_mail_keep_attention(self):
        records = {}
        for email_id, answer in (('mail-question', 'partial'), ('mail-html', 'unanswered')):
            state, row = self.row(email_id)
            changes = {'state': 'done', 'outcome': 'Synthetic local review step completed',
                       'answer_assessment': answer, 'answer_note': 'A technical answer is still required'}
            if answer == 'partial':
                changes.update(reviewed_reply_fact='sent_human', reply_ids='human-partial',
                               reply_note='Synthetic sent human reply independently checked')
            request = review_request(row, 'r1-http-' + answer, **changes)
            status, saved = self.request('/api/records', request, state['session'])
            self.assertEqual(status, 200, saved)
            self.assertTrue(saved['committed_and_read_back'])
            records[email_id] = saved['record']
            reread = self.row(email_id)[1]
            self.assertTrue(reread['triage']['needs_attention'])
            self.assertEqual(reread['state'], 'done')
            self.assertEqual(reread['triage']['answer_assessment'], answer)

        manual = read_snapshot(self.root / 'casework', True)
        stop(self.root)
        type(self).entry = start(self.root)
        self.assertEqual(read_snapshot(self.root / 'casework', True), manual)
        for email_id in records:
            self.assertTrue(self.row(email_id)[1]['triage']['needs_attention'])

        source = copy.deepcopy(self.capture)
        source['captured_at'] = source['config']['cutoff'] = '2026-10-27T09:00:00+08:00'
        source['sources']['salesforce']['observed_at'] = source['captured_at']
        source['sources']['salesforce']['emails'] = []
        type(self).capture = source
        self.run_capture()
        state = self.state()
        self.assertEqual(state['inbox']['new_incoming'], 0)
        for email_id, saved in records.items():
            reread = self.row(email_id)[1]
            self.assertFalse(reread['in_current_capture'])
            self.assertTrue(reread['triage']['needs_attention'])
            self.assertTrue(reread['triage']['review_current'])
            self.assertEqual(reread['record'], saved)
        self.assertEqual(read_snapshot(self.root / 'casework', True), manual)


if __name__ == '__main__':
    unittest.main()
