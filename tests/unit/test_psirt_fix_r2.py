"""EmailMessage absence is unknown across projections and immutable reports."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_ops.pipeline import compare, run
from psirt_ops.sf_messages import email_coverage, email_items
from psirt_ops.reports import analyze, daily_markdown
from psirt_ops.html_report import model, render
from psirt_ops.sf_triage import build as triage
from psirt_ops.weekly_presentation import build as weekly, markdown
from psirt_casework.inbox import build as inbox
from psirt_sf_fixtures import sample
from test_psirt_html import Parsed

MISSING = object()


def changed(value):
    capture = sample()
    source = capture['sources']['salesforce']
    if value is MISSING:
        source.pop('emails', None)
    else:
        source['emails'] = copy.deepcopy(value)
    return capture


class EmailCoverageFix(unittest.TestCase):
    def test_unknown_collection_never_compares_as_empty_in_either_direction(self):
        known = sample()['sources']['salesforce']
        for bad in (MISSING, None, {}, 'invalid', 4, [None], [{'Id': None}]):
            source = changed(bad)['sources']['salesforce']
            for before, after in ((source, source), (source, known), (known, source)):
                with self.subTest(value=repr(bad), old_unknown=before is source):
                    result = compare('salesforce', after, before)
                    self.assertEqual(result['counts'], {'added': 0, 'changed': 0, 'removed': 0})
                    self.assertIsNone(result['email_counts'])
                    self.assertIsNone(result['email_changes'])

    def test_complete_empty_zero_requires_compatible_complete_baselines(self):
        source = changed([])['sources']['salesforce']
        self.assertEqual(compare('salesforce', source, source)['email_counts'],
                         {'added': 0, 'changed': 0, 'removed': 0})
        self.assertIsNone(compare('salesforce', source)['email_counts'])
        for updates in ({'scope': {'different': True}},
                        {'observed_at': '2020-01-01T00:00:00+00:00'},
                        {'status': 'FAILED', 'complete': False},
                        {'status': 'PARTIAL', 'complete': False}):
            with self.subTest(updates=updates):
                self.assertIsNone(compare('salesforce', {**source, **updates}, source)['email_counts'])

    def test_observed_valid_rows_keep_original_evidence_offsets(self):
        message = sample()['sources']['salesforce']['emails'][0]
        capture = changed([None, message])
        source = capture['sources']['salesforce']
        self.assertEqual(email_items(source), [(1, message)])
        self.assertEqual(email_coverage(source)['coverage'], 'PARTIAL')
        with tempfile.TemporaryDirectory() as directory:
            result = inbox(Path(directory), capture, {'records': [], 'revisions': []},
                           compare('salesforce', source, source), 'synthetic', capture['captured_at'])
        self.assertEqual(result['known_total'], 1)
        self.assertTrue(result['rows'][0]['source']['evidence_ref'].endswith('/emails/1'))
        self.assertIsNone(result['new_incoming'])
        self.assertIn('/emails/1', next(iter(result['message_index'].values()))['evidence_ref'])
        duplicate = changed([message, message])['sources']['salesforce']
        self.assertFalse(email_coverage(duplicate)['complete'])
        self.assertIsNone(compare('salesforce', duplicate, duplicate)['email_counts'])

    def test_all_views_share_unknown_and_case_success_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            for bad in (MISSING, None, {}, 'invalid', [None]):
                with self.subTest(value=repr(bad)):
                    capture = changed(bad)
                    comparisons = {name: compare(name, src, src) for name, src in capture['sources'].items()}
                    data = analyze(capture, comparisons, {'reviews': {}})
                    home = model(capture, data, comparisons, 'snapshot-replay', 'demo')
                    sf = triage(capture, comparisons, {'schema': 'psirt-human-review/1', 'reviews': {}},
                                'demo', 'snapshot-replay', capture['captured_at'])
                    mail = inbox(Path(directory), capture, {'records': [], 'revisions': []},
                                 comparisons['salesforce'], 'demo', capture['captured_at'])
                    self.assertEqual(mail['email_coverage'], sf['email_coverage'])
                    self.assertIsNone(home['metrics']['sf_week_messages'])
                    self.assertIsNone(home['metrics']['sf_email_added'])
                    self.assertIsNone(sf['increments']['emails'])
                    self.assertIsNone(mail['new_incoming'])
                    self.assertEqual(sf['index_count'], 5)
                    self.assertEqual(mail['source']['status'], 'SUCCESS')
                    page = render(capture, data, comparisons, 'snapshot-replay', 'demo')
                    self.assertIn('郵件覆蓋待確認', page)
                    self.assertNotIn('四來源完整取得', page)
                    self.assertNotIn('本窗口訊息 0', page)
                    self.assertIn('本窗口訊息 待確認／Unknown', page)
                    daily = daily_markdown(capture, data, comparisons, 'snapshot-replay', 'demo')
                    self.assertIn('窗口內郵件數：待確認／Unknown', daily)
                    report = weekly(capture, data, sf, {'meetings': {}, 'overrides': []}, '2026-10-26')
                    self.assertEqual(report['audit']['sf_email_coverage'], sf['email_coverage'])
                    self.assertIn('郵件資料不完整', markdown(report))

    def test_replay_missing_and_null_preserves_history_and_matches_html_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source_path = root / 'input.json'; output = root / 'output'
            old_files = {}
            for bad in (MISSING, None, 'invalid', []):
                capture = changed(bad); source_path.write_text(json.dumps(capture))
                result = run(output, 'snapshot-replay', snapshot=source_path)
                current = Path(result['run_dir'])
                sf = json.loads((current / 'sf-triage.json').read_text())
                mail = json.loads((current / 'sf-inbox.json').read_text())
                page = Parsed((current / 'index.html').read_text())
                self.assertEqual(sf['email_coverage'], mail['email_coverage'])
                self.assertIsNone(sf['increments']['emails'])  # Previous email baseline lacks coverage.
                self.assertEqual(page.metrics['sf_week_messages'], '0' if bad == [] else '待確認／Unknown')
                self.assertEqual(json.loads((current / 'capture.json').read_text()), capture)
                for path, digest in old_files.items():
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                old_files.update({p: hashlib.sha256(p.read_bytes()).hexdigest() for p in current.iterdir()})
            repeated = Path(run(output, 'snapshot-replay', snapshot=source_path)['run_dir'])
            self.assertEqual(json.loads((repeated / 'sf-triage.json').read_text())['increments']['emails'], 0)


if __name__ == '__main__':
    unittest.main()
