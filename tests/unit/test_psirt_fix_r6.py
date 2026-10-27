"""R6: one effort policy for detail, dashboard and immutable report exports."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from psirt_casework.effort import RULE_VERSION as EFFORT_RULE, summarize_work
from psirt_casework.projection import build
from psirt_casework.store import Store, validate
from psirt_casework.web import render
import test_psirt_dashboard_integration as html_fixture
from test_psirt_casework import sample

ASOF = '2026-10-26T12:00:00+08:00'
LEGACY = {'schema': 'psirt-human-review/1', 'reviews': {}}


def record(key='actual', version=1, **changes):
    payload = validate('worklog', {'case_ids': ['DEMO-177'], 'task': 'Synthetic work',
        'work_date': '2026-10-26', 'minutes': 30, 'category': 'technical_analysis',
        'measurement': 'measured', 'outcome': 'Synthetic result', 'evidence': 'fixture://work',
        **changes})
    return {'kind': 'worklog', 'id': key, 'version': version, 'payload': payload}


def manual(records):
    return {'records': records, 'revisions': [], 'available': True, 'synthetic': True}


def project(records, as_of=ASOF, previous=None):
    return build(sample(), manual(records), LEGACY, as_of, previous=previous)


class EffortConsistencyTests(unittest.TestCase):
    def assert_views(self, data, actual, case='DEMO-177'):
        detail = next(row for row in data['cases'] if row['id'] == case)
        self.assertEqual(detail['actual_minutes'], actual)
        self.assertEqual(data['dashboard']['cases'][case]['actual_minutes'], actual)
        self.assertEqual(data['effort']['actual_minutes'], actual)
        self.assertEqual(data['dashboard']['work']['actual_minutes'], actual)
        for key in ('actual_minutes', 'estimated_minutes', 'record_count', 'measured_record_count',
                    'measured_record_ids', 'shared_record_ids', 'rule_version', 'excluded_records'):
            self.assertEqual(data['effort'][key], data['dashboard']['work'][key], key)
        self.assertEqual(data['effort']['rule_version'], EFFORT_RULE)

    def test_no_measurement_is_unknown_even_with_estimate_and_html_matches_projection(self):
        for records in ([], [record('estimate', minutes=40, measurement='estimated')]):
            with self.subTest(records=records):
                original = copy.deepcopy(records)
                data = project(records)
                self.assert_views(data, None)
                self.assertEqual(data['effort']['estimated_minutes'], 40 if records else None)
                page = html_fixture.Page(render(html_fixture.SHELL, data))
                self.assertEqual(page.data, data)
                self.assertEqual(records, original)

    def test_future_date_and_unfinished_known_period_are_excluded_but_records_retained(self):
        future = record('future-date', work_date='2026-10-27')
        ongoing = record('future-end', start='2026-10-26T11:45:00+08:00',
                         end='2026-10-26T12:15:00+08:00')
        for row in (future, ongoing):
            with self.subTest(record=row['id']):
                data = project([row])
                self.assert_views(data, None)
                self.assertEqual(data['worklogs'], [row])
                self.assertEqual(data['effort']['stored_record_count'], 1)
                self.assertEqual(data['effort']['record_count'], 0)
                self.assertEqual(data['effort']['excluded_records'][0]['id'], row['id'])
        completed = project([ongoing], '2026-10-26T12:15:00+08:00')
        self.assert_views(completed, 30)

    def test_dated_net_minutes_without_endpoints_are_valid_and_estimates_stay_separate(self):
        net = record()
        estimate = record('estimate', measurement='estimated', minutes=40)
        self.assertNotIn('start', net['payload'])
        self.assertNotIn('end', net['payload'])
        data = project([net, estimate])
        self.assert_views(data, 30)
        self.assertEqual(data['effort']['estimated_minutes'], 40)
        self.assertEqual(data['effort']['measured_record_ids'], ['actual'])
        self.assertEqual(data['effort']['estimated_record_ids'], ['estimate'])
        self.assertEqual(data['effort']['untimed_record_ids'], ['actual', 'estimate'])

    def test_shared_work_counted_once_latest_revision_wins_and_wait_is_independent(self):
        old = record('shared', case_ids=['DEMO-177', 'DEMO-179'], minutes=20)
        latest = record('shared', version=2, case_ids=['DEMO-177', 'DEMO-179'], minutes=30)
        wait = {'kind': 'wait', 'id': 'wait', 'version': 1, 'payload': {
            'case_id': 'DEMO-177', 'start': '2026-10-26T09:00:00+08:00',
            'end': '2026-10-26T10:00:00+08:00', 'evidence': 'fixture://wait'}}
        records = [old, latest, copy.deepcopy(latest), wait]
        original = copy.deepcopy(records)
        data = project(records)
        self.assert_views(data, 30)
        self.assertEqual(next(r for r in data['cases'] if r['id'] == 'DEMO-179')['actual_minutes'], 30)
        self.assertEqual(data['dashboard']['cases']['DEMO-179']['actual_minutes'], 30)
        self.assertEqual(data['effort']['record_count'], 1)
        self.assertEqual(data['effort']['shared_record_ids'], ['shared'])
        self.assertEqual(data['effort']['waiting_union_minutes'], 60)
        self.assertEqual(records, original)
        self.assertEqual(project(records), data)

    def test_latest_work_association_is_used_before_case_totals(self):
        old = record('same-id', case_ids=['DEMO-177'])
        latest = record('same-id', version=2, case_ids=['DEMO-179'])
        data = project([old, latest])
        self.assertIsNone(next(r for r in data['cases'] if r['id'] == 'DEMO-177')['actual_minutes'])
        self.assertIsNone(data['dashboard']['cases']['DEMO-177']['actual_minutes'])
        self.assertEqual(next(r for r in data['cases'] if r['id'] == 'DEMO-179')['actual_minutes'], 30)
        self.assertEqual(data['effort']['actual_minutes'], 30)

    def test_incomplete_or_malformed_legacy_period_never_counts_as_completed_work(self):
        for updates in ({'start': '2026-10-26T10:00:00+08:00'},
                        {'start': 'bad', 'end': 'bad'},
                        {'start': '2026-10-26T11:00:00+08:00', 'end': '2026-10-26T10:00:00+08:00'}):
            row = record()
            row['payload'].update(updates)
            original = copy.deepcopy(row)
            result = summarize_work([row], ASOF)
            self.assertIsNone(result['actual_minutes'])
            self.assertEqual(result['record_count'], 0)
            self.assertEqual(row, original)

    def test_timezone_and_rule_compatibility_are_explicit(self):
        records = [record()]
        first = project(records)
        self.assert_views(project(records, '2026-10-26T04:00:00+00:00'), 30)
        self.assertEqual(project(records, previous=first)['weekly']['comparison'], 'COMPARABLE')
        old = copy.deepcopy(first)
        old['schema'] = old['compatibility']['rule'] = 'case-timing/4'
        before = copy.deepcopy(old)
        self.assertEqual(project(records, previous=old)['weekly']['comparison'], 'UNKNOWN')
        self.assertEqual(old, before)


class EffortReportTests(unittest.TestCase):
    def test_saved_records_and_reports_use_frozen_as_of_without_rewriting_history(self):
        # The pipeline installs the offline guard, so no external sources can run.
        from psirt_ops.pipeline import run
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, output = base / 'source.json', base / 'output'
            source.write_text(json.dumps(sample()))
            with patch('psirt_ops.pipeline.now', return_value=ASOF):
                first = Path(run(output, 'snapshot-replay', snapshot=source)['run_dir'])
                old_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in first.iterdir()}
                store = Store(output / 'casework', True)
                for row in (record(), record('estimate', measurement='estimated', minutes=40),
                            record('future', work_date='2026-10-27')):
                    store.save('worklog', row['id'], row['payload'], 0, 'save-' + row['id'])
                saved = store.snapshot()
                new = Path(run(output, 'report-rebuild')['run_dir'])
            reopened = Store(output / 'casework', True)
            self.assertEqual(reopened.snapshot(), saved)
            data = json.loads((new / 'casework.json').read_text())
            self.assertEqual(data['as_of'], ASOF)
            EffortConsistencyTests().assert_views(data, 30)
            self.assertEqual(data['effort']['estimated_minutes'], 40)
            self.assertEqual(data['effort']['stored_record_count'], 3)
            self.assertEqual(html_fixture.Page((new / 'casework.html').read_text()).data, data)
            self.assertEqual(old_hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in first.iterdir()})
            self.assertEqual(json.loads((new / 'casework_manual_used.json').read_text()), saved)


if __name__ == '__main__':
    unittest.main()
