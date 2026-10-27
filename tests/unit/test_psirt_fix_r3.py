"""R3: preserve bounded DT observations without claiming complete coverage.

All requests use in-memory Readers. The replay test writes only a new temporary
root and never invokes company adapters or authentication.
"""
import copy
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_ops import adapters
from psirt_ops.dt_statistics import build as statistics
from psirt_ops.pipeline import encoded, run
from psirt_dt_fixtures import capture

PID = '00000000-0000-0000-0000-000000000001'
BASE = 'https://synthetic.invalid'
SECRET = 'SYNTHETIC_CREDENTIAL_MUST_NOT_APPEAR'


class Reader:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.urls = []

    def get(self, url, headers=None):
        self.urls.append(url)
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return copy.deepcopy(reply)


def component(index):
    return {'uuid': 'c' + str(index), 'name': 'Synthetic component', 'version': '1'}


def finding(index):
    return {'component': component(index),
            'vulnerability': {'uuid': 'v' + str(index), 'vulnId': 'CVE-2026-99999',
                              'source': 'NVD', 'severity': 'CRITICAL'},
            'analysis': {'state': 'NOT_SET'}}


def page(rows, total):
    return rows, {'X-Total-Count': total}


def http_error():
    return urllib.error.HTTPError(BASE + '/private?' + SECRET, 503, SECRET,
                                  {'Authorization': SECRET}, io.BytesIO(SECRET.encode()))


class DTPaginationRetentionTests(unittest.TestCase):
    def paged(self, replies):
        return adapters.dt_pages(Reader(replies), BASE + '/api/v1/component/project/' + PID,
                                 {'X-Api-Key': SECRET})

    def source(self, component_replies, finding_replies):
        reader = Reader([({'version': 'synthetic/1'}, {}),
                         ({'uuid': PID, 'name': 'Synthetic EXAMPLE-BOARD fixture', 'version': '1'}, {})]
                        + component_replies + finding_replies)
        with patch.object(adapters, 'dt_key', return_value=SECRET):
            source = adapters.collect_dt(reader, {'dt_base': BASE, 'dt_projects': [PID]})
        source.update(synthetic=True, observed_at='2026-10-26T12:00:00+08:00')
        self.assertNotIn(SECRET, json.dumps(source))
        self.assertTrue(all(url.startswith(BASE + '/api/') for url in reader.urls))
        return source

    def test_missing_later_total_retains_101_rows_and_two_page_observations(self):
        rows, pages, complete = self.paged([page([component(i) for i in range(100)], '101'),
                                          ([component(100)], {})])
        self.assertFalse(complete)
        self.assertEqual([row['uuid'] for row in rows], ['c' + str(i) for i in range(101)])
        self.assertEqual(len(pages), 2)
        self.assertEqual(pages[0]['total'], 101)
        self.assertIsNone(pages[1]['total'])
        self.assertEqual(pages[1]['incomplete_reason'], 'missing_total_header')

    def test_invalid_total_preserves_current_valid_rows_without_exposing_header(self):
        for total in (SECRET, '-1', '1.5', True, -1, 1.5, {}, '9' * 10000):
            with self.subTest(total_type=type(total).__name__):
                rows, pages, complete = self.paged([page([component(0)], '2'),
                                                  page([component(1)], total)])
                self.assertFalse(complete)
                self.assertEqual(len(rows), 2)
                self.assertIsNone(pages[-1]['total'])
                self.assertEqual(pages[-1]['incomplete_reason'], 'invalid_total_header')
                self.assertNotIn(SECRET, json.dumps(pages))

    def test_changed_total_retains_rows_and_both_declarations(self):
        rows, pages, complete = self.paged([page([component(0)], '2'), page([component(1)], '3')])
        self.assertFalse(complete)
        self.assertEqual(len(rows), 2)
        self.assertEqual([p['total'] for p in pages], [2, 3])
        self.assertEqual(pages[-1]['incomplete_reason'], 'total_changed')

    def test_later_http_failure_preserves_prior_rows_and_sanitized_failure(self):
        rows, pages, complete = self.paged([page([component(0)], '2'), http_error()])
        self.assertFalse(complete)
        self.assertEqual(rows, [component(0)])
        self.assertEqual(len(pages), 2)
        self.assertTrue(pages[-1]['query_failed'])
        self.assertEqual(pages[-1]['returned'], 0)
        self.assertEqual(pages[-1]['error']['http_status'], 503)
        self.assertNotIn(SECRET, json.dumps(pages))

    def test_invalid_response_keeps_verified_prior_and_current_dict_records(self):
        for response, expected, reason in [
            ({'message': SECRET}, 1, 'response_not_list'),
            ([component(1), SECRET], 2, 'invalid_record_shape'),
        ]:
            with self.subTest(reason=reason):
                rows, pages, complete = self.paged([page([component(0)], '3'), page(response, '3')])
                self.assertFalse(complete)
                self.assertEqual(len(rows), expected)
                self.assertEqual(pages[-1]['incomplete_reason'], reason)
                self.assertNotIn(SECRET, json.dumps({'rows': rows, 'pages': pages}))

    def test_empty_page_and_excess_rows_do_not_prove_completeness(self):
        for replies, expected_count, reason in [
            ([page([component(0)], '2'), page([], '2')], 1, 'empty_page_before_total'),
            ([page([component(0), component(1)], '1')], 2, 'count_exceeds_declared_total'),
        ]:
            with self.subTest(reason=reason):
                rows, pages, complete = self.paged(replies)
                self.assertFalse(complete)
                self.assertEqual(len(rows), expected_count)
                self.assertEqual(pages[-1]['incomplete_reason'], reason)

    def test_page_limit_keeps_100_successful_observations_without_an_extra_request(self):
        reader = Reader([page([component(i)], '101') for i in range(100)])
        rows, pages, complete = adapters.dt_pages(reader, BASE, {})
        self.assertFalse(complete)
        self.assertEqual((len(rows), len(pages), len(reader.urls)), (100, 100, 100))
        self.assertEqual(pages[-1]['incomplete_reason'], 'page_limit_reached')

    def test_complete_pages_and_complete_empty_inventory_remain_successful(self):
        for replies, count in [([page([], '0')], 0),
                               ([page([component(0)], '2'), ([component(1)], {'x-total-count': '2'})], 2)]:
            with self.subTest(count=count):
                rows, pages, complete = self.paged(replies)
                self.assertTrue(complete)
                self.assertEqual(len(rows), count)
                self.assertFalse(any(p.get('incomplete_reason') for p in pages))

    def test_collector_keeps_partial_inventory_findings_and_unknown_statistics(self):
        source = self.source([page([component(i) for i in range(100)], '101'), ([component(100)], {})],
                             [page([finding(i) for i in range(100)], '101'), ([finding(100)], {})])
        self.assertEqual(source['status'], 'PARTIAL')
        self.assertFalse(source['complete'])
        self.assertEqual(len(source['components'][0]['records']), 101)
        self.assertEqual(len(source['raw']), 101)
        self.assertEqual(len(source['finding_responses'][0]['records']), 101)
        for endpoint in source['pages']:
            self.assertEqual(endpoint['declared_total'], 101)
            self.assertIsNone(endpoint['verified_total'])
            self.assertEqual(len(endpoint['pages']), 2)
        self.assertEqual(len(source['errors']), 2)
        snapshot = capture()
        snapshot['sources']['dt'] = source
        result = statistics(snapshot, 'synthetic-r3', 'snapshot-replay')
        self.assertEqual(result['observed_counts']['components'], 101)
        self.assertEqual(result['observed_counts']['findings'], 101)
        self.assertIsNone(result['counts']['components'])
        self.assertIsNone(result['counts']['findings'])
        self.assertEqual(result['status'], 'PARTIAL')

    def test_failed_finding_endpoint_does_not_discard_complete_components(self):
        source = self.source([page([component(0)], '1')], [http_error()])
        self.assertEqual(source['status'], 'PARTIAL')
        self.assertEqual(len(source['projects']), 1)
        self.assertEqual(source['components'][0]['records'], [component(0)])
        self.assertEqual(source['raw'], [])
        self.assertEqual(source['pages'][0]['verified_total'], 1)
        self.assertIsNone(source['pages'][1]['verified_total'])
        self.assertEqual(source['errors'][0]['http_status'], 503)
        self.assertEqual(source['errors'][0]['endpoint'], 'findings')

    def test_invalid_finding_does_not_discard_other_identifiable_findings(self):
        source = self.source([page([component(0), component(1)], '2')],
                             [page([finding(0), {'component': None}, finding(1)], '3')])
        self.assertEqual(source['status'], 'PARTIAL')
        self.assertFalse(source['complete'])
        self.assertEqual(len(source['finding_responses'][0]['records']), 3)
        self.assertEqual(len(source['raw']), 2)
        self.assertEqual(source['errors'][0]['reason'], 'finding_identity_missing')

    def test_partial_capture_never_replaces_successful_baseline_or_old_report(self):
        complete = self.source([page([component(0)], '1')], [page([finding(0)], '1')])
        partial = self.source([page([component(0)], '2'), http_error()],
                              [page([finding(0)], '2'), http_error()])
        self.assertTrue(complete['complete'])
        with tempfile.TemporaryDirectory(prefix='psirt-r3-') as temporary:
            root = Path(temporary)
            snapshot = capture()
            snapshot['sources']['salesforce']['emails'] = []
            snapshot['sources']['dt'] = complete
            input_path = root / 'synthetic.json'
            input_path.write_bytes(encoded(snapshot))
            with patch('psirt_daily.offline.install_offline_guard'), \
                    patch.object(adapters, 'collect', side_effect=AssertionError('Collection forbidden')):
                first = run(root / 'isolated', 'snapshot-replay', snapshot=input_path)
                before = json.loads((root / 'isolated/state.json').read_text())
                old_report = Path(first['run_dir']) / 'index.html'
                old_bytes = old_report.read_bytes()
                snapshot['sources']['dt'] = partial
                input_path.write_bytes(encoded(snapshot))
                second = run(root / 'isolated', 'snapshot-replay', snapshot=input_path)
                after = json.loads((root / 'isolated/state.json').read_text())
            self.assertEqual(second['exit_code'], 1)
            self.assertEqual(after['baselines']['dt'], before['baselines']['dt'])
            self.assertIsNone(second['comparisons']['dt']['counts'])
            self.assertEqual(second['comparisons']['dt']['comparison'], 'SOURCE_INCOMPLETE')
            self.assertEqual(old_report.read_bytes(), old_bytes)
            current_stats = json.loads((Path(second['run_dir']) / 'dt-statistics.json').read_text())
            self.assertIsNone(current_stats['counts']['findings'])
            self.assertEqual(current_stats['observed_counts']['findings'], 1)


if __name__ == '__main__':
    unittest.main()
