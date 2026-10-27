"""Pure synthetic statistics checks: no API, DB, service or daily output writes."""
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_ops.statistics import build


def issue(key, category='new', at='2026-10-26T00:30:00+08:00'):
    return {'key': key, 'fields': {'created': at, 'updated': at,
            'status': {'statusCategory': {'key': category}}}}


def sample():
    sources = {name: {'status': 'SUCCESS', 'complete': True,
                     'observed_at': '2026-10-26T10:00:00+08:00', 'raw': []}
               for name in ('kev', 'dt', 'jira')}
    sources['kev']['raw'] = {'catalogVersion': 'synthetic', 'count': 2, 'vulnerabilities': [
        {'cveID': 'CVE-2026-10001', 'dateAdded': '2026-10-25'},
        {'cveID': 'CVE-2026-10002', 'dateAdded': '2026-10-26'}]}
    sources['jira']['raw'] = [issue('TEST-1', 'new'), issue('TEST-2', 'indeterminate'), issue('TEST-3', 'done')]
    sources['dt']['scope'] = {'instance': 'https://synthetic.invalid', 'project_uuids': ['p1', 'p2']}
    for pid in ('p1', 'p2'):
        sources['dt']['raw'].append({'id': pid + '/finding', 'project': {'uuid': pid},
                                    'component': {'uuid': 'same-component-uuid'},
                                    'vulnerability': {'uuid': 'v1', 'vulnId': 'CVE-2026-10001'}})
    return {'synthetic': True, 'captured_at': '2026-10-26T10:00:00+08:00',
            'config': {'window_start': '2026-10-12T00:00:00+08:00',
                       'cutoff': '2026-10-26T10:00:00+08:00', 'dt_scope_note': 'Synthetic explicit projects'},
            'sources': sources}


def comparable(capture, *, additions=False):
    return {name: {'comparison': 'COMPARABLE', 'changes': {
        'added': (copy.deepcopy(source['raw']['vulnerabilities']) if name == 'kev' else copy.deepcopy(source['raw'])) if additions else [],
        'changed': [], 'removed': []}} for name, source in capture['sources'].items()}


class Statistics(unittest.TestCase):
    def test_query_window_and_taipei_calendar_week_are_independent(self):
        capture = sample()
        capture['config']['cutoff'] = '2026-10-25T16:30:00Z'  # Monday 00:30 Taipei.
        capture['sources']['jira']['raw'] = [issue('SUN', at='2026-10-25T15:59:59Z'),
                                           issue('MON', at='2026-10-25T16:00:00Z'),
                                           issue('LATER', at='2026-10-25T16:31:00Z')]
        result = build(capture, {})
        self.assertEqual(result['periods']['calendar_week']['start'], '2026-10-26T00:00:00+08:00')
        self.assertEqual(result['periods']['calendar_week']['end'], '2026-10-26T00:30:00+08:00')
        self.assertEqual(result['kev']['counts'], {'catalog': 2, 'window': 2, 'week': 1, 'added': None})
        self.assertEqual(result['jira']['keys']['window_created'], ['MON', 'SUN'])
        self.assertEqual(result['jira']['keys']['week_created'], ['MON'])
        self.assertEqual(result['kev']['date_precision'], 'day')

    def test_sunday_month_year_boundary_uses_captured_cutoff_not_now(self):
        capture = sample(); capture['config']['cutoff'] = '2027-01-03T23:59:59+08:00'
        result = build(capture, {})
        self.assertEqual(result['periods']['calendar_week']['start'], '2026-12-28T00:00:00+08:00')
        capture['config']['cutoff'] = '2027-01-04T00:00:00+08:00'
        self.assertEqual(build(capture, {})['periods']['calendar_week']['start'], '2027-01-04T00:00:00+08:00')

    def test_unknown_jira_category_is_not_open_and_makes_exact_classification_unknown(self):
        capture = sample(); capture['sources']['jira']['raw'].append(issue('TEST-4', None))
        result = build(capture, {})['jira']
        self.assertEqual(result['keys']['open'], ['TEST-1', 'TEST-2'])
        self.assertEqual(result['keys']['unknown'], ['TEST-4'])
        self.assertEqual(result['counts']['total'], 4)
        self.assertEqual(result['counts']['unknown'], 1)
        self.assertEqual(result['observed_counts']['open'], 2)
        self.assertIsNone(result['counts']['open']); self.assertIsNone(result['counts']['done'])

    def test_duplicate_keys_and_cves_count_distinct_entities(self):
        capture = sample()
        capture['sources']['kev']['raw']['vulnerabilities'] *= 2
        capture['sources']['kev']['raw']['count'] = 4
        capture['sources']['jira']['raw'] *= 2
        capture['sources']['dt']['raw'] *= 2
        result = build(capture, comparable(capture, additions=True))
        self.assertEqual(result['kev']['counts']['catalog'], 2)
        self.assertEqual(result['kev']['counts']['added'], 2)
        self.assertEqual(result['jira']['counts']['total'], 3)
        self.assertEqual(result['jira']['counts']['added'], 3)
        self.assertEqual(result['kev_dt']['counts'], {'cves': 1, 'findings': 2, 'projects': 2})
        self.assertEqual(len(result['kev_dt']['findings'][0]['evidence_refs']), 2)

    def test_conflicting_duplicate_category_and_dates_do_not_pick_arbitrary_record(self):
        capture = sample()
        capture['sources']['jira']['raw'].append(issue('TEST-1', 'done', '2026-10-25T10:00:00+08:00'))
        capture['sources']['kev']['raw']['vulnerabilities'].append({'cveID': 'CVE-2026-10001', 'dateAdded': '2026-10-26'})
        capture['sources']['kev']['raw']['count'] = 3
        result = build(capture, {})
        self.assertEqual(result['jira']['keys']['unknown'], ['TEST-1'])
        self.assertIsNone(result['jira']['counts']['open'])
        self.assertIsNone(result['jira']['counts']['week_created'])
        self.assertEqual(result['kev']['counts']['catalog'], 2)
        self.assertIsNone(result['kev']['counts']['week'])

    def test_partial_failed_or_false_complete_keeps_observations_without_exact_totals(self):
        for name in ('kev', 'dt', 'jira'):
            for status, complete in (('PARTIAL', False), ('FAILED', False), ('SUCCESS', False)):
                with self.subTest(source=name, status=status):
                    capture = sample(); capture['sources'][name].update(status=status, complete=complete)
                    result = build(capture, comparable(capture))
                    if name in ('kev', 'jira'):
                        self.assertTrue(all(value is None for value in result[name]['counts'].values()))
                        self.assertGreater(result[name]['observed_counts']['catalog' if name == 'kev' else 'total'], 0)
                    if name in ('kev', 'dt'):
                        self.assertEqual(result['kev_dt']['counts'], dict.fromkeys(('cves', 'findings', 'projects')))
                        self.assertEqual(result['kev_dt']['observed_counts'], {'cves': 1, 'findings': 2, 'projects': 2})

    def test_repeated_delta_zero_preserves_full_catalog_matches(self):
        capture = sample()
        first = build(capture, comparable(capture, additions=True))
        repeat = build(capture, comparable(capture))
        self.assertEqual(first['kev']['counts']['added'], 2)
        self.assertEqual(repeat['kev']['counts']['added'], 0)
        self.assertEqual(first['kev_dt']['counts'], repeat['kev_dt']['counts'])
        self.assertEqual(repeat['kev_dt']['counts'], {'cves': 1, 'findings': 2, 'projects': 2})
        self.assertEqual(repeat['kev_dt']['added']['counts'], {'cves': 0, 'findings': 0, 'projects': 0})
        self.assertIsNone(repeat['kev_dt']['product_count'])

    def test_missing_comparison_stays_unknown_and_legacy_finding_is_preserved(self):
        capture = sample()
        capture['sources']['dt']['raw'] = [{'id': 'legacy-finding', 'vulnerability': {'vulnId': 'CVE-2026-10001'}}]
        result = build(capture, {name: {'changes': None} for name in capture['sources']})
        self.assertIsNone(result['kev']['counts']['added'])
        self.assertEqual(result['kev_dt']['observed_counts'], {'cves': 1, 'findings': 1, 'projects': 0})
        self.assertIsNone(result['kev_dt']['counts']['findings'])
        self.assertFalse(result['kev_dt']['findings'][0]['identity_verified'])
        self.assertEqual(result['kev_dt']['findings'][0]['evidence_refs'], ['capture.json#/sources/dt/raw/0'])

    def test_complete_empty_is_zero_and_missing_or_invalid_raw_is_unknown(self):
        capture = sample(); capture['sources']['kev']['raw']['vulnerabilities'] = []
        capture['sources']['kev']['raw']['count'] = 0
        capture['sources']['jira']['raw'] = []; capture['sources']['dt']['raw'] = []
        result = build(capture, comparable(capture))
        self.assertTrue(all(value == 0 for value in result['kev']['counts'].values()))
        self.assertTrue(all(value == 0 for value in result['jira']['counts'].values()))
        self.assertEqual(result['kev_dt']['counts'], {'cves': 0, 'findings': 0, 'projects': 0})
        for name in ('kev', 'jira', 'dt'):
            invalid = copy.deepcopy(capture); invalid['sources'][name]['raw'] = None
            bad = build(invalid, comparable(capture))
            self.assertFalse(bad['kev_dt']['complete'] if name == 'dt' else bad[name]['complete'])

    def test_invalid_dates_do_not_crash_or_count_as_no_activity(self):
        capture = sample(); capture['sources']['jira']['raw'][0]['fields']['created'] = 'invalid'
        capture['sources']['kev']['raw']['vulnerabilities'][0]['dateAdded'] = None
        result = build(capture, {})
        self.assertIsNone(result['jira']['counts']['window_created'])
        self.assertIsNone(result['kev']['counts']['window'])
        self.assertEqual(result['jira']['counts']['total'], 3)
        capture['config']['cutoff'] = '2026-10-26T10:00:00'  # No timezone, do not assume one.
        result = build(capture, {})
        self.assertIn('CUTOFF_UNKNOWN', result['periods']['errors'])
        self.assertIsNone(result['kev']['counts']['week'])

    def test_declared_catalog_count_cannot_hide_truncation_or_invalid_count(self):
        for declared in (100, 0, None, '2', True, -1):
            with self.subTest(declared=declared):
                capture = sample(); capture['sources']['kev']['raw']['count'] = declared
                result = build(capture, comparable(capture))
                self.assertFalse(result['kev']['complete'])
                self.assertTrue(all(value is None for value in result['kev']['counts'].values()))
                self.assertEqual(result['kev']['observed_counts']['catalog'], 2)
                self.assertEqual(result['kev']['observed_rows'], 2)
                self.assertIsNone(result['kev_dt']['counts']['findings'])
                self.assertEqual(result['kev_dt']['observed_counts']['findings'], 2)

    def test_explicit_cve_alias_matches_but_description_is_not_identity(self):
        capture = sample(); row = capture['sources']['dt']['raw'][0]
        row['vulnerability'] = {'uuid': 'g1', 'vulnId': 'GHSA-example', 'aliases': [{'cveId': 'CVE-2026-10001'}]}
        self.assertEqual(build(capture, {})['kev_dt']['counts']['findings'], 2)
        row['vulnerability'] = {'uuid': 'g1', 'vulnId': 'GHSA-example', 'description': 'CVE-2026-10001'}
        result = build(capture, {})['kev_dt']
        self.assertIsNone(result['counts']['findings'])
        self.assertEqual(result['observed_counts']['findings'], 1)

    def test_output_is_compact_deterministic_and_inputs_unchanged(self):
        capture = sample(); capture['sources']['jira']['raw'][0]['fields']['description'] = 'PRIVATE_BODY_DO_NOT_COPY'
        capture['sources']['dt']['raw'][0]['vulnerability']['description'] = 'PRIVATE_BODY_DO_NOT_COPY'
        comparisons = comparable(capture); before = copy.deepcopy((capture, comparisons))
        first = build(capture, comparisons)
        self.assertEqual(first, build(capture, comparisons))
        self.assertEqual((capture, comparisons), before)
        self.assertNotIn('PRIVATE_BODY_DO_NOT_COPY', json.dumps(first))


if __name__ == '__main__':
    unittest.main()
