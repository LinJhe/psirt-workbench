"""Preserve exact Jira-reference semantics while bounding repeated serialization."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_ops import sf_triage
from psirt_ops.pipeline import compare
from psirt_sf_fixtures import sample

NUMBER = 'Q-202610-90000'


def fixture(number=NUMBER):
    capture = sample()
    sf = capture['sources']['salesforce']
    sf['raw'] = [dict(sf['raw'][0], id='synthetic-case', Id='synthetic-case', CaseNumber=number)]
    sf['emails'] = []
    capture['sources']['jira']['raw'] = []
    return capture


def issue(key, text):
    return {'id': key, 'key': key, 'fields': {'summary': text}}


def analyze(capture):
    comparisons = {name: compare(name, source) for name, source in capture['sources'].items()}
    return sf_triage.build(capture, comparisons, {'schema': 'psirt-human-review/1', 'reviews': {}},
                           'synthetic-performance', 'snapshot-replay', '2026-10-22T09:00:00+08:00')


class TriagePerformance(unittest.TestCase):
    def test_prefix_suffix_unicode_words_and_hyphens_cannot_create_false_candidates(self):
        for text in (
                'A' + NUMBER, '9' + NUMBER, '_' + NUMBER, '-' + NUMBER,
                '中' + NUMBER, 'α' + NUMBER,
                NUMBER + 'A', NUMBER + '0', NUMBER + '_', NUMBER + '-',
                NUMBER + '中', NUMBER + 'α',
                'Q-202610-900000', 'prefix-' + NUMBER + '-suffix'):
            with self.subTest(text=text):
                capture = fixture()
                capture['sources']['jira']['raw'] = [issue('DEMO-900', text)]
                row = analyze(capture)['rows'][0]
                self.assertEqual(row['jira']['evidence'], [])
                self.assertEqual(row['jira']['status'], 'NOT_FOUND_IN_SCOPE')

    def test_punctuation_and_whitespace_boundaries_preserve_matches(self):
        for text in (NUMBER, '(' + NUMBER + ')', '[' + NUMBER + ']',
                     'reference: ' + NUMBER + '.', '案件：' + NUMBER + '；待查',
                     ' ' + NUMBER + ' ', '/' + NUMBER + '/'):
            with self.subTest(text=text):
                capture = fixture()
                capture['sources']['jira']['raw'] = [issue('DEMO-900', text)]
                row = analyze(capture)['rows'][0]
                self.assertEqual([r['key'] for r in row['jira']['evidence']], ['DEMO-900'])
                self.assertEqual(row['jira']['formal_link'], 'UNKNOWN')

    def test_special_case_number_is_matched_as_a_literal_without_tokenizing(self):
        for number in ('REQ/42 (A)+.β', 'CASE.[42]+?', '測試/甲 42', '12345'):
            with self.subTest(number=number):
                capture = fixture(number)
                capture['sources']['jira']['raw'] = [issue('DEMO-900', 'Reference (' + number + ')')]
                result = analyze(capture)['rows'][0]
                self.assertEqual([r['key'] for r in result['jira']['evidence']], ['DEMO-900'])

    def test_two_matching_jira_issues_retain_each_exact_source_reference(self):
        capture = fixture()
        capture['sources']['jira']['raw'] = [issue('DEMO-902', 'Ref: ' + NUMBER),
                                             issue('DEMO-901', '(' + NUMBER + ')')]
        row = analyze(capture)['rows'][0]
        references = {r['key']: r['evidence_refs'] for r in row['jira']['evidence']}
        self.assertEqual(set(references), {'DEMO-901', 'DEMO-902'})
        self.assertEqual(references['DEMO-902'][0]['path'], 'capture.json#/sources/jira/raw/0/fields')
        self.assertEqual(references['DEMO-901'][0]['path'], 'capture.json#/sources/jira/raw/1/fields')
        self.assertEqual(row['jira']['formal_link'], 'UNKNOWN')

    def test_details_override_index_and_detail_only_rows_do_not_expand_scope(self):
        capture = fixture()
        jira = capture['sources']['jira']
        jira['raw'] = [issue('DEMO-901', NUMBER), issue('DEMO-902', 'No case reference')]
        jira['details'] = {'DEMO-901': issue('DEMO-901', 'Reference removed in detailed source'),
                           'DEMO-902': issue('DEMO-902', 'Detailed reference: ' + NUMBER),
                           'DEMO-903': issue('DEMO-903', NUMBER)}
        row = analyze(capture)['rows'][0]
        self.assertEqual([r['key'] for r in row['jira']['evidence']], ['DEMO-902'])
        self.assertEqual(row['jira']['evidence'][0]['evidence_refs'][0]['path'],
                         'capture.json#/sources/jira/details/DEMO-902/fields')

    def test_partial_sources_keep_candidates_without_claiming_formal_relationship(self):
        capture = fixture()
        capture['sources']['salesforce'].update(status='PARTIAL', complete=False)
        capture['sources']['jira'].update(status='PARTIAL', complete=False,
            raw=[issue('DEMO-901', NUMBER)])
        data = analyze(capture)
        row = data['rows'][0]
        self.assertEqual(row['jira']['status'], 'CANDIDATE')
        self.assertEqual(row['jira']['current_status'], 'UNKNOWN_SOURCE_INCOMPLETE')
        self.assertEqual(row['jira']['formal_link'], 'UNKNOWN')
        self.assertIsNone(data['index_count'])
        self.assertTrue(all(value is None for value in data['counts'].values()))

    def test_jira_field_serialization_does_not_scale_with_case_count(self):
        capture = fixture()
        sf = capture['sources']['salesforce']
        base = sf['raw'][0]
        sf['raw'] = [dict(base, id='case-' + str(i), Id='case-' + str(i), CaseNumber='Q-202610-' + str(90000 + i))
                     for i in range(60)]
        jira = capture['sources']['jira']
        jira['raw'] = [issue('DEMO-901', NUMBER), issue('DEMO-902', 'No match'),
                       issue('DEMO-903', 'Q-202610-90059')]
        original = copy.deepcopy(capture)
        field_ids = {id(row['fields']) for row in jira['raw']}
        serialized = []
        actual_dumps = json.dumps

        def counted(value, *args, **kwargs):
            if id(value) in field_ids:
                serialized.append(id(value))
            return actual_dumps(value, *args, **kwargs)

        with patch.object(sf_triage.json, 'dumps', side_effect=counted):
            result = analyze(capture)
        self.assertLessEqual(len(serialized), len(jira['raw']))
        rows = {r['id']: r for r in result['rows']}
        self.assertEqual(rows['case-0']['jira']['evidence'][0]['key'], 'DEMO-901')
        self.assertEqual(rows['case-59']['jira']['evidence'][0]['key'], 'DEMO-903')
        self.assertEqual(rows['case-30']['jira']['evidence'], [])
        self.assertEqual(capture, original)


if __name__ == '__main__':
    unittest.main()
