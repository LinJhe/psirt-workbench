"""Sharing edition: tenant-neutral reports, inert text and explicit guidance scope."""
import copy
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from psirt_dt_fixtures import capture
from psirt_ops import decision_guide, html_report, kev_learning, pm_cra_guide, reports
from psirt_ops.pipeline import compare
from psirt_ops.weekly_presentation import build as weekly


class Tags(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.tags = []
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def fixture():
    value = capture()
    value['sources']['jira']['scope'] = {'instance': 'https://tracker.example.invalid'}
    value['sources']['jira']['raw'] = [{
        'id': 'DEMO-700', 'key': 'DEMO-700',
        'fields': {'summary': 'Synthetic Q-209901-90001',
                   'created': '2026-10-18T09:00:00+08:00',
                   'updated': '2026-10-18T09:00:00+08:00',
                   'status': {'name': 'In Progress', 'statusCategory': {'key': 'indeterminate'}}}}]
    comparisons = {name: compare(name, row, row) for name, row in value['sources'].items()}
    return value, comparisons, reports.analyze(value, comparisons, {'reviews': {}})


class ShareGuideTests(unittest.TestCase):
    def test_tenant_links_are_scoped_per_capture_without_shared_global_state(self):
        first, _, _ = fixture()
        second = copy.deepcopy(first)
        second['sources']['jira']['scope']['instance'] = 'https://second.example.invalid'
        self.assertEqual(reports.source_url(first, 'jira', 'DEMO-700'),
                         'https://tracker.example.invalid/browse/DEMO-700')
        self.assertEqual(reports.source_url(second, 'jira', 'DEMO-700'),
                         'https://second.example.invalid/browse/DEMO-700')
        self.assertIn('tracker.example.invalid', reports.link('DEMO-700', first))
        self.assertNotIn('http', reports.link('DEMO-700'))
        first['sources']['jira']['scope'] = None
        self.assertIsNone(reports.source_url(first, 'jira', 'DEMO-700'))

    def test_tenant_origin_rejects_active_schemes_credentials_and_ambiguous_urls(self):
        source, _, _ = fixture()
        for base in ('javascript:alert(1)', 'http://tracker.example.invalid',
                     'https://user:pass@tracker.example.invalid',
                     'https://tracker.example.invalid?access_token=sample',
                     'https://tracker.example.invalid/#fragment',
                     'https://tracker.example.invalid/path',
                     'https://tracker.example.invalid\\path',
                     'https://tracker.example.invalid\n'):
            with self.subTest(base=base):
                source['sources']['jira']['scope']['instance'] = base
                self.assertIsNone(reports.source_url(source, 'jira', 'DEMO-700'))
        source['sources']['jira']['scope']['instance'] = 'https://tracker.example.invalid'
        self.assertIn('%22%3E%3Cscript%3E', reports.source_url(source, 'jira', '\"><script>'))

    def test_html_and_markdown_link_back_to_captured_tenant_without_mutating_input(self):
        source, comparisons, data = fixture()
        original = copy.deepcopy(source)
        page = html_report.render(source, data, comparisons, 'snapshot-replay', 'synthetic-share')
        targets = [attrs.get('href', '') for _, attrs in Tags(page).tags]
        self.assertIn('https://tracker.example.invalid/browse/DEMO-700', targets)
        self.assertEqual([url for url in targets if '/browse/' in url],
                         ['https://tracker.example.invalid/browse/DEMO-700'])
        self.assertIn('tracker.example.invalid/browse/DEMO-700',
                      reports.action_markdown(source, data))
        self.assertEqual(source, original)

    def test_report_source_text_is_inert_in_html_and_guidance(self):
        source, comparisons, data = fixture()
        source['sources']['jira']['raw'][0]['fields']['summary'] = '<img src=x onerror=alert(1)>'
        data = reports.analyze(source, comparisons, {'reviews': {}})
        page = html_report.render(source, data, comparisons, 'snapshot-replay', 'synthetic-share')
        self.assertFalse(any(name.lower().startswith('on') for _, attrs in Tags(page).tags for name in attrs))
        guide = pm_cra_guide.load_content()
        guide['title'] = '<script>alert(1)</script>'
        guide['stages'][0]['input'] = '<img src=x onerror=alert(1)>'
        rendered = pm_cra_guide.render(data=guide)
        self.assertIn('&lt;script&gt;', rendered)
        self.assertFalse(any(tag in {'script', 'img'} for tag, _ in Tags(rendered).tags))

    def test_weekly_issue_selection_comes_from_source_references(self):
        source, _, data = fixture()
        model = weekly(source, data, {'rows': []}, {'meetings': {}, 'overrides': []}, '2026-10-18')
        rows = next(block['rows'] for block in model['blocks'] if block.get('key') == 'reported')
        self.assertEqual(rows[0][0], 'DEMO-700')
        self.assertEqual(rows[0][1], 'Q-209901-90001')
        source['sources']['jira']['raw'] = []
        comparisons = {name: compare(name, row, row) for name, row in source['sources'].items()}
        empty = reports.analyze(source, comparisons, {'reviews': {}})
        model = weekly(source, empty, {'rows': []}, {'meetings': {}, 'overrides': []}, '2026-10-18')
        self.assertFalse(any(row[0] == 'DEMO-700' for block in model['blocks']
                             if block.get('key') == 'reported' for row in block['rows']))

    def test_guides_do_not_claim_policy_approval_or_retain_internal_downloads(self):
        data = pm_cra_guide.load_content()
        self.assertIn('不是任何組織已核准', data['subtitle'])
        self.assertEqual(pm_cra_guide.download_artifacts(), {})
        self.assertEqual(pm_cra_guide.DOWNLOADS, ())
        self.assertIn('合成案例', decision_guide.render())
        source, comparisons, _ = fixture()
        learning = kev_learning.render(source, comparisons)
        self.assertIn('合成情境', learning)
        self.assertIn('沒有本輪重新連線查核', learning)
        self.assertIn('不替公司設定回應或修補期限', learning)


if __name__ == '__main__':
    unittest.main()
