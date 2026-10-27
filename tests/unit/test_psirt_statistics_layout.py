"""Overview definitions and source identity using isolated, synthetic inputs only."""
import copy
import re
import sys
import tempfile
import unittest
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from psirt_ops.nordic_layout import finish
from psirt_ops.garden_layout import finish as garden
from psirt_ops.pipeline import compare
from psirt_ops.sf_triage import build as build_sf, render as render_sf
from psirt_casework.projection import build as build_cases
from psirt_casework.store import read_snapshot
from psirt_casework.web import render as render_cases
from psirt_casework.branding import enhance as brand
from psirt_sf_fixtures import sample


SHELL = '''<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>PSIRT 工作台 · newly-generated-report-id</title></head><body><aside>
<div class="brand-mark">IEI</div><nav><a href="sf-triage.html">SF</a><a href="casework.html">案件</a></nav></aside>
<header class="page-head"><div class="head-top">IEI / PRODUCT SECURITY
<span class="edition">NORDIC 02 · 本機草稿</span></div><h1>PSIRT 工作總覽</h1>
<p>今天需要處理的事</p><p>擷取完成 OLD_SOURCE_TIME · snapshot-replay</p></header><main>
<div class="workspace-links"><a href="#kev-dt">old number</a></div></main></body></html>'''


class Header(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.active = False
        self.paragraphs = []
        self.contents = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == 'header':
            self.active = True
        if self.active and tag == 'p':
            self.paragraphs.append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == 'header':
            self.active = False

    def handle_data(self, value):
        if self.active:
            self.contents.append(value)


class StatisticsLayoutTests(unittest.TestCase):
    def setUp(self):
        self.capture = sample()
        self.capture['captured_at'] = '2026-10-19T09:00:00+08:00'
        self.capture['sources']['jira']['observed_at'] = '2026-10-19T08:58:00+08:00'
        self.capture['sources']['jira']['scope'] = {'project': 'SYNTHETIC', 'selection': 'all statuses including Done'}
        self.vm = {'mode': 'snapshot-replay', 'captured_at': self.capture['captured_at'],
                   'window_start': '2026-10-01T00:00:00+08:00', 'cutoff': '2026-10-19T09:00:00+08:00',
                   'metrics': {'kev_window': 3, 'kev_week': 0, 'kev_added': 0, 'jira_open': 4},
                   'statistics': {'periods': {'query': {'start': '2026-10-01T00:00:00+08:00', 'end': '2026-10-19T09:00:00+08:00'}}}}
        self.data = {'sf_activity': []}

    def output(self):
        return finish(SHELL, self.vm, self.data, self.capture)

    def overview(self, page, name):
        return unescape(re.search(r'<strong class="kpi-number" data-overview="' + re.escape(name) + '">(.*?)</strong>', page).group(1))

    def test_zero_delta_does_not_replace_nonzero_query_period_inventory(self):
        page = self.output()
        self.assertEqual(self.overview(page, 'kev-dt'), '3')
        self.assertIn('查詢期間 KEV · dateAdded', page)
        self.assertIn('相較上次新增：0', page)
        self.assertIn('0 不表示沒有既有 KEV', page)
        self.assertNotIn('本週清單', page)
        self.assertIn('2026-10-01T00:00:00+08:00 ～ 2026-10-19T09:00:00+08:00', page)

    def test_query_period_uses_shared_contract_not_calendar_week_or_render_time(self):
        self.vm['window_start'] = 'stale-window'
        self.vm['statistics']['periods']['calendar_week'] = {'start': '2026-10-19T00:00:00+08:00'}
        page = self.output()
        self.assertNotIn('stale-window', page)
        self.assertIn('查詢期間：2026-10-01T00:00:00+08:00', page)
        self.assertNotIn('newly-generated-report-id', ''.join(Header(page).contents))
        self.assertIn('來源擷取：2026-10-19T09:00:00+08:00', ''.join(Header(page).contents))

    def test_jira_card_identifies_workflow_scope_and_source_observation(self):
        page = self.output()
        self.assertEqual(self.overview(page, 'jira'), '4')
        self.assertIn('非 Done 工作流工單', page)
        self.assertIn('專案 SYNTHETIC', page)
        self.assertIn('來源選樣 all statuses including Done', page)
        self.assertIn('來源觀測：2026-10-19T08:58:00+08:00', page)
        self.assertIn('不是漏洞數或修復完成證明', page)

    def test_failure_keeps_unknown_and_complete_empty_can_show_zero(self):
        self.capture['sources']['kev'].update(status='PARTIAL', complete=False)
        self.vm['metrics']['kev_window'] = None
        page = self.output()
        self.assertEqual(self.overview(page, 'kev-dt'), 'Unknown')
        self.assertIn('相較上次新增：Unknown', page)
        self.capture['sources']['kev'].update(status='SUCCESS', complete=True)
        self.vm['metrics']['kev_window'] = 0
        self.assertEqual(self.overview(self.output(), 'kev-dt'), '0')

    def test_synthetic_snapshot_and_live_source_identity_are_distinct(self):
        for synthetic, mode, expected in (
            (True, 'snapshot-replay', '合成驗收資料・不得作日常現況'),
            (False, 'snapshot-replay', '真實來源快照・未重新取數'),
            (False, 'report-rebuild', '真實來源快照・未重新取數'),
            (False, 'live', '真實來源・依擷取時間判讀'),
            (None, 'snapshot-replay', '來源性質／取數方式待確認'),
        ):
            with self.subTest(synthetic=synthetic, mode=mode):
                self.capture['synthetic'], self.vm['mode'] = synthetic, mode
                page = self.output()
                header = Header(page)
                self.assertIn(expected, ''.join(header.contents))
                self.assertIn(expected, re.search(r'<title>(.*?)</title>', page).group(1))
                self.assertLess(page.index('id="psirt-data-context"'), page.index('<main>'))
                self.assertEqual(len(header.paragraphs), 2)
                self.assertEqual(header.paragraphs[-1]['id'], 'psirt-data-context')
                self.assertNotIn('OLD_SOURCE_TIME', page)

    def test_untrusted_scope_and_time_remain_escaped_text(self):
        self.capture['sources']['jira']['scope']['project'] = '<img src=x onerror=alert(1)>'
        self.capture['captured_at'] = '<script>unsafe()</script>'
        page = self.output()
        self.assertNotIn('<script>unsafe()', page)
        self.assertNotIn('<img src=x', page)
        self.assertIn('&lt;script&gt;unsafe()', page)
        self.assertIn('&lt;img src=x', page)

    def test_garden_and_compact_subpages_preserve_identity_assets_and_page_names(self):
        before = copy.deepcopy(self.capture)
        shell = garden(SHELL, self.vm, self.data, self.capture)
        comp = {name: compare(name, source, None) for name, source in self.capture['sources'].items()}
        review = {'schema': 'psirt-human-review/1', 'reviews': {}}
        sf = build_sf(self.capture, comp, review, 'fixture', 'snapshot-replay', '2026-10-27T00:00:00+08:00')
        with tempfile.TemporaryDirectory() as temp:
            manual = read_snapshot(Path(temp) / 'missing', True)
            cases = build_cases(self.capture, manual, review, '2026-10-27T00:00:00+08:00')
        for page, title in ((render_sf(shell, sf), 'SF 通報判讀'), (render_cases(shell, cases), '案件流程與時程')):
            page = brand(page)
            self.assertIn('psirt-work-page', page)
            self.assertIn('<title>' + title + '【合成驗收資料', page)
            self.assertIn('garden-illustration', page)
            self.assertIn('brand-avatar', page)
            self.assertIn('Product Security Workbench', page)
            self.assertIn('id="psirt-data-context"', page.split('<main>', 1)[0])
            self.assertEqual(len(Header(page).paragraphs), 2)
        self.assertEqual(before, self.capture)


if __name__ == '__main__':
    unittest.main()
