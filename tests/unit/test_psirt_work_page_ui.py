"""Offline HTML contracts for the two compact work pages; browser checks are separate."""
import base64
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from psirt_casework.inbox import build as build_inbox
from psirt_casework.inbox_web import section
from psirt_casework.projection import build as build_casework
from psirt_casework.refresh_web import enhance
from psirt_casework.store import read_snapshot
from psirt_casework.web import render as case_html
from psirt_casework.work_page import compact_shell
from psirt_ops.pipeline import compare
from psirt_ops.sf_triage import build as build_triage, render as sf_html
from psirt_mail_triage_fixtures import sample, failed

SHELL = '''<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>PSIRT 工作台</title></head><body class="antialiased"><aside class="sidebar">
<img class="brand-avatar" src="data:image/png;base64,ZmFrZQ==" alt="Vance">
<nav><a href="sf-triage.html">SF</a><a href="casework.html">案件</a></nav></aside>
<header class="page-head"><h1>Product Security Workbench</h1><p>既有來源時間</p>
<div class="garden-art"><img src="data:image/png;base64,ZmFrZQ==" alt="garden"></div></header>
<main>DO_NOT_COPY_HOME_PAYLOAD</main><div id="fixture-penguin">Penguin</div></body></html>'''
ASOF = '2026-10-26T10:00:00+08:00'


class Node:
    def __init__(self, tag, attrs=(), parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children, self.text = [], ''

    def ancestors(self):
        result, node = [], self.parent
        while node:
            result.append(node)
            node = node.parent
        return result


class Page(HTMLParser):
    VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.root = Node('root')
        self.stack, self.nodes, self.ids = [self.root], [], {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(node)
        self.nodes.append(node)
        if node.attrs.get('id'):
            if node.attrs['id'] in self.ids:
                raise AssertionError('Duplicate ID ' + node.attrs['id'])
            self.ids[node.attrs['id']] = node
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                self.stack = self.stack[:index]
                return

    def handle_data(self, data):
        self.stack[-1].text += data


class WorkPageUITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)
        self.manual = read_snapshot(self.output / 'casework', True)

    def sf(self, source=None):
        capture = source or sample()
        comparisons = {k: compare(k, v, None) for k, v in capture['sources'].items()}
        data = build_triage(capture, comparisons, {'schema': 'psirt-human-review/1', 'reviews': {}},
                            'fixture-ui', 'snapshot-replay', ASOF)
        data['inbox'] = build_inbox(self.output, capture, self.manual, comparisons['salesforce'], 'fixture-ui', ASOF)
        return data

    def cases(self):
        return build_casework(sample(), self.manual, {'schema': 'psirt-human-review/1', 'reviews': {}}, ASOF)

    def assert_hashed_scripts(self, page):
        policy = next(n.attrs['content'] for n in page.nodes if n.tag == 'meta' and n.attrs.get('http-equiv', '').lower() == 'content-security-policy')
        for script in (n for n in page.nodes if n.tag == 'script'):
            self.assertNotIn('src', script.attrs)
            digest = base64.b64encode(hashlib.sha256(script.text.encode()).digest()).decode()
            self.assertIn("'sha256-" + digest + "'", policy)

    def test_layout_scope_preserves_existing_header_assets_and_navigation(self):
        prefix = SHELL.split('<main>', 1)[0]
        page = Page(compact_shell(prefix))
        body = next(n for n in page.nodes if n.tag == 'body')
        self.assertEqual(body.attrs['class'].split(), ['psirt-work-page', 'antialiased'])
        self.assertEqual([n.attrs for n in page.nodes if n.tag == 'img'], [n.attrs for n in Page(prefix).nodes if n.tag == 'img'])
        self.assertEqual([n.attrs for n in page.nodes if n.tag == 'a'], [n.attrs for n in Page(prefix).nodes if n.tag == 'a'])
        self.assertNotIn('psirt-work-page', SHELL)

    def test_source_warning_and_currentness_are_outside_folded_raw_evidence(self):
        page = Page(section(True))
        for name in ('sfi-coverage', 'sfi-currentness', 'sfi-source-warning', 'sfi-retry-note', 'sfi-retry'):
            self.assertFalse(any(n.tag == 'details' for n in page.ids[name].ancestors()), name)
        for name in ('sfi-times', 'sfi-source-error'):
            self.assertIn(page.ids['sfi-source-evidence'], page.ids[name].ancestors())
        self.assertNotIn('open', page.ids['sfi-source-evidence'].attrs)

    def test_search_reset_and_live_only_operations_are_separate(self):
        for editable in (False, True):
            page = Page(section(editable))
            self.assertNotIn('disabled', page.ids['sfi-clear'].attrs)
            self.assertEqual('disabled' in page.ids['sfi-refresh'].attrs, not editable)
            self.assertEqual('disabled' in page.ids['sfi-rebuild'].attrs, not editable)
            self.assertEqual(page.ids['sfi-search'].attrs['type'], 'search')
            self.assertEqual(page.ids['sfi-results'].attrs['aria-live'], 'polite')

    def test_secondary_statistics_follow_work_list_without_hiding_source_alerts(self):
        page = Page(section(True))
        self.assertLess(page.nodes.index(page.ids['sfi-rows']), page.nodes.index(page.ids['sfi-counts']))
        fold = next(n for n in page.ids['sfi-counts'].ancestors() if n.tag == 'details')
        self.assertNotIn('open', fold.attrs)
        self.assertLess(page.nodes.index(page.ids['sfi-source-warning']), page.nodes.index(page.ids['sfi-search']))

    def test_source_variants_retain_exact_projection_and_hashed_safe_script(self):
        missing = sample()
        missing['sources']['salesforce'].pop('emails')
        for capture in (sample(), failed(sample()), missing):
            with self.subTest(status=capture['sources']['salesforce']['status'], emails='emails' in capture['sources']['salesforce']):
                data = self.sf(capture)
                before = copy.deepcopy(data)
                rendered = sf_html(SHELL, data, True)
                page = Page(rendered)
                self.assertEqual(json.loads(page.ids['sf-data'].text), before)
                self.assertEqual(data, before)
                self.assertNotIn('DO_NOT_COPY_HOME_PAYLOAD', rendered)
                self.assertNotIn('<script>window.mailExecuted=1</script>', rendered)
                self.assert_hashed_scripts(page)
                self.assertFalse(any(n.tag == 'details' for n in page.ids['report-version-state'].ancestors()))

    def test_case_editors_versions_and_source_flags_survive_compact_layout(self):
        data = self.cases()
        page = Page(case_html(SHELL, data, True))
        self.assertEqual(json.loads(page.ids['cw-data'].text), data)
        self.assertEqual({n.attrs['data-kind'] for n in page.nodes if n.tag == 'form'}, {'case', 'worklog', 'wait', 'delivery'})
        self.assertFalse(any(n.tag == 'details' for n in page.ids['cw-source-summary'].ancestors()))
        fold = next(n for n in page.ids['cw-dashboard'].ancestors() if n.tag == 'details')
        self.assertNotIn('open', fold.attrs)
        self.assertIn('cw-dashboard-fold', fold.attrs['class'])
        self.assertFalse(any(n.tag == 'details' for n in page.ids['report-version-state'].ancestors()))
        self.assertEqual(next(n for n in page.ids['cw-rows'].ancestors() if n.attrs.get('class') == 'cw-scroll').attrs['tabindex'], '0')
        self.assert_hashed_scripts(page)

    def test_refresh_toolbar_integration_keeps_scoping_and_all_script_hashes(self):
        for html in (sf_html(SHELL, self.sf(), True), case_html(SHELL, self.cases(), True)):
            page = Page(enhance(html, {'run_id': 'fixture-ui'}))
            self.assertIn('psirt-refresh-state', page.ids)
            self.assertIn('report-version-state', page.ids)
            self.assert_hashed_scripts(page)
            body = next(n for n in page.nodes if n.tag == 'body')
            self.assertIn('psirt-work-page', body.attrs['class'])
            self.assertFalse(any(k.lower().startswith('on') for n in page.nodes for k in n.attrs))

    def test_case_frozen_report_keeps_readonly_notice_visible(self):
        page = Page(case_html(SHELL, self.cases(), False))
        mode = next(n for n in page.nodes if n.attrs.get('class') == 'work-mode')
        self.assertIn('唯讀', mode.text)
        self.assertFalse(any(n.tag == 'details' for n in mode.ancestors()))
        self.assertIn('disabled', page.ids['cw-refresh'].attrs)


if __name__ == '__main__':
    unittest.main()
