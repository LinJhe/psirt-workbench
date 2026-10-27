"""Synthetic projection/render and offline report integration; no company API."""
import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework.projection import build as project
from psirt_casework.store import Store
from psirt_casework.web import render
from psirt_dt_fixtures import sample as dt_sample

ASOF = '2026-10-22T12:00:00+08:00'
LEGACY = {'schema': 'psirt-human-review/1', 'reviews': {}}
SHELL = '''<!DOCTYPE html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Product Security Workbench · DEMO</title></head><body><aside class="sidebar"><a href="casework.html">案件</a></aside><main></main></body></html>'''


def capture():
    data = dt_sample()
    data['captured_at'] = ASOF
    data['config']['cutoff'] = ASOF
    data['sources']['jira']['observed_at'] = ASOF
    data['sources']['jira']['raw'] = [
        {'id': key, 'key': key, 'fields': {'summary': 'Synthetic ' + key,
         'status': {'name': 'Closed' if done else 'In Progress',
                    'statusCategory': {'key': 'done' if done else 'indeterminate'}},
         'assignee': {'displayName': 'DEMO assignee'}, 'created': '2026-10-20T09:00:00+08:00', 'updated': ASOF}}
        for key, done in [('DEMO-101', False), ('DEMO-102', False), ('DEMO-103', True), ('DEMO-999', True)]]
    return data


def save_manual(store):
    old = {'case_id': 'DEMO-101', 'stage': 'analysis', 'stage_confirmation': 'confirmed',
           'entered_at': '2026-10-20T09:00:00+08:00', 'exited_at': '2026-10-20T11:00:00+08:00',
           'entry_evidence': 'fixture://entry', 'exit_evidence': 'fixture://exit', 'evidence': 'fixture://review',
           'reviewer': 'DEMO reviewer', 'owner_kind': 'unknown', 'acceptance': 'pending',
           'record_confirmation': 'confirmed', 'blocker': '無', 'dates': {}}
    store.save('case', 'DEMO-101', old, 0, 'case-first-visit')
    current = {**old, 'entered_at': '2026-10-21T09:00:00+08:00', 'exited_at': '', 'exit_evidence': '',
               'stage_event': 'reenter', 'correction_reason': 'Synthetic second visit',
               'dates': {'commitment': {'at': '2026-10-21T10:00:00+08:00', 'confirmation': 'confirmed',
                                       'evidence': 'fixture://commitment', 'confirmed_by': 'DEMO reviewer'}}}
    store.save('case', 'DEMO-101', current, 1, 'case-second-visit')
    store.save('case', 'DEMO-103', {**old, 'case_id': 'DEMO-103', 'stage': 'closure',
                                   'exited_at': '', 'exit_evidence': ''}, 0, 'tracked-jira-done')
    work = {'case_ids': ['DEMO-101', 'DEMO-103'], 'task': 'Synthetic shared verification',
            'work_date': '2026-10-21', 'minutes': 45, 'category': 'verification', 'measurement': 'measured',
            'outcome': 'Synthetic scope checked', 'evidence': 'fixture://work', 'recording_mode': 'backfill'}
    store.save('worklog', 'shared-work', work, 0, 'shared-work-op')
    store.save('worklog', 'general-work', {**work, 'case_ids': [], 'minutes': 15,
                                         'task': 'Synthetic general task'}, 0, 'general-work-op')
    store.save('wait', 'open-wait', {'case_id': 'DEMO-101', 'stage': 'analysis',
               'start': '2026-10-21T09:00:00+08:00', 'waiting_for': 'DEMO RD', 'deliverable': 'DEMO version',
               'reason': 'Synthetic open wait', 'evidence': 'fixture://wait'}, 0, 'open-wait-operation')
    store.save('delivery', 'shared-delivery', {'case_ids': ['DEMO-101', 'DEMO-103'],
               'title': 'Synthetic shared report', 'received_at': '2026-10-20T10:00:00+08:00',
               'outcome': 'Report accepted; no remediation conclusion', 'evidence': 'fixture://report',
               'reviewer': 'DEMO reviewer', 'acceptance': 'accepted',
               'accepted_at': '2026-10-21T10:00:00+08:00', 'acceptance_evidence': 'fixture://accept'}, 0, 'delivery-op')


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.capture = False
        self.payload = []
        self.ids = []
        self.forms = []
        self.fieldsets = []
        self.policies = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.append(attrs['id'])
        if tag == 'pre' and attrs.get('id') == 'cw-data':
            self.capture = True
        if tag == 'form':
            self.forms.append(attrs.get('data-kind'))
        if tag == 'fieldset':
            self.fieldsets.append('disabled' in attrs)
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'content-security-policy':
            self.policies.append(attrs.get('content', ''))

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.capture = False

    def handle_data(self, data):
        if self.capture:
            self.payload.append(data)

    @property
    def data(self):
        return json.loads(''.join(self.payload))


class DashboardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def assert_dashboard(self, data, complete=True):
        dashboard = data['dashboard']
        self.assertEqual(dashboard['schema'], 'case-dashboard/1')
        self.assertEqual(dashboard['scope']['complete'], complete)
        self.assertEqual(dashboard['metrics']['total']['observed_count'], 3)
        self.assertEqual(dashboard['metrics']['jira_done']['case_ids'], ['DEMO-103'])
        self.assertNotIn('DEMO-999', dashboard['cases'])
        self.assertEqual(dashboard['work']['actual_minutes'], 60)
        self.assertEqual(dashboard['work']['record_count'], 2)
        self.assertEqual(dashboard['deliveries']['received'], 1)
        self.assertEqual(dashboard['deliveries']['accepted'], 1)
        node = next(node for node in dashboard['cases']['DEMO-101']['timeline'] if node['key'] == 'analysis')
        self.assertEqual(node['state'], 'current')
        self.assertEqual(len(node['visits']), 2)
        self.assertIn('重新進入', node['note'])
        if complete:
            self.assertEqual(dashboard['metrics']['total']['value'], 3)
            self.assertEqual(dashboard['metrics']['overdue']['case_ids'], ['DEMO-101'])
        else:
            self.assertTrue(all(metric['value'] is None for metric in dashboard['metrics'].values()))

    def assert_page(self, html, data, editable):
        page = Page(html)
        self.assertEqual(page.data, data)
        self.assertEqual(page.data['dashboard'], data['dashboard'])
        self.assertCountEqual(page.forms, ['case', 'worklog', 'wait', 'delivery'])
        self.assertEqual(page.fieldsets, [not editable] * 4)
        self.assertEqual(page.ids.count('cw-data'), 1)
        self.assertEqual(page.ids.count('cw-rows'), 1)
        self.assertEqual(page.ids.count('cw-detail'), 1)
        self.assertTrue(any('dashboard' in id_ for id_ in page.ids), 'Dashboard mount missing from actual rendered page')
        for policy in page.policies:
            directives = {}
            for directive in policy.split(';'):
                values = directive.split()
                if values:
                    directives.setdefault(values[0], values[1:])
            allowed = directives.get('script-src', directives.get('default-src', []))
            for script in re.findall(r'<script\b[^>]*>(.*?)</script>', html, flags=re.S):
                digest = "'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"
                self.assertIn(digest, allowed, 'Rendered inline script is not allowed by the first CSP directive')

    def test_projection_and_editable_historical_html_share_dashboard_without_mutation(self):
        store = Store(self.base / 'casework', synthetic=True)
        save_manual(store)
        source, manual, legacy = capture(), store.snapshot(), copy.deepcopy(LEGACY)
        originals = copy.deepcopy((source, manual, legacy))
        data = project(source, manual, legacy, ASOF, run_id='DEMO-dashboard-run')
        self.assert_dashboard(data)
        self.assertEqual(next(row for row in data['cases'] if row['id'] == 'DEMO-103')['jira_status_category'], 'done')
        for editable in (False, True):
            with self.subTest(editable=editable):
                self.assert_page(render(SHELL, data, editable=editable), data, editable)
        self.assertEqual(data, project(source, manual, legacy, ASOF, run_id='DEMO-dashboard-run'))
        self.assertEqual((source, manual, legacy), originals)
        self.assertEqual(store.snapshot(), manual)

    def test_partial_and_failed_fallback_keep_unknown_totals_and_visible_manual_work(self):
        store = Store(self.base / 'casework', synthetic=True)
        save_manual(store)
        manual = store.snapshot()
        for status in ('PARTIAL', 'FAILED'):
            with self.subTest(status=status):
                source = capture()
                fallback = copy.deepcopy(source['sources']['jira'])
                source['sources']['jira'].update(status=status, complete=False,
                    raw=None if status == 'FAILED' else source['sources']['jira']['raw'][:2])
                before = copy.deepcopy((source, manual, fallback))
                data = project(source, manual, LEGACY, ASOF, fallback=fallback, run_id='DEMO-incomplete-run')
                self.assertIsNone(data['dashboard']['metrics']['total']['value'])
                self.assertTrue(all(item['value'] is None for item in data['dashboard']['metrics'].values()))
                self.assertEqual(data['dashboard']['metrics']['total']['observed_count'], 3)
                self.assertEqual(data['dashboard']['work']['actual_minutes'], 60)
                self.assertEqual(data['dashboard']['deliveries']['received'], 1)
                if status == 'FAILED':
                    self.assert_dashboard(data, complete=False)
                    self.assertTrue(data['dashboard']['scope']['historical'])
                self.assert_page(render(SHELL, data), data, False)
                self.assertEqual((source, manual, fallback), before)
        self.assertEqual(store.snapshot(), manual)

    def test_future_entry_has_consistent_unknown_row_stage_distribution_and_dashboard(self):
        store = Store(self.base / 'casework', synthetic=True)
        save_manual(store)
        future = {'case_id': 'DEMO-102', 'stage': 'verification', 'stage_confirmation': 'confirmed',
                  'entered_at': '2026-10-23T09:00:00+08:00', 'entry_evidence': 'fixture://future-entry',
                  'evidence': 'fixture://stage-review', 'reviewer': 'DEMO reviewer',
                  'owner_kind': 'unknown', 'acceptance': 'pending', 'dates': {}}
        store.save('case', 'DEMO-102', future, 0, 'future-entry-operation')
        # An unknown entry time is different from a known future entry. Preserve
        # the existing confirmed-stage behavior without inventing elapsed time.
        store.save('case', 'DEMO-104', {**future, 'case_id': 'DEMO-104', 'stage': 'analysis',
                   'entered_at': '', 'entry_evidence': ''}, 0, 'unknown-entry-time-operation')
        manual, source = store.snapshot(), capture()
        original = copy.deepcopy((manual, source))
        data = project(source, manual, LEGACY, ASOF, run_id='DEMO-future-entry')
        rows = {row['id']: row for row in data['cases']}
        dashboard = data['dashboard']
        self.assertEqual(rows['DEMO-102']['stage'], 'unknown')
        self.assertIsNone(rows['DEMO-102']['elapsed_minutes'])
        self.assertEqual(dashboard['cases']['DEMO-102']['stage'], 'unknown')
        self.assertTrue(all(node['state'] == 'unknown' for node in dashboard['cases']['DEMO-102']['timeline']))
        self.assertEqual(rows['DEMO-104']['stage'], 'analysis')
        self.assertIsNone(rows['DEMO-104']['elapsed_minutes'])
        self.assertEqual(dashboard['cases']['DEMO-104']['stage'], 'analysis')
        self.assertEqual(dashboard['metrics']['stage_unknown']['case_ids'], ['DEMO-102'])
        for stage in dashboard['stages']:
            self.assertEqual(stage['case_ids'], data['stages'][stage['key']]['case_ids'])
            self.assertEqual(stage['count'], data['stages'][stage['key']]['count'])
            self.assertEqual(stage['observed_count'], data['stages'][stage['key']]['observed_count'])
        self.assert_page(render(SHELL, data, editable=True), data, True)
        self.assertEqual((manual, source), original)
        self.assertEqual(store.snapshot(), manual)

    def cli(self, root, mode, snapshot=None):
        command = [sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'), '--mode', mode,
                   '--output-dir', str(root)]
        if snapshot is not None:
            command += ['--snapshot', str(snapshot)]
        process = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertIn(process.returncode, (0, 1), process.stderr.decode())
        return Path(json.loads(process.stdout)['run_dir'])

    def test_real_offline_rebuild_preserves_input_manual_history_and_frozen_reports(self):
        source, root = self.base / 'capture.json', self.base / 'output'
        source.write_text(json.dumps(capture()))
        input_bytes = source.read_bytes()
        seed = self.cli(root, 'snapshot-replay', source)
        old_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in seed.iterdir()}
        store = Store(root / 'casework', synthetic=True)
        save_manual(store)
        manual = store.snapshot()
        legacy_bytes = (root / 'human_review.json').read_bytes()
        db_hash = hashlib.sha256(store.path.read_bytes()).hexdigest()
        first = self.cli(root, 'report-rebuild')
        data = json.loads((first / 'casework.json').read_text())
        self.assert_dashboard(data)
        self.assert_page((first / 'casework.html').read_text(), data, False)
        first_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in first.iterdir()}
        second = self.cli(root, 'report-rebuild')
        next_data = json.loads((second / 'casework.json').read_text())
        self.assert_dashboard(next_data)
        self.assert_page((second / 'casework.html').read_text(), next_data, False)
        self.assertNotEqual(first, second)
        self.assertEqual(input_bytes, source.read_bytes())
        self.assertEqual(manual, store.snapshot())
        self.assertEqual(db_hash, hashlib.sha256(store.path.read_bytes()).hexdigest())
        self.assertEqual(legacy_bytes, (root / 'human_review.json').read_bytes())
        self.assertEqual(old_hashes, {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in seed.iterdir()})
        self.assertEqual(first_hashes, {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in first.iterdir()})
        self.assertEqual((first / 'capture.json').read_bytes(), (second / 'capture.json').read_bytes())
        self.assertEqual((first / 'casework_manual_used.json').read_bytes(), (second / 'casework_manual_used.json').read_bytes())
        self.assertEqual(data['dashboard']['metrics'], next_data['dashboard']['metrics'])
        for run in (first, second):
            manifest = json.loads((run / 'manifest.json').read_text())
            for name in ('casework.json', 'casework.html', 'casework_manual_used.json'):
                self.assertEqual(hashlib.sha256((run / name).read_bytes()).hexdigest(), manifest['artifacts_sha256'][name])


if __name__ == '__main__':
    unittest.main()
