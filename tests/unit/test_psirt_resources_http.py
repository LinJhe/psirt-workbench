"""Loopback-only link editing with isolated synthetic reports and local stores."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from psirt_casework.service import ROOT, start, stop
from psirt_casework.store import read_snapshot
from psirt_sf_fixtures import sample


class ResourcesHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        cls.root = cls.base / 'output'
        cls.capture = sample()
        cls.capture['sources']['salesforce']['scope']['instance'] = 'https://sf.synthetic.invalid'
        cls.capture['sources']['jira']['scope']['instance'] = 'https://jira.synthetic.invalid'
        cls.run_capture()
        cls.entry = start(cls.root)

    @classmethod
    def tearDownClass(cls):
        stop(cls.root)
        cls.temp.cleanup()

    @classmethod
    def run_capture(cls):
        snapshot = cls.base / 'input.json'
        snapshot.write_text(json.dumps(cls.capture))
        result = subprocess.run([
            sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
            '--mode', 'snapshot-replay', '--snapshot', str(snapshot),
            '--output-dir', str(cls.root)], capture_output=True, text=True)
        if result.returncode not in (0, 1):
            raise AssertionError(result.stdout + result.stderr)
        return json.loads(result.stdout)

    def request(self, path, body=None, token=None, headers=None):
        connection = http.client.HTTPConnection(
            '127.0.0.1', int(self.entry['origin'].rsplit(':', 1)[1]), timeout=30)
        request_headers = {'Origin': self.entry['origin'], 'Content-Type': 'application/json'}
        if token:
            request_headers['X-PSIRT-Token'] = token
        request_headers.update(headers or {})
        connection.request('GET' if body is None else 'POST', path,
                           body=json.dumps(body) if body is not None else None,
                           headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        value = json.loads(raw) if 'json' in (response.getheader('Content-Type') or '') else raw.decode()
        status = response.status
        connection.close()
        return status, value

    def state(self):
        status, result = self.request('/api/resources')
        self.assertEqual(status, 200, result)
        return result

    def row(self, state=None):
        data = (state or self.state())['resources']
        return next(row for row in data['rows'] if row['id'] == 'http-test-link')

    @staticmethod
    def payload():
        return {'title': 'Synthetic meeting notes',
                'url': 'https://example.invalid/team?view=all',
                'category': 'documents', 'status': 'active',
                'note': 'Synthetic link; do not contact this URL', 'reviewer': 'DEMO reviewer'}

    def test_01_get_is_readonly_and_ui_uses_existing_entry(self):
        self.assertFalse((self.root / 'casework/worklog.sqlite3').exists())
        state = self.state()
        self.assertEqual(state['resources']['schema'], 'psirt-resources/1')
        self.assertTrue(state['resources']['synthetic'])
        status, page = self.request('/resources.html')
        self.assertEqual(status, 200)
        self.assertIn('data-editable="true"', page)
        self.assertIn('重要網址', page)
        for path in ('/casework.html', '/sf-triage.html'):
            status, page = self.request(path)
            self.assertEqual(status, 200)
            self.assertIn('href="resources.html"', page)
        self.assertFalse((self.root / 'casework/worklog.sqlite3').exists())

    def test_02_save_readback_idempotence_conflict_and_restart(self):
        state = self.state()
        request = {'kind': 'bookmark', 'id': 'http-test-link', 'payload': self.payload(),
                   'expected_version': 0, 'operation_id': 'http-bookmark-create'}
        status, saved = self.request('/api/records', request, state['session'])
        self.assertEqual(status, 200, saved)
        self.assertTrue(saved['committed_and_read_back'])
        self.assertEqual(self.row()['payload'], request['payload'])
        self.assertEqual(self.request('/api/records', request, state['session'])[1]['record'], saved['record'])
        stale = copy.deepcopy(request)
        stale['operation_id'] = 'http-bookmark-stale'
        stale['payload'].update(title='Must not overwrite', correction_reason='Stale browser tab')
        self.assertEqual(self.request('/api/records', stale, state['session'])[0], 409)
        snapshot = read_snapshot(self.root / 'casework', True)
        stop(self.root)
        type(self).entry = start(self.root)
        self.assertEqual(read_snapshot(self.root / 'casework', True), snapshot)
        self.assertEqual(self.row()['version'], 1)
        self.assertEqual(self.row()['payload']['title'], 'Synthetic meeting notes')

    def test_03_archive_restore_and_replay_do_not_duplicate_or_lose_saved_links(self):
        for target, version in [('archived', 1), ('active', 2)]:
            state = self.state()
            request = {'kind': 'bookmark', 'id': 'http-test-link',
                       'payload': {**self.payload(), 'status': target, 'correction_reason': 'Synthetic ' + target},
                       'expected_version': version, 'operation_id': 'http-bookmark-' + target}
            status, saved = self.request('/api/records', request, state['session'])
            self.assertEqual(status, 200, saved)
            self.assertEqual(self.row()['payload']['status'], target)
        manual = read_snapshot(self.root / 'casework', True)
        self.run_capture()
        self.run_capture()
        self.assertEqual(read_snapshot(self.root / 'casework', True), manual)
        row = self.row()
        self.assertEqual(row['version'], 3)
        self.assertEqual(len(row['revisions']), 3)
        self.assertEqual(sum(r['id'] == 'http-test-link' for r in self.state()['resources']['rows']), 1)

    def test_04_rebuild_keeps_old_report_bytes_and_html_matches_json(self):
        old = Path(json.loads((self.root / 'state.json').read_text())['latest_run'])
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in old.iterdir()}
        state = self.state()
        manual = read_snapshot(self.root / 'casework', True)
        status, result = self.request('/api/rebuild', {}, state['session'])
        self.assertEqual(status, 200, result)
        run = Path(result['run_dir'])
        data = json.loads((run / 'resources.json').read_text())
        self.assertEqual(data['rows'], state['resources']['rows'])
        self.assertEqual(data['manual_sha256'], state['resources']['manual_sha256'])
        self.assertEqual(data['source_at'], state['resources']['source_at'])
        status, page = self.request('/runs/' + run.name + '/resources.html')
        self.assertEqual(status, 200)
        self.assertIn('data-editable="false"', page)
        import html
        import re
        embedded = re.search(r'<pre id="res-data" hidden>(.*?)</pre>', page, re.S).group(1)
        self.assertEqual(json.loads(html.unescape(embedded)), data)
        self.assertEqual(hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in old.iterdir()})
        self.assertEqual(read_snapshot(self.root / 'casework', True), manual)

    def test_05_rejects_unsafe_urls_missing_token_and_cross_origin_without_committing(self):
        state = self.state()
        before = read_snapshot(self.root / 'casework', True)
        request = {'kind': 'bookmark', 'id': 'rejected-link', 'payload': self.payload(),
                   'expected_version': 0, 'operation_id': 'http-bookmark-rejected'}
        self.assertEqual(self.request('/api/records', request)[0], 403)
        self.assertEqual(self.request('/api/records', request, state['session'], {'Origin': 'https://other.invalid'})[0], 403)
        for url in ('javascript:alert(1)', 'https://u:p@example.invalid/', 'https://example.invalid/?access_token=synthetic'):
            request['payload']['url'] = url
            status, result = self.request('/api/records', request, state['session'])
            self.assertEqual(status, 400, result)
            self.assertFalse(result.get('committed', False))
        self.assertEqual(read_snapshot(self.root / 'casework', True), before)


if __name__ == '__main__':
    unittest.main()
