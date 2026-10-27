"""Isolated HTTP save -> pinned download -> rebuild -> coherent report checks."""
import hashlib
import http.client
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework.service import ROOT, start, stop
from psirt_mail_triage_fixtures import sample, review_request


class ReportVersionHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.base = Path(cls.temp.name); cls.root = cls.base / 'output'
        cls.source = cls.base / 'input.json'; cls.source.write_text(json.dumps(sample()))
        command = [sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'), '--mode', 'snapshot-replay', '--snapshot', str(cls.source), '--output-dir', str(cls.root)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0: raise AssertionError(result.stdout + result.stderr)
        cls.first = Path(json.loads(result.stdout)['run_dir']); cls.entry = start(cls.root)

    @classmethod
    def tearDownClass(cls):
        stop(cls.root); cls.temp.cleanup()

    def request(self, path, body=None, token=None):
        conn = http.client.HTTPConnection('127.0.0.1', int(self.entry['origin'].rsplit(':', 1)[1]), timeout=60)
        headers = {'Origin': self.entry['origin'], 'Content-Type': 'application/json'}
        if token: headers['X-PSIRT-Token'] = token
        conn.request('GET' if body is None else 'POST', path, json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse(); raw = response.read(); status = response.status
        content = json.loads(raw) if 'json' in (response.getheader('Content-Type') or '') else raw.decode()
        conn.close(); self.assertEqual(status, 200, content); return content

    def test_save_download_and_rebuild_keep_version_and_history(self):
        old_bytes = {p.name: p.read_bytes() for p in self.first.iterdir()}
        state = self.request('/api/sf-inbox'); meta = state['inbox']['report_version']
        self.assertEqual(meta['matches_report'], 'MATCH')
        row = next(r for r in state['inbox']['rows'] if r['source']['email_id'] == 'mail-question')
        change = review_request(row, 'report-version-save', state='done', answer_assessment='unanswered',
                                answer_note='Synthetic review confirms the technical question remains unanswered.',
                                outcome='Only reviewed; technical question remains', next_action='Ask for missing technical answer')
        saved = self.request('/api/records', change, state['session']); self.assertTrue(saved['committed_and_read_back'])
        updated = self.request('/api/sf-inbox')['inbox']; meta = updated['report_version']
        self.assertEqual(meta['matches_report'], 'CHANGED')
        self.assertEqual(meta['current_manual_sha256'], updated['manual_sha256'])
        case_meta = self.request('/api/state')['projection']['report_version']
        self.assertEqual(case_meta, meta)
        for page, artifact in [('casework.html', 'casework.json'), ('sf-triage.html', 'sf-triage.json')]:
            html = self.request('/' + page)
            self.assertIn('下載仍是最近已產生的固定報告', html)
            self.assertIn('/runs/' + self.first.name + '/' + artifact, html)
        old_download = self.request('/runs/' + self.first.name + '/sf-inbox.json')
        self.assertNotEqual(old_download['manual_sha256'], updated['manual_sha256'])
        session = self.request('/api/session')['session']
        rebuilt = self.request('/api/rebuild', {}, session)
        current = self.request('/api/sf-inbox')['inbox']; new_meta = current['report_version']
        self.assertEqual(new_meta['matches_report'], 'MATCH')
        self.assertNotEqual(new_meta['report_run_id'], self.first.name)
        newest = self.request('/runs/' + new_meta['report_run_id'] + '/sf-inbox.json')
        self.assertEqual(newest['manual_sha256'], current['manual_sha256'])
        self.assertEqual(newest['rows'], current['rows'])
        self.assertEqual(old_download, self.request('/runs/' + self.first.name + '/sf-inbox.json'))
        self.assertEqual(old_bytes, {p.name: p.read_bytes() for p in self.first.iterdir()})
        self.assertEqual((Path(rebuilt['run_dir']) / 'capture.json').read_bytes(), old_bytes['capture.json'])
        manifest = self.request('/runs/' + new_meta['report_run_id'] + '/manifest.json')
        for name in ('sf-inbox.json', 'casework.json', 'casework_manual_used.json'):
            self.assertEqual(hashlib.sha256((Path(rebuilt['run_dir']) / name).read_bytes()).hexdigest(), manifest['artifacts_sha256'][name])


if __name__ == '__main__': unittest.main()
