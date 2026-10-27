"""Refresh HTTP contract on isolated synthetic roots; collector is always replaced.

The fake collector publishes only local snapshot-replay fixtures. No live mode,
company API, credential resolution, or system scheduler is used by this suite.
"""
import concurrent.futures
import copy
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework.refresh import Manager, SOURCES
from psirt_casework.service import Server
from psirt_sf_fixtures import sample


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class RefreshHTTP(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'output'
        self.capture = sample()
        self.capture['sources']['salesforce']['scope']['instance'] = 'https://sf.synthetic.invalid'
        self.capture['sources']['jira']['scope']['instance'] = 'https://jira.synthetic.invalid'
        self.replay(self.capture)
        self.original = Path(json.loads((self.root / 'state.json').read_text())['latest_run'])
        self.original_hashes = self.hashes(self.original)
        self.clock = Clock()
        self.calls = []
        self.job_started = threading.Event()
        self.job_release = threading.Event()
        self.job_release.set()
        self.outcome = 0
        self.real_collector = patch('psirt_casework.refresh.run_job', side_effect=AssertionError('Live collector forbidden'))
        self.real_collector.start()
        self.addCleanup(self.real_collector.stop)
        self.start_server()

    def tearDown(self):
        self.job_release.set()
        self.finish_job()
        self.stop_server()
        self.assertEqual(self.hashes(self.original), self.original_hashes)
        self.temp.cleanup()

    @staticmethod
    def hashes(directory):
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in directory.iterdir() if path.is_file()}

    def replay(self, capture):
        source = self.base / 'synthetic-input.json'
        source.write_text(json.dumps(capture))
        result = subprocess.run([
            sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
            '--mode', 'snapshot-replay', '--snapshot', str(source),
            '--output-dir', str(self.root)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        return json.loads(result.stdout)

    def runner(self, root, progress):
        self.calls.append(root)
        progress('kev', 'SUCCESS')
        progress('salesforce', 'RUNNING')
        self.job_started.set()
        if not self.job_release.wait(10):
            raise TimeoutError('Synthetic test release missing')
        if self.outcome == 'exception':
            raise RuntimeError('SYNTHETIC_PRIVATE_EXCEPTION_MUST_NOT_LEAK')
        if self.outcome in (2, 75):
            return {'exit_code': self.outcome}
        source = copy.deepcopy(self.capture)
        if self.outcome == 1:
            source['sources']['salesforce'].update(status='PARTIAL', complete=False)
        result = self.replay(source)
        return {'exit_code': self.outcome, 'run_id': Path(result['run_dir']).name,
                'mode': 'report-rebuild',
                'statuses': {name: source['sources'][name]['status'] for name in SOURCES}}

    def start_server(self):
        self.server = Server(self.root)
        self.server.refresh = Manager(self.root, runner=self.runner, clock=self.clock)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()

    def stop_server(self):
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(3)
        self.server.server_close()
        self.assertFalse(self.thread.is_alive())

    def finish_job(self):
        worker = self.server.refresh.thread
        if worker:
            worker.join(20)
            self.assertFalse(worker.is_alive(), 'Synthetic refresh worker did not finish')

    def request(self, path='/api/refresh', body=None, token=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=30)
        request_headers = {'Origin': self.server.origin, 'Content-Type': 'application/json'}
        if token:
            request_headers['X-PSIRT-Token'] = token
        request_headers.update(headers or {})
        connection.request('GET' if body is None else 'POST', path,
                           body=json.dumps(body) if body is not None else None,
                           headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        result = json.loads(raw) if 'json' in (response.getheader('Content-Type') or '') else raw.decode()
        status = response.status
        connection.close()
        return status, result

    def state(self):
        status, body = self.request()
        self.assertEqual(status, 200, body)
        return body

    def action(self, action, **extra):
        token = self.state()['session']
        status, body = self.request(body={'action': action, **extra}, token=token)
        self.assertEqual(status, 200, body)
        return body

    def test_get_session_and_refresh_are_readonly_and_do_not_collect(self):
        before = (self.root / 'state.json').read_bytes()
        self.assertEqual(self.request('/api/session')[0], 200)
        for _ in range(3):
            state = self.state()
            self.assertEqual(state['refresh']['phase'], 'IDLE')
            self.assertEqual(state['refresh']['interval_seconds'], 900)
            self.assertIsNone(state['refresh']['seconds_until_next'])
            self.assertEqual(state['latest']['run_id'], self.original.name)
        self.assertEqual(self.calls, [])
        self.assertEqual((self.root / 'state.json').read_bytes(), before)
        self.assertFalse((self.root / 'casework/worklog.sqlite3').exists())
        self.assertFalse((self.root / 'refresh-settings.json').exists())

    def test_tabs_share_deadline_and_running_job_without_duplicate_collection(self):
        self.job_release.clear()
        first = self.action('tick')
        self.assertEqual(first['refresh']['seconds_until_next'], 900)
        self.clock.value += 899
        for _ in range(4):
            self.assertEqual(self.action('tick')['refresh']['seconds_until_next'], 1)
        self.assertEqual(self.calls, [])
        self.clock.value += 1
        launched = self.action('tick')['refresh']
        self.assertEqual(launched['phase'], 'RUNNING')
        self.assertTrue(self.job_started.wait(2))
        token = self.state()['session']
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda action: self.request(body={'action': action}, token=token),
                                    ['manual', 'tick', 'manual', 'tick', 'manual', 'tick']))
        for status, body in results:
            self.assertIn(status, (200, 409), body)
            if status == 200:
                self.assertEqual(body['refresh']['job_id'], launched['job_id'])
        for _ in range(3):
            page = self.state()['refresh']
            self.assertEqual(page['job_id'], launched['job_id'])
            self.assertEqual(page['progress']['salesforce'], 'RUNNING')
        self.assertEqual(len(self.calls), 1)
        self.job_release.set()
        self.finish_job()
        final = self.state()
        self.assertEqual(final['refresh']['phase'], 'SUCCESS')
        self.assertEqual(final['refresh']['seconds_until_next'], 900)
        self.assertNotEqual(final['latest']['run_id'], self.original.name)
        self.assertEqual(final['latest']['run_id'], final['refresh']['result']['run_id'])

    def test_auto_toggle_survives_service_restart_and_manual_still_works(self):
        self.assertFalse(self.action('auto', enabled=False)['refresh']['auto_enabled'])
        self.stop_server()
        self.start_server()
        self.assertFalse(self.state()['refresh']['auto_enabled'])
        self.clock.value += 9000
        self.assertEqual(self.action('tick')['refresh']['phase'], 'IDLE')
        self.assertEqual(self.calls, [])
        self.action('manual')
        self.finish_job()
        self.assertEqual(self.state()['refresh']['phase'], 'SUCCESS')
        self.assertIsNone(self.state()['refresh']['seconds_until_next'])
        enabled = self.action('auto', enabled=True)['refresh']
        self.assertTrue(enabled['auto_enabled'])
        self.assertEqual(enabled['seconds_until_next'], 900)
        self.assertTrue(json.loads((self.root / 'refresh-settings.json').read_text())['auto_enabled'])

    def test_partial_is_not_success_and_has_current_partial_report(self):
        self.outcome = 1
        self.action('manual')
        self.finish_job()
        state = self.state()
        self.assertEqual(state['refresh']['phase'], 'PARTIAL')
        self.assertEqual(state['refresh']['result']['statuses']['salesforce'], 'PARTIAL')
        self.assertEqual(state['latest']['sources']['salesforce']['status'], 'PARTIAL')
        self.assertEqual(state['latest']['run_id'], state['refresh']['result']['run_id'])
        self.assertNotEqual(state['latest']['run_id'], self.original.name)

    def test_failed_and_busy_attempts_do_not_promote_old_report_as_new_success(self):
        for outcome, phase in [(2, 'FAILED'), (75, 'BUSY'), ('exception', 'FAILED')]:
            with self.subTest(outcome=outcome):
                self.outcome = outcome
                self.action('manual')
                self.finish_job()
                state = self.state()
                self.assertEqual(state['refresh']['phase'], phase)
                self.assertIsNone(state['refresh']['result'])
                self.assertEqual(state['latest']['run_id'], self.original.name)
                self.assertNotIn('SYNTHETIC_PRIVATE_EXCEPTION', json.dumps(state))

    def test_control_stop_refuses_running_job_then_stops_after_completion(self):
        self.job_release.clear()
        self.action('manual')
        self.assertTrue(self.job_started.wait(2))
        headers = {'X-PSIRT-Control': self.server.receipt['control']}
        status, body = self.request('/control/stop', body={}, headers=headers)
        self.assertEqual(status, 409, body)
        self.assertFalse(self.server.closing)
        self.assertEqual(self.state()['refresh']['phase'], 'RUNNING')
        self.job_release.set()
        self.finish_job()
        status, body = self.request('/control/stop', body={}, headers=headers)
        self.assertEqual(status, 200, body)
        self.assertTrue(body['stopping'])
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())
        self.assertTrue(self.server.refresh.status()['closed'])

    def test_refresh_mutations_require_token_origin_and_exact_fields(self):
        token = self.state()['session']
        self.assertEqual(self.request(body={'action': 'manual'})[0], 403)
        self.assertEqual(self.request(body={'action': 'manual'}, token=token,
                                      headers={'Origin': 'https://cross-origin.invalid'})[0], 403)
        for body in ({'action': 'auto', 'enabled': 1}, {'action': 'auto'},
                     {'action': 'manual', 'scope': 'all-company'}, {'action': 'invented'}, {}):
            self.assertEqual(self.request(body=body, token=token)[0], 400)
        self.server.tokens[token] = 0
        self.assertEqual(self.request(body={'action': 'tick'}, token=token)[0], 403)
        status, renewed = self.request('/api/session')
        self.assertEqual(status, 200)
        self.assertEqual(self.request(body={'action': 'tick'}, token=renewed['session'])[0], 200)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.root / 'refresh-settings.json').exists())

    def test_toolbar_only_on_active_pages_and_frozen_history_bytes_do_not_change(self):
        for name in ('index.html', 'dt-statistics.html', 'casework.html', 'sf-triage.html', 'resources.html'):
            with self.subTest(name=name):
                status, page = self.request('/' + name)
                self.assertEqual(status, 200, name)
                self.assertEqual(page.count('id="psirt-refresh"'), 1)
                self.assertIn('開頁期間每 15 分鐘更新', page)
                status, frozen = self.request('/runs/' + self.original.name + '/' + name)
                self.assertEqual(status, 200)
                self.assertNotIn('id="psirt-refresh"', frozen)
                self.assertEqual(frozen, (self.original / name).read_text())
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
