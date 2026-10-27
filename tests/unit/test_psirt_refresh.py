"""Isolated refresh scheduling and verified CLI receipts; never live collection."""
import copy
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework import refresh
from psirt_casework.refresh import Manager, RefreshError, run_job
from psirt_casework.store import Conflict, Invalid
from psirt_daily.pipeline import encoded, read_json, sha
from psirt_sf_fixtures import sample


class Clock:
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


def successful(code=0):
    return {'exit_code': code, 'run_id': 'synthetic-new-run', 'mode': 'report-rebuild',
            'statuses': {name: 'PARTIAL' if code == 1 and name == 'salesforce' else 'SUCCESS'
                         for name in refresh.SOURCES}}


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker('snapshot-replay')
        self.clock = Clock()
        self.managers = []

    def tearDown(self):
        for manager in self.managers:
            if manager.thread:
                manager.thread.join(3)

    def marker(self, mode):
        (self.root / '.psirt-ops').write_bytes(encoded({'schema': 'psirt-ops/1', 'mode': mode}))

    def manager(self, runner):
        manager = Manager(self.root, runner=runner, clock=self.clock)
        self.managers.append(manager)
        return manager

    def finish(self, manager):
        manager.thread.join(3)
        self.assertFalse(manager.thread.is_alive())
        return manager.status()

    def publish(self, run_id, *, mode='report-rebuild', synthetic=True, code=0, started=None, changed_scope=False):
        at = started or datetime.now(timezone.utc).isoformat()
        capture = sample()
        capture['synthetic'] = synthetic
        capture['config']['cutoff'] = at if mode == 'live' else capture['config']['cutoff']
        if changed_scope:
            capture['config']['dt_projects'] = ['00000000-0000-0000-0000-000000000099']
        if code == 1:
            capture['sources']['salesforce'].update(status='PARTIAL', complete=False)
        run = self.root / 'runs' / run_id
        run.mkdir(parents=True)
        presentation = {'schema': 'psirt-weekly-presentation/1', 'meetings': {}, 'overrides': []}
        artifacts = {'capture.json': encoded(capture), 'index.html': b'<html>synthetic report</html>',
                     'report_presentation_used.json': encoded(presentation)}
        for name, raw in artifacts.items():
            (run / name).write_bytes(raw)
        manifest = {'schema': 'psirt-ops-manifest/1', 'run_id': run_id, 'mode': mode,
                    'synthetic': synthetic, 'started_at': at, 'completed_at': at,
                    'sources': {name: {'status': capture['sources'][name]['status'],
                                       'complete': capture['sources'][name]['complete']}
                                for name in refresh.SOURCES},
                    'artifacts_sha256': {name: sha(raw) for name, raw in artifacts.items()}}
        raw = encoded(manifest)
        (run / 'manifest.json').write_bytes(raw)
        (self.root / 'state.json').write_bytes(encoded({
            'latest_run': str(run), 'manifest_sha256': sha(raw), 'synthetic': synthetic, 'baselines': {}}))
        receipt = {'exit_code': code, 'run_dir': str(run), 'html_path': str(run / 'index.html'),
                   'mode': mode, 'synthetic': synthetic,
                   'sources': {name: capture['sources'][name]['status'] for name in refresh.SOURCES}}
        return run, capture, receipt

    def test_first_tick_only_schedules_and_tabs_share_one_deadline(self):
        calls = []
        manager = self.manager(lambda *_: calls.append(1) or successful())
        self.assertIsNone(manager.status()['seconds_until_next'])
        self.assertEqual(manager.tick()['seconds_until_next'], 900)
        self.clock.value += 899
        self.assertEqual(manager.tick()['seconds_until_next'], 1)
        self.assertEqual(manager.tick()['seconds_until_next'], 1)
        self.assertFalse(calls)
        self.clock.value += 1
        manager.tick()
        result = self.finish(manager)
        self.assertEqual(result['phase'], 'SUCCESS')
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['seconds_until_next'], 900)

    def test_manual_and_auto_deduplicate_running_job_and_do_not_catch_up(self):
        started, release = threading.Event(), threading.Event()
        calls = []
        def runner(root, progress):
            calls.append(root)
            progress('salesforce', 'RUNNING')
            started.set()
            release.wait(3)
            return successful()
        self.addCleanup(release.set)
        manager = self.manager(runner)
        manager.tick()
        first = manager.manual()
        self.assertTrue(started.wait(2))
        self.clock.value += 3600
        with self.assertRaises(Conflict):
            manager.close()
        for _ in range(10):
            self.assertEqual(manager.manual()['job_id'], first['job_id'])
            self.assertEqual(manager.tick()['job_id'], first['job_id'])
        self.assertIsNone(manager.status()['seconds_until_next'])
        self.assertEqual(manager.status()['progress']['salesforce'], 'RUNNING')
        self.assertEqual(len(calls), 1)
        release.set()
        self.assertEqual(self.finish(manager)['seconds_until_next'], 900)
        self.assertEqual(manager.tick()['phase'], 'SUCCESS')
        self.assertEqual(len(calls), 1)

    def test_auto_choice_persists_and_disabling_does_not_cancel_current_job(self):
        release = threading.Event()
        self.addCleanup(release.set)
        manager = self.manager(lambda *_: release.wait(3) and successful())
        manager.manual()
        self.assertEqual(manager.set_auto(False)['phase'], 'RUNNING')
        release.set()
        self.assertIsNone(self.finish(manager)['seconds_until_next'])
        self.assertFalse(self.manager(lambda *_: successful()).status()['auto_enabled'])
        self.clock.value += 9000
        self.assertEqual(manager.tick()['phase'], 'SUCCESS')
        self.assertEqual(manager.set_auto(True)['seconds_until_next'], 900)
        self.clock.value += 100
        self.assertEqual(manager.set_auto(True)['seconds_until_next'], 800)
        self.assertTrue(self.manager(lambda *_: successful()).status()['auto_enabled'])
        with self.assertRaises(Invalid):
            manager.set_auto('true')

    def test_terminal_results_are_distinct_and_status_is_detached(self):
        for code, phase in ((0, 'SUCCESS'), (1, 'PARTIAL'), (2, 'FAILED'), (75, 'BUSY')):
            with self.subTest(code=code):
                manager = self.manager(lambda *_, code=code: successful(code) if code in (0, 1) else
                                       {'exit_code': code, 'stderr': 'MUST_NOT_LEAK', 'token': 'MUST_NOT_LEAK'})
                manager.manual()
                state = self.finish(manager)
                self.assertEqual(state['phase'], phase)
                self.assertNotIn('MUST_NOT_LEAK', json.dumps(state))
                self.assertIsNotNone(state['finished_at'])
                state['progress']['kev'] = 'caller mutation'
                self.assertNotEqual(manager.status()['progress']['kev'], 'caller mutation')

    def test_worker_exception_releases_job_and_close_prevents_new_jobs(self):
        calls = []
        def runner(*_):
            calls.append(1)
            if len(calls) == 1:
                raise ValueError('SECRET_RESPONSE_MUST_NOT_LEAK')
            return successful()
        manager = self.manager(runner)
        manager.manual()
        failed = self.finish(manager)
        self.assertEqual(failed['error_code'], 'ValueError')
        self.assertNotIn('SECRET', json.dumps(failed))
        manager.manual()
        self.assertEqual(self.finish(manager)['phase'], 'SUCCESS')
        self.assertTrue(manager.close()['closed'])
        with self.assertRaises(Conflict):
            manager.manual()
        with self.assertRaises(Conflict):
            manager.set_auto(False)
        self.clock.value += 10000
        self.assertTrue(manager.tick()['closed'])
        self.assertEqual(len(calls), 2)

    def test_thread_start_failure_and_invalid_settings_fail_safely(self):
        manager = self.manager(lambda *_: successful())
        with patch.object(threading.Thread, 'start', side_effect=RuntimeError('not exposed')):
            self.assertEqual(manager.manual()['error_code'], 'RefreshWorkerStartFailed')
        manager.thread = None
        self.assertEqual(manager.status()['seconds_until_next'], 900)
        (self.root / 'refresh-settings.json').write_text('{"schema":"psirt-refresh-settings/1","auto_enabled":"false"}')
        with self.assertRaises(RefreshError):
            Manager(self.root)

    def test_live_runner_pins_exact_scope_and_presentation_with_exclusive_receipt(self):
        self.marker('live')
        _, original, _ = self.publish('prior', mode='live', synthetic=False)
        commands = []
        def execute(command, progress):
            commands.append(command)
            self.assertEqual(command[command.index('--mode') + 1], 'live')
            scope = Path(command[command.index('--scope') + 1])
            self.assertEqual(read_json(scope.read_bytes()), original['config'])
            presentation = Path(command[command.index('--presentation') + 1])
            self.assertEqual(presentation.read_bytes(), (self.root / 'runs/prior/report_presentation_used.json').read_bytes())
            receipt = Path(command[command.index('--result-file') + 1])
            self.assertFalse(receipt.exists())
            self.assertEqual(receipt.parent.parent, self.root / 'refresh-attempts')
            progress('kev', 'SUCCESS')
            _, _, result = self.publish('fresh', mode='live', synthetic=False)
            receipt.write_bytes(encoded(result))
            return 0
        with patch.object(refresh, '_execute', side_effect=execute):
            result = run_job(self.root, lambda *_: None)
        self.assertEqual(result['run_id'], 'fresh')
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(len(commands), 1)

    def test_synthetic_live_root_is_rejected_before_spawn(self):
        self.marker('live')
        self.publish('prior', mode='live', synthetic=True)
        with patch.object(refresh, '_execute') as execute, self.assertRaisesRegex(RefreshError, 'SyntheticLiveRejected'):
            run_job(self.root, lambda *_: None)
        execute.assert_not_called()
        self.assertFalse((self.root / 'refresh-attempts').exists())

    def test_runner_maps_failure_and_busy_receipts_without_opening_old_report(self):
        prior, _, _ = self.publish('prior')
        for code in (2, 75):
            with self.subTest(code=code):
                def execute(command, _):
                    receipt = Path(command[command.index('--result-file') + 1])
                    receipt.write_bytes(encoded({'exit_code': code, 'error_type': 'SECRET_MUST_NOT_LEAK'}))
                    return code
                with patch.object(refresh, '_execute', side_effect=execute):
                    result = run_job(self.root, lambda *_: None)
                self.assertEqual(result['exit_code'], code)
                self.assertNotIn('run_id', result)
                self.assertNotIn('SECRET', json.dumps(result))
                self.assertEqual(read_json((self.root / 'state.json').read_bytes())['latest_run'], str(prior))

    def test_success_requires_matching_exit_new_run_current_root_and_artifact_hash(self):
        for failure in ('exit', 'old', 'outside', 'artifact', 'stale', 'statuses', 'missing'):
            with self.subTest(failure=failure):
                prior_id = 'prior-' + failure
                _, _, old_receipt = self.publish(prior_id)
                def execute(command, _):
                    receipt = Path(command[command.index('--result-file') + 1])
                    if failure == 'missing':
                        return 0
                    run, _, result = self.publish('new-' + failure,
                        started='2000-01-01T00:00:00+00:00' if failure == 'stale' else None)
                    if failure == 'exit': result['exit_code'] = 1
                    if failure == 'old': result = old_receipt
                    if failure == 'outside': result['run_dir'] = '/tmp/another-root/runs/not-this-job'
                    if failure == 'artifact': (run / 'index.html').write_text('tampered')
                    if failure == 'statuses': result['sources']['kev'] = 'FAILED'
                    receipt.write_bytes(encoded(result))
                    return 0
                with patch.object(refresh, '_execute', side_effect=execute), self.assertRaises(RefreshError):
                    run_job(self.root, lambda *_: None)

    def test_live_result_cannot_silently_expand_scope(self):
        self.marker('live')
        self.publish('prior', mode='live', synthetic=False)
        def execute(command, _):
            _, _, result = self.publish('changed', mode='live', synthetic=False, changed_scope=True)
            Path(command[command.index('--result-file') + 1]).write_bytes(encoded(result))
            return 0
        with patch.object(refresh, '_execute', side_effect=execute), self.assertRaisesRegex(RefreshError, 'RefreshScopeChanged'):
            run_job(self.root, lambda *_: None)

    def test_partial_result_has_a_verified_new_report(self):
        self.publish('prior')
        def execute(command, _):
            self.assertEqual(command[command.index('--mode') + 1], 'report-rebuild')
            self.assertNotIn('--scope', command)
            _, _, result = self.publish('partial', code=1)
            Path(command[command.index('--result-file') + 1]).write_bytes(encoded(result))
            return 1
        with patch.object(refresh, '_execute', side_effect=execute):
            result = run_job(self.root, lambda *_: None)
        self.assertEqual(result['exit_code'], 1)
        self.assertEqual(result['run_id'], 'partial')
        self.assertEqual(result['statuses']['salesforce'], 'PARTIAL')

    def test_subprocess_progress_is_whitelisted_and_stdout_is_discarded(self):
        seen = []
        code = "import sys; print('PRIVATE_STDOUT'); sys.stderr.write('UNKNOWN_SECRET\\n'+'x'*10000+'\\nCollecting kev (read-only)...\\nkev: SUCCESS\\nsalesforce: PARTIAL\\n')"
        actual_popen = subprocess.Popen
        with patch.object(refresh.subprocess, 'Popen', wraps=actual_popen) as popen:
            result = refresh._execute([sys.executable, '-B', '-c', code], lambda *args: seen.append(args))
        self.assertEqual(result, 0)
        self.assertEqual(seen, [('kev', 'RUNNING'), ('kev', 'SUCCESS'), ('salesforce', 'PARTIAL')])
        self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertEqual(popen.call_args.kwargs['stdout'], subprocess.DEVNULL)

    def test_timeout_reaps_child_before_releasing_runner(self):
        processes = []
        actual_popen = subprocess.Popen
        def launch(*args, **kwargs):
            process = actual_popen(*args, **kwargs)
            processes.append(process)
            return process
        with patch.object(refresh, 'PROCESS_TIMEOUT', .05), patch.object(refresh.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(RefreshError, 'RefreshTimeout'):
                refresh._execute([sys.executable, '-B', '-c', 'import time; time.sleep(10)'], lambda *_: None)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stderr.closed)


class OfflineRefreshTest(unittest.TestCase):
    def test_actual_cli_rebuild_is_offline_and_keeps_old_artifacts_immutable(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            snapshot = base / 'capture.json'
            snapshot.write_bytes(encoded(sample()))
            root = base / 'output'
            seed = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
                                   '--mode', 'snapshot-replay', '--snapshot', str(snapshot), '--output-dir', str(root)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            self.assertIn(seed.returncode, (0, 1), seed.stderr.decode())
            prior = Path(read_json((root / 'state.json').read_bytes())['latest_run'])
            hashes = {p.name: sha(p.read_bytes()) for p in prior.iterdir()}
            result = run_job(root, lambda *_: None)
            self.assertIn(result['exit_code'], (0, 1))
            self.assertEqual(result['mode'], 'report-rebuild')
            self.assertNotEqual(result['run_id'], prior.name)
            current = root / 'runs' / result['run_id']
            self.assertEqual((current / 'capture.json').read_bytes(), (prior / 'capture.json').read_bytes())
            self.assertEqual(hashes, {p.name: sha(p.read_bytes()) for p in prior.iterdir()})
            self.assertFalse((root / 'casework/worklog.sqlite3').exists())


if __name__ == '__main__':
    unittest.main()
