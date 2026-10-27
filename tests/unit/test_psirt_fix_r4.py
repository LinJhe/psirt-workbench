"""R4: unchanged refresh policy, explicit trigger and collection/rebuild meaning.

Managers use a fake clock and injected runner. CLI integration runs only local
synthetic snapshot-replay/report-rebuild with no HTTP service or company access.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework import refresh
from psirt_casework.refresh_web import enhance, strip
from psirt_ops.pipeline import encoded, execution_metadata, run, sha
from psirt_sf_fixtures import sample
import test_psirt_refresh as refresh_fixtures
from test_psirt_refresh import Clock, successful
from test_psirt_refresh_web import shell


class RefreshMeaningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='psirt-r4-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / '.psirt-ops').write_bytes(encoded({'schema': 'psirt-ops/1', 'mode': 'snapshot-replay'}))
        self.clock = Clock()
        self.calls = []
        self.manager = refresh.Manager(self.root, runner=self.runner, clock=self.clock)
        self.addCleanup(self.finish)

    def runner(self, root, progress):
        self.calls.append(root)
        return successful()

    def finish(self):
        if self.manager.thread:
            self.manager.thread.join(3)
            self.assertFalse(self.manager.thread.is_alive())

    def test_first_open_waits_until_due_then_records_page_auto_trigger(self):
        self.assertIsNone(self.manager.status()['trigger'])
        self.assertEqual(self.manager.tick()['seconds_until_next'], 900)
        self.clock.value += 899
        self.manager.tick()
        self.assertEqual(self.calls, [])
        self.clock.value += 1
        self.manager.tick()
        self.finish()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.manager.status()['trigger'], 'page-auto')
        self.assertEqual(self.manager.status()['interval_seconds'], 900)

    def test_no_page_tick_means_no_job_but_reopening_overdue_page_starts_one(self):
        self.manager.tick()
        self.clock.value += 10 * 900
        self.assertEqual(self.manager.status()['seconds_until_next'], 0)
        self.assertEqual(self.calls, [])  # Closing pages does not create a timer.
        self.manager.tick()  # First page tick after reopening the existing service.
        self.finish()
        self.assertEqual(len(self.calls), 1)
        self.manager.tick()
        self.assertEqual(len(self.calls), 1)  # No catch-up execution of missed rounds.
        self.assertEqual(self.manager.status()['seconds_until_next'], 900)

    def test_auto_off_survives_reopen_and_manual_action_remains_available(self):
        self.manager.set_auto(False)
        self.clock.value += 9000
        self.manager.tick()
        reopened = refresh.Manager(self.root, runner=self.runner, clock=self.clock)
        reopened.tick()
        self.assertFalse(reopened.status()['auto_enabled'])
        self.assertEqual(self.calls, [])
        self.manager.manual()
        self.finish()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.manager.status()['trigger'], 'page-manual')
        self.assertIsNone(self.manager.status()['seconds_until_next'])

    def test_builtin_runner_receives_trigger_without_changing_custom_runner_contract(self):
        with patch.object(refresh, 'run_job', return_value=successful()) as runner:
            manager = refresh.Manager(self.root, clock=self.clock)
            manager.manual()
            manager.thread.join(3)
            self.assertFalse(manager.thread.is_alive())
            self.assertEqual(runner.call_args.kwargs, {'trigger': 'page-manual'})
            manager.tick()
            self.clock.value += 900
            manager.tick()
            manager.thread.join(3)
            self.assertEqual(runner.call_args.kwargs, {'trigger': 'page-auto'})
            self.assertEqual(runner.call_count, 2)

    def test_report_rebuild_runner_passes_trigger_without_source_or_retry_flags(self):
        fixture = refresh_fixtures.RefreshTests()
        fixture.setUp()
        self.addCleanup(fixture.temp.cleanup)
        fixture.publish('prior')
        calls = []

        def execute(command, progress):
            calls.append(command)
            self.assertEqual(command[command.index('--trigger') + 1], 'page-auto')
            self.assertEqual(command[command.index('--mode') + 1], 'report-rebuild')
            self.assertNotIn('--scope', command)
            self.assertNotIn('--retry-salesforce', command)
            _, _, receipt = fixture.publish('fresh')
            Path(command[command.index('--result-file') + 1]).write_bytes(encoded(receipt))
            return 0

        with patch.object(refresh, '_execute', side_effect=execute):
            result = refresh.run_job(fixture.root, lambda *_: None, trigger='page-auto')
        self.assertEqual(result['trigger'], 'page-auto')
        self.assertEqual(result['mode'], 'report-rebuild')
        self.assertEqual(len(calls), 1)

    def test_operation_metadata_distinguishes_fetch_from_rebuild_without_executing_live(self):
        for mode, operation, fetch in [('live', 'source-refresh', True),
                                       ('snapshot-replay', 'snapshot-replay', False),
                                       ('report-rebuild', 'report-rebuild', False)]:
            with self.subTest(mode=mode):
                result = execution_metadata(mode, 'page-auto')
                self.assertEqual(result['operation'], operation)
                self.assertEqual(result['source_collection_requested'], fetch)
                self.assertFalse(result['built_in_scheduler'])
        self.assertEqual(execution_metadata('report-rebuild', 'page-rebuild')['trigger'], 'page-rebuild')
        for mode, trigger in [('live', 'page-rebuild'), ('snapshot-replay', 'salesforce-retry'),
                              ('report-rebuild', 'SECRET_UNTRUSTED_TRIGGER')]:
            with self.subTest(mode=mode, trigger=trigger):
                with self.assertRaises(ValueError):
                    execution_metadata(mode, trigger)

    def test_cli_compatibility_and_offline_rebuild_manifest_keep_source_time(self):
        source = self.root / 'synthetic.json'
        source.write_bytes(encoded(sample()))
        output = self.root / 'output'

        def invoke(mode, extra):
            command = [sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
                       '--mode', mode, '--output-dir', str(output), *extra]
            result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads(result.stdout)
            directory = Path(receipt['run_dir'])
            return directory, json.loads((directory / 'manifest.json').read_text())

        first, first_manifest = invoke('snapshot-replay', ['--snapshot', str(source)])
        self.assertEqual(first_manifest['execution']['trigger'], 'cli')
        self.assertFalse(first_manifest['execution']['source_collection_requested'])
        old_hashes = {p.name: sha(p.read_bytes()) for p in first.iterdir()}
        for trigger in ('page-auto', 'page-rebuild'):
            current, manifest = invoke('report-rebuild', ['--trigger', trigger])
            self.assertEqual(manifest['execution']['trigger'], trigger)
            self.assertEqual(manifest['execution']['operation'], 'report-rebuild')
            self.assertFalse(manifest['execution']['source_collection_requested'])
            self.assertEqual(manifest['original_capture_at'], first_manifest['original_capture_at'])
            self.assertEqual((current / 'capture.json').read_bytes(), (first / 'capture.json').read_bytes())
            self.assertNotIn('Manual trigger only; no scheduler', manifest['limits'])
        self.assertEqual(old_hashes, {p.name: sha(p.read_bytes()) for p in first.iterdir()})

    def test_invalid_trigger_fails_before_creating_an_output_directory(self):
        output = self.root / 'must-not-exist'
        with self.assertRaisesRegex(ValueError, 'InvalidRunTrigger'):
            run(output, 'snapshot-replay', trigger='not-allowed')
        self.assertFalse(output.exists())

    def test_toolbar_explains_source_refresh_rebuild_and_overdue_reopen(self):
        original = shell()
        latest = {'run_id': 'synthetic-r4', 'synthetic': True, 'mode': 'snapshot-replay'}
        page = enhance(original, latest)
        self.assertIn('讀取與保存本機紀錄本身不取數', page)
        self.assertIn('頁面依到期狀態觸發既有範圍更新', page)
        self.assertIn('隔離離線工作頁僅重建報告', page)
        self.assertIn('再開工作頁可能立即觸發一輪', page)
        self.assertIn('關閉所有工作頁後不會再發起自動更新', page)
        self.assertIn('尚未保存時延後套用畫面，來源更新仍可執行', page)
        self.assertEqual(strip(page), original)
        self.assertEqual(enhance(page, latest), page)


if __name__ == '__main__':
    unittest.main()
