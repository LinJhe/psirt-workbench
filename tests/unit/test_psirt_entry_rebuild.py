"""Local entry checks use synthetic roots; no running service or company API."""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework import service
from psirt_casework.service import ServiceVersionMismatch
from psirt_casework.store import Invalid
from psirt_dt_fixtures import sample


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class SyntheticRoot:
    """Small real files around a mocked child process for rejection boundaries."""
    def __init__(self, root):
        self.root = root; root.mkdir()
        (root / '.psirt-ops').write_bytes(encoded({'schema': 'psirt-ops/1', 'mode': 'snapshot-replay'}))
        self.capture = sample(); self.capture['sources']['salesforce']['emails'] = []
        self.prior, self.receipt = self.publish('synthetic-prior')

    def publish(self, name, capture=None):
        capture = self.capture if capture is None else capture
        run = self.root / 'runs' / name; run.mkdir(parents=True)
        content = {'capture.json': encoded(capture), 'index.html': b'<html>synthetic index</html>',
                   'casework.html': b'<html>synthetic report</html>', 'report_presentation_used.json': b'{}'}
        for filename, raw in content.items():
            (run / filename).write_bytes(raw)
        at = datetime.now(timezone.utc).isoformat()
        manifest = {'schema': 'psirt-ops-manifest/1', 'run_id': name, 'mode': 'report-rebuild',
                    'started_at': at, 'completed_at': at, 'synthetic': capture['synthetic'],
                    'original_capture_at': capture['captured_at'], 'replay_input_sha256': digest(content['capture.json']),
                    'sources': {name: {'status': row['status']} for name, row in capture['sources'].items()},
                    'artifacts_sha256': {name: digest(raw) for name, raw in content.items()}}
        self.manifest(run, manifest)
        result = {'exit_code': 0, 'run_dir': str(run), 'html_path': str(run / 'index.html'),
                  'mode': 'report-rebuild', 'synthetic': capture['synthetic'],
                  'sources': {name: row['status'] for name, row in capture['sources'].items()}}
        return run, result

    def manifest(self, run, value):
        raw = encoded(value); (run / 'manifest.json').write_bytes(raw)
        (self.root / 'state.json').write_bytes(encoded({'latest_run': str(run), 'manifest_sha256': digest(raw),
                                                     'synthetic': value['synthetic'], 'baselines': {}}))


class EntryRebuildTests(unittest.TestCase):
    def test_actual_cli_rebuild_keeps_complete_and_partial_results_and_source_bytes(self):
        for partial in (False, True):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory() as directory:
                base = Path(directory); root = base / 'output'; capture = sample()
                capture['sources']['salesforce']['emails'] = []
                if partial: capture['sources']['dt'].update(status='PARTIAL', complete=False)
                source = base / 'synthetic.json'; source.write_bytes(encoded(capture))
                command = [sys.executable, '-B', str(service.ROOT / 'scripts/run_psirt_ops.py'),
                           '--mode', 'snapshot-replay', '--snapshot', str(source), '--output-dir', str(root)]
                seeded = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(seeded.returncode, int(partial), seeded.stderr)
                prior = Path(json.loads(seeded.stdout)['run_dir'])
                before = {path.name: digest(path.read_bytes()) for path in prior.iterdir()}
                manual = (root / 'human_review.json').read_bytes()
                result = service.rebuild(root)
                self.assertEqual(result['exit_code'], int(partial))
                self.assertEqual(result['mode'], 'report-rebuild')
                current = Path(result['run_dir']); self.assertNotEqual(current, prior)
                self.assertEqual(result['url'], '/runs/' + current.name + '/casework.html')
                self.assertEqual((current / 'capture.json').read_bytes(), (prior / 'capture.json').read_bytes())
                self.assertEqual(before, {path.name: digest(path.read_bytes()) for path in prior.iterdir()})
                self.assertEqual(manual, (root / 'human_review.json').read_bytes())
                self.assertFalse((root / 'casework/worklog.sqlite3').exists())

    def test_bad_child_receipts_and_artifacts_are_rejected(self):
        scenarios = {'exit': 'RebuildExitMismatch', 'old': 'RebuildCurrentReportMismatch',
                     'outside': 'RebuildCurrentReportMismatch', 'outside-state': 'RefreshRunPathRejected',
                     'mode': 'RebuildCurrentReportMismatch', 'manifest-mode': 'RebuildCurrentReportMismatch',
                     'manifest': 'RefreshManifestMismatch', 'index': 'RefreshArtifactMismatch',
                     'casework': 'RebuildReportHashMismatch', 'capture': 'RebuildSourceChanged',
                     'replay-digest': 'RebuildSourceChanged', 'stale': 'RebuildStaleReportRejected',
                     'statuses': 'RebuildSourceStatusMismatch', 'complete': 'RebuildCompletenessMismatch',
                     'missing': 'RebuildReceiptMissing'}
        for scenario, error in scenarios.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                fixture = SyntheticRoot(Path(directory) / 'root')
                def child(command, **kwargs):
                    self.assertEqual(command[command.index('--mode') + 1], 'report-rebuild')
                    self.assertEqual(command[command.index('--trigger') + 1], 'page-rebuild')
                    receipt = Path(command[command.index('--result-file') + 1])
                    if scenario == 'missing': return SimpleNamespace(returncode=0)
                    capture = copy.deepcopy(fixture.capture)
                    if scenario == 'capture': capture['captured_at'] = '2026-10-19T12:00:00+08:00'
                    run, result = (fixture.prior, copy.deepcopy(fixture.receipt)) if scenario == 'old' else fixture.publish('synthetic-new', capture)
                    manifest = json.loads((run / 'manifest.json').read_bytes())
                    code = 0
                    if scenario == 'exit': result['exit_code'] = 1
                    if scenario == 'outside': result['run_dir'] = str(Path(directory) / 'unrelated' / 'run')
                    if scenario == 'outside-state':
                        state = json.loads((fixture.root / 'state.json').read_bytes())
                        state['latest_run'] = str(Path(directory) / 'unrelated' / 'run')
                        (fixture.root / 'state.json').write_bytes(encoded(state))
                    if scenario == 'mode': result['mode'] = 'live'
                    if scenario == 'manifest-mode': manifest['mode'] = 'live'; fixture.manifest(run, manifest)
                    if scenario == 'manifest': (run / 'manifest.json').write_bytes(b'{}')
                    if scenario == 'index': (run / 'index.html').write_bytes(b'changed')
                    if scenario == 'casework': (run / 'casework.html').write_bytes(b'changed')
                    if scenario == 'replay-digest': manifest['replay_input_sha256'] = 'wrong'; fixture.manifest(run, manifest)
                    if scenario == 'stale': manifest['started_at'] = '2000-01-01T00:00:00+00:00'; fixture.manifest(run, manifest)
                    if scenario == 'statuses': result['sources']['kev'] = 'FAILED'
                    if scenario == 'complete': result['exit_code'] = code = 1
                    receipt.write_bytes(encoded(result))
                    return SimpleNamespace(returncode=code)
                with patch.object(service.subprocess, 'run', side_effect=child):
                    with self.assertRaisesRegex(Invalid, error): service.rebuild(fixture.root)

    def test_old_version_has_safe_type_and_can_only_bypass_version_check_for_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = SyntheticRoot(Path(directory) / 'root')
            receipt = {'root': str(fixture.root), 'uid': os.getuid(), 'origin': 'http://127.0.0.1:9',
                       'instance': 'synthetic-instance', 'version': 'synthetic-old', 'control': 'synthetic-control'}
            (fixture.root / service.RECEIPT).write_bytes(encoded(receipt))
            with patch.object(service, 'local_request', return_value=receipt), patch.object(service, 'version', return_value='synthetic-new'):
                with self.assertRaises(ServiceVersionMismatch) as caught: service.inspect(fixture.root)
                self.assertEqual(caught.exception.code, 'ServiceVersionMismatch')
                self.assertNotIn('synthetic-control', str(caught.exception))
                self.assertEqual(service.inspect(fixture.root, allow_old=True), receipt)
            bad_health = {**receipt, 'instance': 'different-instance'}
            with patch.object(service, 'local_request', return_value=bad_health):
                with self.assertRaisesRegex(Invalid, '服務身分不一致'): service.inspect(fixture.root, allow_old=True)


if __name__ == '__main__': unittest.main()
