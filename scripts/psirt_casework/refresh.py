"""One refresh job per workbench; page heartbeats, never a background timer.

The collector remains a separate CLI process with its existing credentials and
root lock. Only a verified per-attempt receipt may become a successful result.
"""
import copy
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from psirt_daily.pipeline import encoded, no_symlinks, read_json, sha, sync_directory, write_new
from .store import Conflict, Invalid, now

ROOT = Path(__file__).resolve().parents[2]
INTERVAL = 900
PROCESS_TIMEOUT = 600
SOURCES = ('kev', 'dt', 'salesforce', 'jira')
SOURCE_STATES = {'WAITING', 'RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED'}
PHASES = {0: 'SUCCESS', 1: 'PARTIAL', 2: 'FAILED', 75: 'BUSY'}


class RefreshError(Invalid):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _mode(root):
    no_symlinks(root / '.psirt-ops')
    marker = read_json((root / '.psirt-ops').read_bytes())
    if marker.get('schema') != 'psirt-ops/1' or marker.get('mode') not in ('live', 'snapshot-replay'):
        raise RefreshError('RefreshRootRejected')
    return marker['mode']


def _latest(root):
    no_symlinks(root / 'state.json')
    state = read_json((root / 'state.json').read_bytes())
    run = Path(state['latest_run'])
    if run.parent != root / 'runs' or not re.fullmatch(r'[A-Za-z0-9_+.-]+', run.name):
        raise RefreshError('RefreshRunPathRejected')
    no_symlinks(run / 'manifest.json')
    raw = (run / 'manifest.json').read_bytes()
    if sha(raw) != state.get('manifest_sha256'):
        raise RefreshError('RefreshManifestMismatch')
    manifest = read_json(raw)
    if manifest.get('run_id') != run.name or manifest.get('schema') != 'psirt-ops-manifest/1':
        raise RefreshError('RefreshManifestRejected')
    artifacts = {}
    for name in ('capture.json', 'index.html', 'report_presentation_used.json'):
        path = run / name
        no_symlinks(path)
        raw = path.read_bytes()
        if sha(raw) != manifest.get('artifacts_sha256', {}).get(name):
            raise RefreshError('RefreshArtifactMismatch')
        artifacts[name] = raw
    capture = read_json(artifacts['capture.json'])
    if (not isinstance(capture.get('synthetic'), bool) or
            state.get('synthetic') != capture['synthetic'] or
            manifest.get('synthetic') != capture['synthetic']):
        raise RefreshError('RefreshModeMismatch')
    return state, run, manifest, capture, artifacts


def _progress(line, callback):
    match = re.fullmatch(r'Collecting (kev|dt|salesforce|jira) \(read-only\)\.\.\.', line)
    if match:
        callback(match[1], 'RUNNING')
        return
    match = re.fullmatch(r'(kev|dt|salesforce|jira): (SUCCESS|PARTIAL|FAILED)', line)
    if match:
        callback(match[1], match[2])


def _terminate(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def _execute(command, progress):
    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               shell=False, start_new_session=True)
    deadline = time.monotonic() + PROCESS_TIMEOUT
    buffer = b''
    discarding = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RefreshError('RefreshTimeout')
                for key, _ in selector.select(min(remaining, .2)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    for part in chunk.splitlines(keepends=True):
                        buffer += part
                        if len(buffer) > 512:
                            buffer = b''
                            discarding = True
                        if part.endswith((b'\n', b'\r')):
                            if not discarding:
                                _progress(buffer.decode('utf-8', errors='replace').strip(), progress)
                            buffer = b''
                            discarding = False
            if buffer and not discarding:
                _progress(buffer.decode('utf-8', errors='replace').strip(), progress)
            try:
                return process.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise RefreshError('RefreshTimeout') from None
    finally:
        _terminate(process)
        process.stderr.close()


def run_job(root, progress, *, retry_sf=False, trigger='direct'):
    """Run only the existing CLI and return a small, verified, non-secret result."""
    root = Path(root).absolute()
    mode = 'live' if _mode(root) == 'live' else 'report-rebuild'
    if retry_sf and mode != 'live':
        raise RefreshError('SalesforceRetryRequiresLiveMode')
    if retry_sf:
        trigger = 'salesforce-retry'
    if trigger not in {'direct', 'page-manual', 'page-auto', 'salesforce-retry'}:
        raise RefreshError('RefreshTriggerRejected')
    state, prior, _, capture, artifacts = _latest(root)
    if mode == 'live' and (capture['synthetic'] or state['synthetic']):
        raise RefreshError('SyntheticLiveRejected')
    attempts = root / 'refresh-attempts'
    no_symlinks(attempts)
    attempts.mkdir(exist_ok=True, mode=0o700)
    attempt = attempts / uuid4().hex
    attempt.mkdir(mode=0o700)
    receipt = attempt / 'result.json'  # The CLI reserves this path with open('xb').
    presentation = attempt / 'presentation.json'
    write_new(presentation, artifacts['report_presentation_used.json'])
    command = [sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
               '--mode', mode, '--output-dir', str(root), '--result-file', str(receipt),
               '--presentation', str(presentation), '--trigger', trigger]
    if mode == 'live':
        scope = attempt / 'scope.json'
        if not isinstance(capture.get('config'), dict):
            raise RefreshError('RefreshScopeRejected')
        write_new(scope, encoded(capture['config']))
        command += ['--scope', str(scope)]
        if retry_sf:
            command.append('--retry-salesforce')
    started = datetime.fromisoformat(now())
    code = _execute(command, progress)
    no_symlinks(receipt)
    if not receipt.is_file() or receipt.stat().st_size > 2_000_000:
        raise RefreshError('RefreshReceiptMissing')
    result = read_json(receipt.read_bytes())
    if type(result.get('exit_code')) is not int or result['exit_code'] != code or code not in PHASES:
        raise RefreshError('RefreshExitMismatch')
    if code in (2, 75):
        return {'exit_code': code, 'error_code': 'AlreadyRunning' if code == 75 else 'CollectionFailed'}
    current_state, run, manifest, current, _ = _latest(root)
    if (result.get('run_dir') != str(run) or run == prior or result.get('html_path') != str(run / 'index.html') or
            result.get('mode') != mode or manifest.get('mode') != mode or
            result.get('synthetic') != capture['synthetic'] or current['synthetic'] != capture['synthetic']):
        raise RefreshError('RefreshCurrentReportMismatch')
    began = datetime.fromisoformat(manifest['started_at'])
    ended = datetime.fromisoformat(manifest['completed_at'])
    if began.tzinfo is None or ended.tzinfo is None or began < started or ended < began:
        raise RefreshError('RefreshStaleReportRejected')
    statuses = result.get('sources')
    if (not isinstance(statuses, dict) or set(statuses) != set(SOURCES) or
            any(statuses[n] not in {'SUCCESS', 'PARTIAL', 'FAILED'} or
                statuses[n] != manifest.get('sources', {}).get(n, {}).get('status') or
                statuses[n] != current['sources'][n].get('status') for n in SOURCES)):
        raise RefreshError('RefreshSourceStatusMismatch')
    complete = all(current['sources'][n].get('complete') is True and statuses[n] == 'SUCCESS' for n in SOURCES)
    if code != (0 if complete else 1):
        raise RefreshError('RefreshCompletenessMismatch')
    if mode == 'live' and current.get('config') != {**capture['config'], 'cutoff': manifest['started_at']}:
        raise RefreshError('RefreshScopeChanged')
    return {'exit_code': code, 'run_id': run.name, 'statuses': statuses, 'mode': mode,
            'trigger': trigger, 'error_code': None}


class Manager:
    def __init__(self, root, runner=None, clock=time.monotonic):
        self.root = Path(root).absolute()
        _mode(self.root)
        self.runner = runner or run_job
        self.uses_default_runner = runner is None
        self.clock = clock
        self.lock = threading.RLock()
        self.thread = None
        self.closed = False
        self.due = None
        self.auto_enabled = True
        self.settings = self.root / 'refresh-settings.json'
        no_symlinks(self.settings)
        if self.settings.exists():
            settings = read_json(self.settings.read_bytes())
            if settings.get('schema') != 'psirt-refresh-settings/1' or type(settings.get('auto_enabled')) is not bool:
                raise RefreshError('RefreshSettingsRejected')
            self.auto_enabled = settings['auto_enabled']
        self.state = {'job_id': None, 'phase': 'IDLE', 'started_at': None, 'finished_at': None, 'trigger': None,
                      'progress': {n: 'WAITING' for n in SOURCES}, 'result': None, 'error_code': None}

    def _status(self):
        remaining = max(0, math.ceil(self.due - self.clock())) if self.due is not None and self.auto_enabled and not self.closed else None
        return {**copy.deepcopy(self.state), 'auto_enabled': self.auto_enabled, 'interval_seconds': INTERVAL,
                'seconds_until_next': remaining, 'closed': self.closed}

    def status(self):
        with self.lock:
            return self._status()

    def _start(self, *, retry_sf=False, trigger='page-manual'):
        if self.closed:
            raise Conflict('更新服務已停止')
        if self.state['phase'] == 'RUNNING':
            return self._status()
        self.due = None
        self.state = {'job_id': uuid4().hex, 'phase': 'RUNNING', 'started_at': now(), 'finished_at': None, 'trigger': trigger,
                      'progress': {n: 'WAITING' for n in SOURCES}, 'result': None, 'error_code': None}
        self.thread = threading.Thread(target=self._work, args=(self.state['job_id'], retry_sf, trigger), daemon=True, name='psirt-refresh')
        try:
            self.thread.start()
        except Exception:
            self.state.update(phase='FAILED', finished_at=now(), error_code='RefreshWorkerStartFailed')
            self.due = self.clock() + INTERVAL if self.auto_enabled else None
        return self._status()

    def manual(self):
        with self.lock:
            return self._start()

    def retry_salesforce(self):
        with self.lock:
            if _mode(self.root) != 'live':
                raise Invalid('SalesforceRetryRequiresLiveMode')
            return self._start(retry_sf=True, trigger='salesforce-retry')

    def tick(self):
        with self.lock:
            if self.closed or not self.auto_enabled or self.state['phase'] == 'RUNNING':
                return self._status()
            if self.due is None:
                self.due = self.clock() + INTERVAL
            elif self.clock() >= self.due:
                return self._start(trigger='page-auto')
            return self._status()

    def set_auto(self, enabled):
        if type(enabled) is not bool:
            raise Invalid('自動更新設定須為布林值')
        with self.lock:
            if self.closed:
                raise Conflict('更新服務已停止')
            no_symlinks(self.settings)
            temporary = self.root / ('refresh-settings-' + uuid4().hex + '.tmp')
            try:
                write_new(temporary, encoded({'schema': 'psirt-refresh-settings/1', 'auto_enabled': enabled}))
                temporary.chmod(0o600)
                os.replace(temporary, self.settings)
                sync_directory(self.root)
            finally:
                temporary.unlink(missing_ok=True)
            if enabled != self.auto_enabled:
                self.due = self.clock() + INTERVAL if enabled and self.state['phase'] != 'RUNNING' else None
            self.auto_enabled = enabled
            return self._status()

    def _work(self, job_id, retry_sf=False, trigger='page-manual'):
        def progress(source, status):
            if source in SOURCES and status in SOURCE_STATES:
                with self.lock:
                    if self.state['job_id'] == job_id and self.state['phase'] == 'RUNNING':
                        self.state['progress'][source] = status
        terminal = {'phase': 'FAILED', 'result': None, 'error_code': 'RefreshWorkerFailed'}
        try:
            # Keep the existing injected-runner contract for isolated tests and
            # callers. Only our built-in CLI runner accepts trigger metadata.
            kwargs = {'retry_sf': True} if retry_sf else {}
            if self.uses_default_runner:
                kwargs['trigger'] = trigger
            result = self.runner(self.root, progress, **kwargs)
            code = result.get('exit_code')
            if type(code) is not int or code not in PHASES:
                raise RefreshError('RefreshRunnerResultRejected')
            safe_result = None
            if code in (0, 1):
                statuses = result.get('statuses', result.get('sources', {}))
                if (not isinstance(result.get('run_id'), str) or not re.fullmatch(r'[A-Za-z0-9_+.-]+', result['run_id']) or
                        not isinstance(statuses, dict) or set(statuses) != set(SOURCES) or
                        any(statuses[n] not in {'SUCCESS', 'PARTIAL', 'FAILED'} for n in SOURCES)):
                    raise RefreshError('RefreshRunnerResultRejected')
                safe_result = {'run_id': result['run_id'], 'statuses': dict(statuses),
                               'mode': result.get('mode') if result.get('mode') in ('live', 'report-rebuild') else None}
            terminal = {'phase': PHASES[code], 'result': safe_result,
                        'error_code': 'AlreadyRunning' if code == 75 else 'CollectionFailed' if code == 2 else None}
        except Exception as exc:
            terminal = {'phase': 'FAILED', 'result': None,
                        'error_code': exc.code if isinstance(exc, RefreshError) else type(exc).__name__}
        finally:
            with self.lock:
                self.state.update(terminal, finished_at=now())
                if terminal['result']:
                    self.state['progress'].update(terminal['result']['statuses'])
                self.due = self.clock() + INTERVAL if self.auto_enabled and not self.closed else None

    def close(self):
        with self.lock:
            if self.state['phase'] == 'RUNNING':
                raise Conflict('來源更新仍在執行，完成後才能停止')
            self.closed = True
            self.due = None
            return self._status()
