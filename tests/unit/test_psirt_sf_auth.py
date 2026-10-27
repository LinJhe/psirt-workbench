"""SF auth/query behavior using isolated files and fake transports only."""
import copy
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_ops import adapters, sf_auth
from psirt_ops.pipeline import run
from psirt_casework import refresh
from psirt_sf_fixtures import sample

AT = '2026-10-26T13:05:00+08:00'
SECRET = 'DO_NOT_EXPOSE_SESSION_OR_PASSWORD'


def error(code=sf_auth.EXPIRED, status=401, body=None):
    raw = body if body is not None else json.dumps([{'errorCode': code, 'message': SECRET}]).encode()
    return urllib.error.HTTPError('https://fixture.invalid', status, SECRET,
                                  {'Authorization': SECRET}, io.BytesIO(raw))


def source(status='SUCCESS', complete=True, errors=None):
    return {**adapters.envelope({'instance': 'https://fixture.invalid'}, 'fixture/1'),
            'status': status, 'complete': complete, 'observed_at': AT,
            'raw': [] if status != 'FAILED' else None, 'emails': [], 'errors': errors or []}


class Reader:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.urls = []

    def get(self, url, headers=None):
        self.urls.append(url)
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return reply, {}


def page(rows, total=None, done=True, next_path='/services/data/v58.0/query/next'):
    return {'records': rows, 'totalSize': len(rows) if total is None else total,
            'done': done, 'nextRecordsUrl': next_path}


class SalesforceAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = {'scope_version': 'fixture/1', 'sf_owner': 'Fixture', 'sf_explicit_cases': [],
                    'window_start': '2026-10-19T00:00:00+08:00', 'cutoff': AT}

    def collect(self, sf, *, retry=False):
        with ExitStack() as stack:
            calls = {name: stack.enter_context(patch.object(adapters, 'collect_' + name,
                         return_value=source())) for name in ('kev', 'dt', 'jira')}
            current = stack.enter_context(patch.object(adapters, 'collect_sf', return_value=sf))
            stack.enter_context(patch.object(adapters, 'collect_weekly', return_value={'status': 'SUCCESS'}))
            stack.enter_context(patch.object(adapters, 'now', return_value=AT))
            stderr = stack.enter_context(redirect_stderr(io.StringIO()))
            result = adapters.collect(self.cfg, output_root=self.root, retry_sf=retry)
            self.assertNotIn(SECRET, json.dumps(result) + stderr.getvalue())
            for call in calls.values():
                call.assert_called_once()
            return result['sources']['salesforce'], current.call_count

    def test_safe_error_is_bounded_cached_and_never_exposes_body_headers_or_url(self):
        exc = error()
        first = adapters.safe_error(exc)
        self.assertEqual(first['error_code'], sf_auth.EXPIRED)
        self.assertEqual(first, adapters.safe_error(exc))
        self.assertNotIn(SECRET, json.dumps(first))
        for body in (b'not JSON ' + SECRET.encode(), b'[' + b' ' * sf_auth.BODY_LIMIT,
                     json.dumps([{'errorCode': 'UNKNOWN_' + SECRET}]).encode(),
                     json.dumps([{'errorCode': sf_auth.EXPIRED}, {'errorCode': 'INVALID_SESSION_ID'}]).encode()):
            with self.subTest(body_size=len(body)):
                item = adapters.safe_error(error(body=body))
                self.assertNotIn('error_code', item)
                self.assertNotIn(SECRET, json.dumps(item))
        bounded = error()
        with patch.object(bounded, 'read') as read:
            read.return_value = b'[]'
            sf_auth.error_code(bounded)
            read.assert_called_once_with(sf_auth.BODY_LIMIT + 1)
        # Non-HTTP exceptions can contain sensitive messages but never expose them.
        self.assertNotIn(SECRET, json.dumps(adapters.safe_error(RuntimeError(SECRET))))

    def test_expired_skip_failed_retry_and_complete_rest_success_clear_block(self):
        failed, count = self.collect(source('FAILED', False, [adapters.safe_error(error())]))
        self.assertEqual(count, 1)
        self.assertTrue(failed['attempted'] and failed['auth_blocked'])
        state = sf_auth.load(self.root)
        self.assertEqual(state['first_failed_at'], AT)
        before = (self.root / 'sf-auth-state.json').read_bytes()
        skipped, count = self.collect(source())
        self.assertEqual(count, 0)
        self.assertFalse(skipped['attempted'])
        self.assertIsNone(skipped['attempted_at'])
        self.assertEqual(skipped['status'], 'FAILED')
        self.assertFalse(skipped['complete'])
        self.assertEqual(skipped['observed_at'], AT)
        self.assertEqual(before, (self.root / 'sf-auth-state.json').read_bytes())
        retry, count = self.collect(source('FAILED', False, [adapters.safe_error(error('INVALID_SESSION_ID'))]), retry=True)
        self.assertEqual(count, 1)
        self.assertTrue(retry['auth_blocked'])
        self.assertEqual(sf_auth.load(self.root)['first_failed_at'], AT)
        partial, _ = self.collect(source('PARTIAL', False), retry=True)
        self.assertTrue(partial['auth_blocked'])
        good, count = self.collect(source(), retry=True)
        self.assertEqual(count, 1)
        self.assertFalse(good['auth_blocked'])
        self.assertFalse(sf_auth.load(self.root)['blocked'])
        self.assertIsNotNone(sf_auth.load(self.root)['cleared_at'])
        self.assertEqual(self.collect(source())[1], 1)
        self.assertNotIn(SECRET, (self.root / 'sf-auth-state.json').read_text())

    def test_other_401_unknown_error_and_429_do_not_assert_password_expiry(self):
        for exc in (error('INVALID_SESSION_ID'), error('UNKNOWN'), error('REQUEST_LIMIT_EXCEEDED', 429),
                    error(sf_auth.EXPIRED, 500), RuntimeError(SECRET)):
            with self.subTest(error_type=type(exc).__name__):
                result, count = self.collect(source('FAILED', False, [adapters.safe_error(exc)]))
                self.assertEqual(count, 1)
                self.assertFalse(result['auth_blocked'])
                self.assertFalse((self.root / 'sf-auth-state.json').exists())

    def test_query_mid_page_failure_retains_observed_rows_and_error(self):
        reader = Reader([page([{'Id': 'e1'}], 2, False), error()])
        rows, pages, complete = adapters.sf_query(reader, 'https://fixture.invalid', SECRET, 'SELECT Id')
        self.assertEqual(rows, [{'Id': 'e1'}])
        self.assertFalse(complete)
        self.assertEqual(pages[0]['returned'], 1)
        self.assertEqual(pages[1]['error']['error_code'], sf_auth.EXPIRED)
        self.assertNotIn(SECRET, json.dumps(pages))
        self.assertEqual(len(reader.urls), 2)

    def test_query_empty_success_differs_from_failed_or_malformed_page(self):
        rows, pages, complete = adapters.sf_query(Reader([page([])]), 'https://fixture.invalid', SECRET, 'SELECT Id')
        self.assertTrue(complete)
        self.assertEqual(rows, [])
        for bad in (error(), {}, {'records': [], 'totalSize': 0, 'done': 'true'}):
            rows, pages, complete = adapters.sf_query(Reader([bad]), 'https://fixture.invalid', SECRET, 'SELECT Id')
            self.assertFalse(complete)
            self.assertTrue(pages[-1]['query_failed'])
        rows, pages, complete = adapters.sf_query(Reader([page([{'Id': 'e1'}], 2, False, '')]),
                                                  'https://fixture.invalid', SECRET, 'SELECT Id')
        self.assertFalse(complete)
        self.assertEqual(rows, [{'Id': 'e1'}])

    def sf(self, reader):
        with patch.dict('os.environ', {'SF_INSTANCE_URL':'https://fixture.invalid', 'SF_ACCESS_TOKEN':SECRET}):
            return adapters.collect_sf(reader, self.cfg)

    def test_collector_retains_case_and_email_pages_after_auth_failure_and_stops_batches(self):
        cases = [{'Id': str(n).zfill(15), 'CaseNumber': 'Q-202610-' + str(n)} for n in range(76)]
        reader = Reader([page(cases), page([{'Id': 'e1', 'Incoming': True}], 2, False), error()])
        result = self.sf(reader)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertFalse(result['complete'])
        self.assertEqual(len(result['raw']), 76)
        self.assertEqual(result['emails'], [{'Id': 'e1', 'Incoming': True}])
        self.assertEqual(result['errors'][0]['error_code'], sf_auth.EXPIRED)
        self.assertEqual(len(reader.urls), 3)  # Never tries Case batch 76 after 401.
        self.assertIn('HtmlBody', reader.urls[1])
        self.assertIn('LastModifiedDate', reader.urls[1])

    def test_invalid_html_field_is_partial_and_first_case_failure_is_failed(self):
        result = self.sf(Reader([page([{'Id': '000000000000001'}]), error('INVALID_FIELD', 400)]))
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertFalse(result['complete'])
        self.assertEqual(result['errors'][0]['error_code'], 'INVALID_FIELD')
        result = self.sf(Reader([error()]))
        self.assertEqual(result['status'], 'FAILED')
        self.assertIsNone(result['raw'])
        self.assertFalse(result['complete'])
        result = self.sf(Reader([page([])]))
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertTrue(result['complete'])

    def test_default_collect_signature_does_not_create_auth_state(self):
        with ExitStack() as stack:
            for name in ('kev', 'dt', 'jira', 'sf'):
                stack.enter_context(patch.object(adapters, 'collect_' + name, return_value=source()))
            stack.enter_context(patch.object(adapters, 'collect_weekly', return_value={'status': 'SUCCESS'}))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = adapters.collect(self.cfg)
        self.assertEqual(result['sources']['salesforce']['status'], 'SUCCESS')

    def test_replay_and_rebuild_never_read_or_write_auth_circuit(self):
        capture = sample()
        input_path = self.root / 'capture.json'
        input_path.write_text(json.dumps(capture))
        output = self.root / 'offline'
        with patch('psirt_daily.offline.install_offline_guard'), \
                patch.object(sf_auth, 'load', side_effect=AssertionError('must not read auth state')), \
                patch.object(sf_auth, 'update', side_effect=AssertionError('must not write auth state')):
            run(output, 'snapshot-replay', snapshot=input_path)
            auth_file = output / 'sf-auth-state.json'
            auth_file.write_text('preserve existing local file; replay must not parse')
            before = auth_file.read_bytes()
            run(output, 'report-rebuild')
            self.assertEqual(before, auth_file.read_bytes())
        with self.assertRaisesRegex(ValueError, 'SalesforceRetryRequiresLiveMode'):
            run(output, 'report-rebuild', retry_sf=True)

    def test_cli_rejects_retry_in_offline_mode_before_output_writes(self):
        output = self.root / 'untouched'
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/run_psirt_ops.py'),
                                 '--mode', 'report-rebuild', '--output-dir', str(output),
                                 '--retry-salesforce'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_manager_explicit_retry_passes_flag_normal_manual_does_not_and_busy_dedupes(self):
        (self.root / '.psirt-ops').write_text(json.dumps({'schema': 'psirt-ops/1', 'mode': 'live'}))
        entered, release = threading.Event(), threading.Event()
        calls = []
        def runner(root, progress, **kwargs):
            calls.append(kwargs)
            entered.set()
            release.wait(3)
            return {'exit_code': 1, 'run_id': 'fixture-run', 'mode': 'live',
                    'statuses': {n: 'FAILED' if n == 'salesforce' else 'SUCCESS' for n in refresh.SOURCES}}
        self.addCleanup(release.set)
        manager = refresh.Manager(self.root, runner=runner)
        first = manager.retry_salesforce()
        self.assertTrue(entered.wait(1))
        self.assertEqual(manager.manual()['job_id'], first['job_id'])
        self.assertEqual(manager.retry_salesforce()['job_id'], first['job_id'])
        release.set()
        manager.thread.join(3)
        self.assertFalse(manager.thread.is_alive())
        self.assertEqual(calls, [{'retry_sf': True}])
        manager.manual()
        manager.thread.join(3)
        self.assertEqual(calls, [{'retry_sf': True}, {}])
        (self.root / '.psirt-ops').write_text(json.dumps({'schema': 'psirt-ops/1', 'mode': 'snapshot-replay'}))
        with self.assertRaisesRegex(ValueError, 'SalesforceRetryRequiresLiveMode'):
            manager.retry_salesforce()

    def test_run_job_threads_explicit_retry_into_existing_live_cli_without_scope_changes(self):
        from test_psirt_refresh import RefreshTests
        fixture = RefreshTests()
        fixture.setUp()
        self.addCleanup(fixture.temp.cleanup)
        fixture.marker('live')
        _, original, _ = fixture.publish('before-retry', mode='live', synthetic=False)
        calls = []
        def execute(command, progress):
            calls.append(command)
            self.assertIn('--retry-salesforce', command)
            scope_path = Path(command[command.index('--scope') + 1])
            self.assertEqual(json.loads(scope_path.read_text()), original['config'])
            _, _, receipt = fixture.publish('after-retry', mode='live', synthetic=False)
            Path(command[command.index('--result-file') + 1]).write_text(json.dumps(receipt))
            return 0
        with patch.object(refresh, '_execute', side_effect=execute):
            result = refresh.run_job(fixture.root, lambda *_: None, retry_sf=True)
        self.assertEqual(result['run_id'], 'after-retry')
        self.assertEqual(len(calls), 1)
        fixture.marker('snapshot-replay')
        with patch.object(refresh, '_execute') as execute, self.assertRaisesRegex(ValueError, 'SalesforceRetryRequiresLiveMode'):
            refresh.run_job(fixture.root, lambda *_: None, retry_sf=True)
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
