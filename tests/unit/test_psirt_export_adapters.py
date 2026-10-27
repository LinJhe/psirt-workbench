"""Portable integration contract; fake transports and environment only."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from psirt_ops import adapters
from confluence_weekly.adapters import ConfluenceRestClient, resolve_env


class ExportAdapterTests(unittest.TestCase):
    def test_missing_configuration_is_explicit_and_never_reads_fallback_files(self):
        reader = Mock()
        with patch.dict(os.environ, {}, clear=True), patch.object(Path, 'read_text', side_effect=AssertionError('unexpected file read')):
            for action, config, key in (
                (adapters.collect_jira, {}, 'JIRA_URL'),
                (adapters.collect_sf, {}, 'SF_INSTANCE_URL'),
                (adapters.collect_dt, {'dt_base': 'https://fixture.invalid'}, 'DT_API_KEY'),
            ):
                with self.subTest(key=key), self.assertRaises(adapters.ConfigurationUnavailable) as caught:
                    action(reader, config)
                self.assertEqual(adapters.safe_error(caught.exception)['configuration_key'], key)
            self.assertIsNone(resolve_env('CONFLUENCE_TOKEN'))
        reader.get.assert_not_called()

    def test_endpoint_configuration_rejects_credentials_and_query(self):
        for url in ('http://fixture.invalid', 'https://user:secret@fixture.invalid',
                    'https://fixture.invalid?token=secret', 'https://fixture.invalid/#secret',
                    'https://fixture.invalid/path', 'https://fixture.invalid:bad',
                    'https://fixture.invalid\\redirect', 'https://fixture.invalid/\n'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                adapters.instance_url(url)
        self.assertEqual(adapters.instance_url('https://fixture.invalid/context/', allow_path=True),
                         'https://fixture.invalid/context')

    def test_salesforce_reuses_external_token_and_only_queries(self):
        reader = Mock()
        reader.get.return_value = ({'records': [], 'done': True, 'totalSize': 0}, {})
        with patch.dict(os.environ, {'SF_INSTANCE_URL': 'https://fixture.invalid', 'SF_ACCESS_TOKEN': 'FAKE_SESSION'}, clear=True):
            result = adapters.collect_sf(reader, {
                'sf_owner': 'Example', 'sf_explicit_cases': [],
                'window_start': '2026-10-19T00:00:00+08:00', 'cutoff': '2026-10-20T00:00:00+08:00'})
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertTrue(result['complete'])
        self.assertEqual(reader.get.call_count, 1)
        self.assertEqual(reader.get.call_args.args[1], {'Authorization': 'Bearer FAKE_SESSION'})
        self.assertNotIn('FAKE_SESSION', repr(result))

    def test_jira_project_is_configurable_and_detail_scope_stays_bounded(self):
        reader = Mock()
        reader.get.return_value = ({'issues': [], 'startAt': 0, 'total': 0}, {})
        with patch.dict(os.environ, {'JIRA_URL': 'https://fixture.invalid', 'JIRA_TOKEN': 'FAKE_TOKEN'}, clear=True):
            cfg = {'jira_project': 'DEMO', 'sample_issues': [],
                   'window_start': '2026-10-19T00:00:00+08:00', 'cutoff': '2026-10-20T00:00:00+08:00'}
            result = adapters.collect_jira(reader, cfg)
            self.assertEqual(result['scope']['project'], 'DEMO')
            self.assertEqual(result['status'], 'SUCCESS')
            self.assertNotIn('FAKE_TOKEN', repr(result))
            cfg['sample_issues'] = ['OTHER-1']
            with self.assertRaisesRegex(ValueError, 'DetailScopeRejected'):
                adapters.collect_jira(reader, cfg)
            self.assertFalse(any('/issue/' in call.args[0] for call in reader.get.call_args_list))

    def test_optional_confluence_and_structural_write_guard(self):
        reader = Mock()
        self.assertEqual(adapters.collect_weekly(reader, {'weekly_page': None})['status'], 'NOT_CONFIGURED')
        reader.get.assert_not_called()
        transport = Mock()
        client = ConfluenceRestClient('https://fixture.invalid', 'FAKE_TOKEN',
                                      transport=transport, writes_enabled=True)
        for method, body, write in [('POST', {}, False), ('PUT', None, False), ('GET', {}, False), ('GET', None, True)]:
            with self.subTest(method=method, body=body, write=write), self.assertRaises(PermissionError):
                client.request(method, '/rest/api/content', body=body, write=write)
        transport.assert_not_called()


if __name__ == '__main__':
    unittest.main()
