"""Offline acceptance for revisioned local links; never contact a saved URL."""
import copy
import html
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from psirt_casework.projection import build as build_casework
from psirt_casework.resources import build, defaults, navigation, safe_url
from psirt_casework.resources_web import render
from psirt_casework.store import Conflict, Invalid, Store, read_snapshot, validate
from psirt_sf_fixtures import sample

ASOF = '2026-10-21T09:00:00+08:00'


def capture():
    source = sample()
    source['sources']['jira']['scope']['instance'] = 'https://jira.synthetic.invalid'
    source['sources']['salesforce']['scope']['instance'] = 'https://sf.synthetic.invalid'
    source['weekly_template'] = {
        'source': 'https://wiki.synthetic.invalid/pages/viewpage.action?pageId=123'}
    return source


def bookmark(**extra):
    return {'title': 'Synthetic team document',
            'url': 'https://example.invalid/document?view=review#section-1',
            'category': 'documents', 'note': 'Synthetic local link only',
            'status': 'active', 'reviewer': 'DEMO reviewer', **extra}


class ResourcesTests(unittest.TestCase):
    def test_legacy_shell_gains_casework_route_without_mutating_input(self):
        old='<nav><a href="sf-triage.html">Salesforce</a></nav>'
        updated=navigation(old)
        self.assertIn('href="casework.html"',updated)
        self.assertIn('href="resources.html"',updated)
        self.assertEqual(navigation(updated),updated)
        self.assertNotIn('casework.html',old)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'casework', synthetic=True)

    def project(self, source=None):
        return build(source or capture(), self.store.snapshot(), ASOF, 'synthetic-run')

    def test_rejects_active_schemes_credentials_controls_and_invalid_authority(self):
        for value in (
                'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
                'file:///tmp/local', '//example.invalid',
                'https://user:password@example.invalid/path',
                'https://user@example.invalid/', 'https://example.invalid:bad/',
                'https://example.invalid:70000/', 'https:///',
                ' https://example.invalid/', 'https://example.invalid/has space',
                'https://example.invalid/\nfoo', 'https://example.invalid/%0D%0Afoo',
                'https://example.invalid\\@other.invalid/', None, 2, ''):
            with self.subTest(value=value), self.assertRaises(Invalid):
                safe_url(value)

    def test_rejects_oauth_and_secret_query_or_fragment_even_encoded(self):
        for suffix in (
                '?access_token=synthetic', '#access_token=synthetic',
                '?REFRESH_TOKEN=synthetic', '?id_token=synthetic',
                '?client_secret=synthetic', '?password=synthetic',
                '?authorization=synthetic', '?code=synthetic',
                '?%61ccess_token=synthetic', '#%63ode=synthetic'):
            with self.subTest(suffix=suffix), self.assertRaises(Invalid):
                safe_url('https://example.invalid/callback' + suffix)

    def test_accepts_normal_document_links_and_teams_https_deep_links(self):
        for url in (
                'http://intranet.synthetic.invalid:8080/docs',
                'https://wiki.synthetic.invalid/pages/viewpage.action?pageId=123',
                'https://outlook.office.com/mail/',
                'https://teams.microsoft.com/l/message/19%3Asynthetic/123?context=%7B%22x%22%3A1%7D',
                'https://example.invalid/a%20document#section-2'):
            with self.subTest(url=url):
                self.assertEqual(safe_url(url), url)

    def test_defaults_are_derived_and_do_not_invent_dt_frontend_or_persist(self):
        source = capture()
        source['sources']['dt']['scope']['base'] = 'https://dt-api.synthetic.invalid:15001'
        before = self.store.snapshot()
        rows = {r['id']: r for r in defaults(source)}
        self.assertEqual(rows['resource-jira']['url'], 'https://jira.synthetic.invalid')
        self.assertEqual(rows['resource-salesforce']['url'], 'https://sf.synthetic.invalid')
        self.assertEqual(rows['resource-weekly']['url'], source['weekly_template']['source'])
        self.assertNotIn('https://dt-api.synthetic.invalid:15001', [r['url'] for r in rows.values()])
        self.assertIn('尚未驗證', rows['resource-outlook']['note'])
        self.assertIn('未讀取或傳送', rows['resource-teams']['note'])
        result = self.project(source)
        self.assertTrue(result['synthetic'])
        self.assertEqual(self.store.snapshot(), before)
        self.assertEqual(self.store.records('bookmark'), [])

    def test_invalid_and_missing_source_urls_are_not_presented_as_working_entries(self):
        source = capture()
        source['sources']['jira']['scope'].pop('instance')
        source['sources']['salesforce']['scope']['instance'] = 'javascript:alert(1)'
        source['weekly_template']['source'] = 'https://example.invalid/?access_token=synthetic'
        ids = {r['id'] for r in defaults(source)}
        self.assertFalse(ids & {'resource-jira', 'resource-salesforce', 'resource-weekly'})
        self.assertIn('resource-outlook', ids)

    def test_save_reopen_idempotence_conflict_and_correction_reason(self):
        payload = bookmark()
        saved = self.store.save('bookmark', 'test-link', payload, 0, 'bookmark-create-operation')
        self.assertEqual(saved, self.store.save('bookmark', 'test-link', payload, 0, 'bookmark-create-operation'))
        reopened = Store(self.root / 'casework', synthetic=True)
        self.assertEqual(reopened.get('bookmark', 'test-link'), saved)
        changed = bookmark(title='Revised title', correction_reason='Correct document title')
        with self.assertRaises(Conflict):
            reopened.save('bookmark', 'test-link', changed, 0, 'bookmark-stale-operation')
        with self.assertRaises(Conflict):
            reopened.save('bookmark', 'test-link', changed, 1, 'bookmark-create-operation')
        with self.assertRaises(Invalid):
            reopened.save('bookmark', 'test-link', bookmark(title='Missing reason'), 1, 'bookmark-no-reason-operation')
        updated = reopened.save('bookmark', 'test-link', changed, 1, 'bookmark-edit-operation')
        self.assertEqual(updated['version'], 2)
        self.assertEqual(len(reopened.history('bookmark', 'test-link')), 2)
        self.assertEqual(reopened.history('bookmark', 'test-link')[0]['payload'], payload)

    def test_archive_restore_preserves_identity_history_and_source_default_override(self):
        original = bookmark(title='Team Outlook', url='https://outlook.office.com/mail/', category='collaboration')
        self.store.save('bookmark', 'resource-outlook', original, 0, 'override-default-outlook')
        self.store.save('bookmark', 'resource-outlook', {
            **original, 'status': 'archived', 'correction_reason': 'Temporarily hide'}, 1, 'archive-default-outlook')
        rows = [r for r in self.project()['rows'] if r['id'] == 'resource-outlook']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['payload']['status'], 'archived')
        self.assertEqual(rows[0]['payload']['title'], 'Team Outlook')
        self.store.save('bookmark', 'resource-outlook', {
            **original, 'correction_reason': 'Use this link again'}, 2, 'restore-default-outlook')
        restored = [r for r in self.project()['rows'] if r['id'] == 'resource-outlook'][0]
        self.assertEqual(restored['version'], 3)
        self.assertEqual(restored['payload']['status'], 'active')
        self.assertEqual([r['payload']['status'] for r in restored['revisions']], ['active', 'archived', 'active'])

    def test_validation_does_not_accept_invented_categories_or_unbounded_text(self):
        for update in (
                {'title': ''}, {'title': ' '}, {'title': 'x' * 121},
                {'url': 'javascript:alert(1)'}, {'category': 'other'},
                {'status': 'deleted'}, {'note': 'x' * 1001},
                {'reviewer': ''}, {'category': {}}, {'status': True}):
            with self.subTest(update=update), self.assertRaises(Invalid):
                validate('bookmark', bookmark(**update))

    def test_bookmarks_and_existing_worklog_and_sf_records_are_independent(self):
        work = {'task': 'Synthetic evidence review', 'work_date': '2026-10-21',
                'minutes': 30, 'category': 'verification', 'measurement': 'measured',
                'outcome': 'Reviewed fixture', 'evidence': 'fixture://review'}
        self.store.save('worklog', 'synthetic-work', work, 0, 'preserved-worklog-operation')
        from psirt_casework.inbox import identity
        sf = {'instance': 'https://sf.synthetic.invalid', 'email_id': 'synthetic-mail',
              'source_digest': '0' * 64, 'state': 'pending',
              'next_action': 'Review synthetic email', 'reviewer': 'DEMO reviewer'}
        sf_id = identity(sf['instance'], sf['email_id'])
        self.store.save('sf_email', sf_id, sf, 0, 'preserved-sf-operation')
        source = capture()
        legacy = {'schema': 'psirt-human-review/1', 'reviews': {}}
        before = build_casework(source, self.store.snapshot(), legacy, ASOF)
        preserved = [copy.deepcopy(r) for r in self.store.records()]
        self.store.save('bookmark', 'test-link', bookmark(), 0, 'independent-link-operation')
        after = build_casework(source, self.store.snapshot(), legacy, ASOF)
        self.assertEqual(before['effort'], after['effort'])
        self.assertEqual(before['cases'], after['cases'])
        self.assertEqual([r for r in self.store.records() if r['kind'] != 'bookmark'], preserved)
        self.assertFalse({r['id'] for r in self.project()['rows']} & {'synthetic-work', sf_id})

    def test_read_without_database_has_no_persistence_side_effect(self):
        missing = self.root / 'absent'
        result = build(capture(), read_snapshot(missing, True), ASOF, 'no-database')
        self.assertFalse(missing.exists())
        self.assertGreater(len(result['rows']), 0)

    def test_html_escapes_untrusted_labels_and_contains_the_same_json(self):
        hostile = '</pre><img src="https://evil.invalid/probe" onerror="window.pwned=1"><script>alert(1)</script>'
        self.store.save('bookmark', 'hostile-label', bookmark(title='Unsafe <img>', note=hostile), 0, 'hostile-link-operation')
        data = self.project()
        shell = '<!doctype html><html><head><meta content="default-src \'none\';"><title>PSIRT 工作台</title></head><body><nav><a href="#jira">Jira</a></nav><main>old</main></body></html>'
        readonly = render(shell, data, editable=False)
        editable = render(shell, data, editable=True)
        self.assertNotIn(hostile, readonly)
        self.assertIn('data-editable="false"', readonly)
        self.assertIn('data-editable="true"', editable)
        self.assertIn("connect-src 'self';", editable)
        self.assertNotIn("connect-src 'self';", readonly)
        embedded = re.search(r'<pre id="res-data" hidden>(.*?)</pre>', readonly, re.S).group(1)
        self.assertEqual(json.loads(html.unescape(embedded)), data)
        self.assertIn('href="index.html#jira"', readonly)

    def test_navigation_is_idempotent_and_preserves_existing_module_links(self):
        shell = '<nav><a href="sf-triage.html">SF</a><a href="casework.html">Cases</a></nav><main>same content</main>'
        updated = navigation(shell)
        self.assertEqual(navigation(updated), updated)
        self.assertEqual(updated.count('href="resources.html"'), 1)
        self.assertIn('href="sf-triage.html"', updated)
        self.assertIn('href="casework.html"', updated)
        self.assertTrue(updated.endswith('<main>same content</main>'))


if __name__ == '__main__':
    unittest.main()
