"""Offline checks of refresh injection, policy preservation and hostile metadata."""
import base64
import copy
import hashlib
import json
import sys
import unittest
from html import escape
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework.refresh_web import ASSETS, CSS, enhance, strip


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.policies, self.ids, self.tags, self.scripts, self.styles = [], [], [], [], []
        self.config, self.run, self.inside = '', None, None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if attrs.get('id'):
            self.ids.append(attrs['id'])
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'content-security-policy':
            self.policies.append(attrs.get('content', ''))
        if attrs.get('id') == 'psirt-refresh':
            self.run = attrs.get('data-run-id')
        if attrs.get('id') == 'psirt-refresh-config':
            self.inside = 'config'
        elif tag in ('script', 'style'):
            getattr(self, tag + 's').append('')
            self.inside = tag

    def handle_data(self, value):
        if self.inside == 'config':
            self.config += value
        elif self.inside in ('script', 'style'):
            getattr(self, self.inside + 's')[-1] += value

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'pre'):
            self.inside = None


def shell(policy=None, extra=''):
    policy = policy if policy is not None else "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
    return '<!doctype html><html><head><title>Existing workbench</title><meta http-equiv="Content-Security-Policy" content="' + escape(policy, quote=True) + '">' + extra + '</head><body><nav>Existing navigation</nav><main><section>Existing report</section></main><script>/* existing source */</script></body></html>'


def digest(value):
    return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode()).digest()).decode() + "'"


def directives(policy):
    return {parts[0]: parts[1:] for raw in policy.split(';') if (parts := raw.split())}


class RefreshWebTests(unittest.TestCase):
    def setUp(self):
        self.latest = {'run_id': 'synthetic-run-1', 'captured_at': '2026-10-21T08:00:00+08:00',
                       'mode': 'snapshot-replay', 'synthetic': True,
                       'sources': {'dt': {'status': 'PARTIAL', 'observed_at': '2026-10-19T12:00:00+08:00'}}}

    def test_eight_shell_shapes_preserve_source_and_support_idempotent_enhancement(self):
        shells = [
            shell(),
            shell("default-src 'none'; script-src 'sha256-original'; connect-src 'none'; style-src 'unsafe-inline'"),
            shell("default-src 'none'; script-src 'self'; script-src-elem 'sha256-original'; style-src 'none'; style-src-elem 'none'"),
            shell().replace('<main>', '<main class="workspace" data-kind="report">'),
            shell().replace('http-equiv="Content-Security-Policy"', "HTTP-EQUIV='Content-Security-Policy'"),
            shell().replace('<main>', '<MAIN>').replace('</main>', '</MAIN>').replace('</head>', '</HEAD>').replace('</body>', '</BODY>'),
            '<html><head><title>No prior policy</title></head><body><main><section>Original</section></main></body></html>',
            shell(extra='<meta http-equiv="Content-Security-Policy" content="script-src \'sha256-second\'; connect-src \'none\'">'),
        ]
        for index, original in enumerate(shells):
            with self.subTest(shell=index):
                first = enhance(original, self.latest)
                self.assertEqual(enhance(first, self.latest), first)
                self.assertEqual(strip(first), original)
                self.assertEqual(strip(original), original)
                page = Page(first)
                self.assertEqual(page.run, self.latest['run_id'])
                self.assertEqual(json.loads(page.config)['latest'], self.latest)
                self.assertEqual(len(page.ids), len(set(page.ids)))
                self.assertEqual(page.scripts[-1], (ASSETS / 'refresh.js').read_text())
                self.assertEqual(page.styles[-1], CSS)
                for policy in page.policies:
                    parts = [item.strip().split()[0] for item in policy.split(';') if item.strip()]
                    self.assertEqual(parts.count('script-src'), 1)
                    self.assertEqual(parts.count('connect-src'), 1)
                    values = directives(policy)
                    self.assertEqual(values['connect-src'], ["'self'"])
                    self.assertIn(digest(page.scripts[-1]), values['script-src'])
                    self.assertTrue(digest(CSS) in values['style-src'] or values['style-src'] == ["'unsafe-inline'"])
                    self.assertNotIn("'none'", values['script-src'])

    def test_existing_policy_limits_and_first_duplicate_directive_are_preserved(self):
        original = shell("default-src 'none'; script-src 'sha256-original'; script-src *; img-src data:; frame-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; style-src 'unsafe-inline'")
        values = directives(Page(enhance(original, self.latest)).policies[0])
        self.assertEqual(values['default-src'], ["'none'"])
        self.assertEqual(values['img-src'], ['data:'])
        self.assertEqual(values['frame-src'], ["'none'"])
        self.assertEqual(values['base-uri'], ["'none'"])
        self.assertEqual(values['form-action'], ["'none'"])
        self.assertEqual(values['object-src'], ["'none'"])
        self.assertEqual(values['script-src'][0], "'sha256-original'")
        self.assertNotIn('*', values['script-src'])
        self.assertNotIn("'unsafe-inline'", values['script-src'])

    def test_element_specific_policies_allow_only_added_script_and_style_hashes(self):
        page = Page(enhance(shell("default-src 'none'; script-src-elem 'none'; style-src-elem 'none'"), self.latest))
        values = directives(page.policies[0])
        self.assertEqual(values['script-src-elem'], [digest(page.scripts[-1])])
        self.assertEqual(values['style-src-elem'], [digest(CSS)])

    def test_existing_unsafe_inline_styles_are_not_disabled_by_a_new_hash(self):
        for policy in (
                "default-src 'none'; style-src 'unsafe-inline'",
                "default-src 'none'; style-src 'self' 'unsafe-inline'; style-src-elem 'unsafe-inline'",
                "default-src 'unsafe-inline'; img-src 'none'"):
            with self.subTest(policy=policy):
                original = shell(policy, '<style>.existing{color:rgb(1,2,3)}</style>').replace('<section>Existing report</section>', '<section class="existing" style="display:grid">Existing report</section>')
                output = enhance(original, self.latest)
                page = Page(output)
                values = directives(page.policies[0])
                self.assertIn("'unsafe-inline'", values['style-src'])
                self.assertFalse(any(v.startswith(("'sha", "'nonce-")) for v in values['style-src']))
                if 'style-src-elem' in values:
                    self.assertEqual(values['style-src-elem'], ["'unsafe-inline'"])
                self.assertIn('.existing{color:rgb(1,2,3)}', page.styles)
                self.assertIn('style="display:grid"', output)
                self.assertEqual(strip(output), original)

    def test_existing_nonce_or_hash_style_policy_stays_strict_and_allows_toolbar(self):
        page = Page(enhance(shell("default-src 'none'; style-src 'unsafe-inline' 'nonce-original'; style-src-elem 'sha256-original'"), self.latest))
        values = directives(page.policies[0])
        self.assertEqual(values['style-src'], ["'unsafe-inline'", "'nonce-original'", digest(CSS)])
        self.assertEqual(values['style-src-elem'], ["'sha256-original'", digest(CSS)])

    def test_hostile_run_metadata_is_text_not_html_and_input_is_unchanged(self):
        hostile = '</pre></aside><img src=x onerror="alert(1)"><script>alert(1)</script>&\"\u2028'
        self.latest.update(run_id=hostile, captured_at=hostile)
        self.latest['sources'][hostile] = {'status': hostile, 'observed_at': hostile}
        before = copy.deepcopy(self.latest)
        original = shell()
        actual = enhance(original, self.latest)
        page = Page(actual)
        self.assertEqual(page.run, hostile)
        self.assertEqual(json.loads(page.config)['latest'], before)
        self.assertNotIn('img', page.tags)
        self.assertEqual(len(page.scripts), 2)
        self.assertEqual(self.latest, before)
        self.assertEqual(strip(actual), original)

    def test_new_metadata_replaces_original_loaded_run_without_duplicate_toolbar(self):
        first = enhance(shell(), self.latest)
        updated = {**self.latest, 'run_id': 'synthetic-run-2'}
        actual = enhance(first, updated)
        self.assertEqual(Page(actual).run, 'synthetic-run-2')
        self.assertEqual(actual.count('id="psirt-refresh"'), 1)
        self.assertEqual(actual.count('PSIRT_REFRESH_SCRIPT_BEGIN'), 1)
        self.assertEqual(strip(actual), shell())

    def test_missing_structure_fails_explicitly_instead_of_returning_unwired_toolbar(self):
        for value in ('<main>only partial', '<html><head></head><body>no main</body></html>', '<main></main></body>'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                enhance(value, self.latest)

    def test_injection_follows_main_and_preserves_existing_body_and_navigation(self):
        actual = enhance(shell(), self.latest)
        self.assertLess(actual.index('<main>'), actual.index('id="psirt-refresh"'))
        self.assertLess(actual.index('id="psirt-refresh"'), actual.index('<section>Existing report'))
        self.assertIn('<nav>Existing navigation</nav>', actual)
        self.assertIn('<section>Existing report</section>', actual)
        self.assertIn('<script>/* existing source */</script>', actual)
        self.assertIn('關閉所有工作頁後不會再發起自動更新', actual)
        self.assertNotIn('http://', actual)
        self.assertNotIn('https://', actual)

    def test_editable_fields_and_filters_are_preserved_exactly_during_injection(self):
        content = '''<section data-editable="true"><div class="dt-controls"><input id="sf-search" type="search" value="case 123"><select id="sf-filter"><option selected value="all">全部</option></select></div><form><input name="owner" value="DEMO Owner"><textarea name="draft">Unsent synthetic text &amp; evidence</textarea><input name="password" type="password" value="synthetic-only"></form><div contenteditable="plaintext-only">Unsent note</div></section>'''
        original = shell().replace('<section>Existing report</section>', content)
        updated = enhance(original, self.latest)
        self.assertIn(content, updated)
        self.assertEqual(strip(updated), original)
        page = Page(updated)
        self.assertEqual(page.tags.count('form'), 1)
        self.assertEqual(page.tags.count('textarea'), 1)
        self.assertEqual(json.loads(page.config), {'latest': self.latest})
        self.assertNotIn('Unsent synthetic text', page.config)
        self.assertNotIn('synthetic-only', page.config)

    def test_updated_toolbar_explains_safe_reload_without_claiming_no_refresh(self):
        output = enhance(shell(), self.latest)
        self.assertIn('唯讀頁在可安全套用時自動更新，只保留搜尋與篩選', output)
        self.assertIn('DT 深入分析或翻頁中會保留原頁', output)
        self.assertIn('正在輸入或尚未保存時延後', output)
        self.assertNotIn('資料更新不會自動重載本頁', output)
        page = Page(output)
        self.assertIn('psirt-refresh-shown', page.ids)
        self.assertIn('psirt-refresh-sources', page.ids)
        self.assertIn('psirt-refresh-pending', page.ids)
        self.assertIn('psirt-refresh-apply', page.ids)
        # The response is injected without asserting that an upcoming fetch has
        # already updated the currently rendered report.
        self.assertEqual(page.run, self.latest['run_id'])

    def test_dt_analysis_dom_is_not_rewritten_or_serialized_as_a_saved_filter(self):
        content = '''<section id="dt-statistics"><button data-dt-view="findings" aria-pressed="true">Finding 明細</button><span id="dt-page">2 / 7</span><h3 id="dt-view-title">Finding 明細 · CVE-2026-1234</h3><div id="dt-detail"><pre>Synthetic selected evidence</pre></div></section>'''
        original = shell().replace('<section>Existing report</section>', content)
        output = enhance(original, self.latest)
        self.assertIn(content, output)
        self.assertEqual(strip(output), original)
        self.assertNotIn('Synthetic selected evidence', Page(output).config)
        self.assertIn('id="psirt-refresh-open" target="_blank" rel="noopener noreferrer"', output)


if __name__ == '__main__':
    unittest.main()
