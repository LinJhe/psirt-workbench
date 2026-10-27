"""Offline final-page acceptance for the optional local penguin decoration."""
import base64
import hashlib
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from psirt_casework.companion import enhance, strip
from psirt_casework.inbox import build as build_inbox
from psirt_casework.projection import build as build_casework
from psirt_casework.resources import build as build_resources, navigation
from psirt_casework.resources_web import render as render_resources
from psirt_casework.web import render as render_casework
from psirt_ops.dt_statistics import build as build_statistics, render as render_statistics
from psirt_ops.html_report import render as render_index
from psirt_ops.pipeline import compare
from psirt_ops.reports import analyze
from psirt_ops.sf_triage import build as build_triage, render as render_triage
from psirt_sf_fixtures import sample


def script_hash(script):
    return "'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"


class Page(HTMLParser):
    def __init__(self, value):
        super().__init__(convert_charrefs=False)
        self.ids = []
        self.elements = {}
        self.policies = []
        self.scripts = []
        self.script = None
        self.sidebar = False
        self.companion_in_sidebar = False
        self.feed(value)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'aside':
            self.sidebar = 'sidebar' in attrs.get('class', '').split()
        if 'id' in attrs:
            self.ids.append(attrs['id'])
            self.elements[attrs['id']] = (tag, attrs)
        if attrs.get('id') == 'psirt-companion':
            self.companion_in_sidebar = self.sidebar
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'content-security-policy':
            self.policies.append(attrs['content'])
        if tag == 'script':
            self.script = {'attrs': attrs, 'text': ''}
        if tag == 'img' and 'data-animated' in attrs:
            self.image = attrs

    def handle_endtag(self, tag):
        if tag == 'aside':
            self.sidebar = False
        if tag == 'script' and self.script is not None:
            self.scripts.append(self.script)
            self.script = None

    def handle_data(self, value):
        if self.script is not None:
            self.script['text'] += value


@unittest.skipUnless((ROOT / 'psirt-workbench/assets/ppmini/52-5-static.png').exists(),
                     'Optional third-party decoration images are not distributed')
class CompanionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = sample()
        cls.comp = {name: compare(name, source) for name, source in cls.source['sources'].items()}
        cls.review = {'schema': 'psirt-human-review/1', 'reviews': {}}
        cls.manual = {'schema': 'psirt-casework/1', 'synthetic': True,
                      'available': False, 'records': [], 'revisions': []}
        cls.at = cls.source['config']['cutoff']
        analysis = analyze(cls.source, cls.comp, cls.review)
        cls.shell = navigation(render_index(cls.source, analysis, cls.comp,
                                            'snapshot-replay', 'companion-synthetic'))
        cls.casework = build_casework(cls.source, cls.manual, cls.review, cls.at)
        cls.triage = build_triage(cls.source, cls.comp, cls.review,
                                 'companion-synthetic', 'snapshot-replay', cls.at)
        with tempfile.TemporaryDirectory() as root:
            cls.triage['inbox'] = build_inbox(Path(root), cls.source, cls.manual,
                                             cls.comp['salesforce'], 'companion-synthetic', cls.at)
        cls.statistics = build_statistics(cls.source, 'companion-synthetic', 'snapshot-replay')
        cls.resources = build_resources(cls.source, cls.manual, cls.at, 'companion-synthetic')

    def pages(self, shell=None):
        shell = self.shell if shell is None else shell
        yield 'index', shell
        yield 'statistics', render_statistics(shell, self.statistics)
        for editable in (False, True):
            yield 'casework-' + str(editable), render_casework(shell, self.casework, editable)
            yield 'sf-' + str(editable), render_triage(shell, self.triage, editable)
            yield 'resources-' + str(editable), render_resources(shell, self.resources, editable)

    def assert_allowed_scripts(self, page):
        self.assertEqual(len(page.policies), 1)
        directives = [part.split() for part in page.policies[0].split(';') if part.strip()]
        script = [part for part in directives if part[0] == 'script-src']
        self.assertEqual(len(script), 1)
        for item in page.scripts:
            self.assertIn(script_hash(item['text']), script[0])
            self.assertNotIn('src', item['attrs'])
        self.assertNotIn("'unsafe-inline'", script[0])

    def test_final_report_and_interactive_pages_keep_existing_scripts_and_permissions(self):
        for name, raw in self.pages():
            with self.subTest(page=name):
                before, after = Page(raw), Page(enhance(raw))
                self.assert_allowed_scripts(after)
                self.assertEqual(after.ids.count('psirt-companion'), 1)
                self.assertTrue(after.companion_in_sidebar)
                self.assertEqual(after.scripts[:-1], before.scripts)
                self.assertEqual(len(after.scripts), len(before.scripts) + 1)
                self.assertEqual("connect-src 'self'" in after.policies[0], name.endswith('True'))
                self.assertIn("base-uri 'none'", after.policies[0])
                self.assertIn("form-action 'none'", after.policies[0])
                self.assertIn('img-src data:', after.policies[0])
                self.assertEqual(strip(enhance(raw)), raw)

    def test_enhance_is_idempotent_for_every_actual_renderer(self):
        for name, raw in self.pages():
            with self.subTest(page=name):
                once = enhance(raw)
                self.assertEqual(enhance(once), once)
                self.assertEqual(enhance(strip(once)), once)
                self.assertEqual(strip(strip(once)), raw)

    def test_saved_index_can_be_stripped_then_used_by_all_derived_renderers(self):
        stored = enhance(self.shell)
        base = strip(stored)
        self.assertEqual(base, self.shell)
        for (name, derived), (_, expected) in zip(self.pages(base), self.pages(self.shell)):
            with self.subTest(page=name):
                result = enhance(derived)
                self.assertEqual(strip(result), expected)
                self.assert_allowed_scripts(Page(result))
                self.assertEqual(Page(result).ids.count('psirt-companion'), 1)

    def test_uses_original_local_images_and_starts_static_before_script_runs(self):
        page = Page(enhance(self.shell))
        for mode in ('static', 'animated'):
            value = page.image['data-' + mode]
            self.assertTrue(value.startswith('data:image/png;base64,'))
            decoded = base64.b64decode(value.partition(',')[2], validate=True)
            self.assertEqual(decoded, (ROOT / 'psirt-workbench/assets/ppmini' /
                                       ('52-5-' + mode + '.png')).read_bytes())
        self.assertEqual(page.image['src'], page.image['data-static'])
        self.assertEqual(page.image['data-mode'], 'static')
        self.assertEqual(page.image['alt'], '')
        self.assertEqual(page.image['aria-hidden'], 'true')
        button = page.elements['psirt-companion-toggle'][1]
        self.assertEqual(button['type'], 'button')
        self.assertIn('hidden', button)
        self.assertIn('錢錢陪你開工', enhance(self.shell))

    def test_strip_removes_only_own_hash_when_another_script_is_added_later(self):
        existing = render_casework(self.shell, self.casework, True)
        decorated = enhance(existing)
        own = next(s['text'] for s in Page(decorated).scripts
                   if s['attrs'].get('id') == 'psirt-companion-script')
        other = "'sha256-a-separate-feature'"
        decorated = decorated.replace(script_hash(own), script_hash(own) + ' ' + other, 1)
        result = strip(decorated)
        self.assertIn(other, Page(result).policies[0])
        self.assertNotIn(script_hash(own), Page(result).policies[0])
        self.assertEqual(Page(result).scripts, Page(existing).scripts)
        self.assertIn("connect-src 'self'", Page(result).policies[0])

    def test_strip_uses_embedded_script_hash_after_a_module_upgrade(self):
        decorated = enhance(self.shell)
        own = next(s['text'] for s in Page(decorated).scripts
                   if s['attrs'].get('id') == 'psirt-companion-script')
        previous = '/* Previous local decoration version. */'
        decorated = decorated.replace(own, previous).replace(script_hash(own), script_hash(previous))
        self.assertEqual(strip(decorated), self.shell)

    def test_shell_without_sidebar_or_csp_is_unchanged(self):
        no_sidebar = self.shell.replace('class="sidebar"', 'class="different-panel"')
        self.assertEqual(enhance(no_sidebar), no_sidebar)
        plain = '<html><head></head><body><aside class="sidebar"></aside></body></html>'
        self.assertEqual(enhance(plain), plain)
        self.assertEqual(strip(plain), plain)


if __name__ == '__main__':
    unittest.main()
