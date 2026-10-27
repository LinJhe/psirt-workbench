"""Offline wordmark/font checks; preserve report data, styles and old shells."""
import base64
import re
import sys
import unittest
from html import escape
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework import branding, companion


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.policies, self.styles, self.ids = [], [], []
        self.h1, self.style, self.headings = None, None, []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.append(attrs['id'])
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'content-security-policy':
            self.policies.append(attrs['content'])
        if tag == 'h1':
            self.h1 = {'attrs': attrs, 'text': ''}
        if tag == 'style':
            self.style = ''

    def handle_endtag(self, tag):
        if tag == 'h1' and self.h1 is not None:
            self.headings.append(self.h1)
            self.h1 = None
        if tag == 'style' and self.style is not None:
            self.styles.append(self.style)
            self.style = None

    def handle_data(self, data):
        if self.h1 is not None:
            self.h1['text'] += data
        if self.style is not None:
            self.style += data


def shell(policy="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'", head=''):
    return '<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="' + escape(policy, quote=True) + '"><style>.existing{color:purple}</style>' + head + '</head><body><aside class="sidebar"><img class="brand-avatar" src="data:image/png;base64,c3ludGhldGlj" alt="Vance"></aside><header class="page-head"><span class="edition">Original edition</span><h1 id="original-heading">原標題 <span>Casework</span></h1><p>來源擷取 2026-10-19</p></header><main><h1>Existing content heading</h1><p>Original evidence</p></main></body></html>'


def directives(policy):
    return {parts[0]: parts[1:] for part in policy.split(';') if (parts := part.split())}


class BrandingTests(unittest.TestCase):
    def test_font_is_embedded_exactly_with_license_and_no_external_font_fetch(self):
        output = branding.enhance(shell())
        font = re.search(r'data:font/ttf;base64,([A-Za-z0-9+/=]+)', output)
        self.assertIsNotNone(font)
        decoded = base64.b64decode(font.group(1), validate=True)
        self.assertEqual(decoded, (branding.ASSETS / 'UnifrakturCook-Bold.ttf').read_bytes())
        self.assertEqual(decoded[:4], b'\x00\x01\x00\x00')
        self.assertIn('SIL OPEN FONT LICENSE Version 1.1', output)
        self.assertIn('Copyright (c) 2010', output)
        self.assertNotIn('fonts.googleapis.com', output)
        self.assertNotIn('fonts.gstatic.com', output)
        self.assertNotIn('url("https:', output)

    def test_only_page_head_title_changes_avatar_and_data_are_preserved(self):
        original = shell()
        output = branding.enhance(original)
        headings = Page(output).headings
        self.assertEqual([item['text'] for item in headings], ['Product Security Workbench', 'Existing content heading'])
        self.assertEqual(headings[0]['attrs']['class'], 'psirt-brand-title')
        self.assertEqual(headings[0]['attrs']['lang'], 'en')
        self.assertIn('<img class="brand-avatar" src="data:image/png;base64,c3ludGhldGlj" alt="Vance">', output)
        self.assertIn('<p>來源擷取 2026-10-19</p>', output)
        self.assertIn('<p>Original evidence</p>', output)
        self.assertIn('Original edition', output)
        self.assertEqual(branding.strip(output), original)

    def test_idempotence_and_exact_restore_for_policy_and_quote_variants(self):
        samples = [shell(), shell("default-src 'none'; style-src 'unsafe-inline'; font-src 'none'"),
                   shell("default-src 'none'; style-src 'unsafe-inline'; font-src 'self' data:"),
                   shell().replace('http-equiv="Content-Security-Policy"', "HTTP-EQUIV='Content-Security-Policy'"),
                   shell(head='<meta http-equiv="Content-Security-Policy" content="font-src \'self\'; script-src \'none\'">')]
        for original in samples:
            with self.subTest(original=original[:150]):
                first = branding.enhance(original)
                self.assertEqual(branding.enhance(first), first)
                self.assertEqual(branding.strip(first), original)
                self.assertEqual(branding.strip(branding.strip(first)), original)
                self.assertEqual(Page(first).ids.count('psirt-branding-style'), 1)

    def test_only_font_src_changes_unsafe_inline_and_script_hashes_stay_exact(self):
        policy = "default-src 'none'; script-src 'sha256-existing'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'"
        output = branding.enhance(shell(policy))
        values = directives(Page(output).policies[0])
        expected = directives(policy)
        self.assertEqual(values.pop('font-src'), ['data:'])
        self.assertEqual(values, expected)
        self.assertEqual(values['style-src'], ["'unsafe-inline'"])
        self.assertEqual(Page(output).styles[0], '.existing{color:purple}')

    def test_strip_preserves_later_unrelated_script_permission(self):
        original = shell("default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-first'")
        output = branding.enhance(original).replace("'sha256-first'", "'sha256-first' 'sha256-added-later'", 1)
        stripped = branding.strip(output)
        values = directives(Page(stripped).policies[0])
        self.assertEqual(values['script-src'], ["'sha256-first'", "'sha256-added-later'"])
        self.assertNotIn('font-src', values)
        self.assertEqual(Page(stripped).headings, Page(original).headings)

    def test_companion_remains_reversible_and_idempotent_with_new_brand(self):
        # Existing report renderers use literal apostrophes in a double-quoted
        # policy; companion's older CSP normalizer retains that representation.
        original = shell().replace('&#x27;', "'")
        output = companion.enhance(original)
        self.assertEqual(companion.enhance(output), output)
        self.assertEqual(companion.strip(output), original)
        page = Page(output)
        self.assertNotIn('psirt-companion', page.ids)  # Optional licensed images are not distributed.
        self.assertIn('psirt-branding-style', page.ids)
        self.assertEqual(page.headings[0]['text'], branding.TITLE)

    def test_unsupported_shell_is_unchanged(self):
        for original in ('<html><head></head><body></body></html>', shell().replace('class="page-head"', 'class="other"'),
                         '<html><head></head><body><header class="page-head"><h1>Original</h1></header></body></html>'):
            self.assertEqual(branding.enhance(original), original)

    def test_title_css_is_scoped_bold_and_responsive_without_global_font_override(self):
        css = (branding.ASSETS / 'branding.css').read_text()
        self.assertIn('.page-head h1.psirt-brand-title', css)
        self.assertIn('font-family:"UnifrakturCook"', css)
        self.assertIn('font-weight:700', css)
        self.assertIn('font-size:50px', css)
        self.assertIn('font-size:32px', css)
        self.assertIn('max-width:100%', css)
        self.assertNotIn('body{', css)
        self.assertNotIn('!important', css)


if __name__ == '__main__':
    unittest.main()
