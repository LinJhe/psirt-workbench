"""Reversible, offline page-head branding; never rename a page's data or sources."""
import base64
import json
import re
from html import escape
from html.parser import HTMLParser
from pathlib import Path

ASSETS = Path(__file__).with_name('assets')
TITLE = 'Product Security Workbench'
META = re.compile(r'<meta\b(?:[^>\"\']|\"[^\"]*\"|\'[^\']*\')*>', re.I)
CONTENT = re.compile(r'\bcontent\s*=\s*([\"\'])(.*?)\1', re.I | re.S)
HEADER = re.compile(r'<header\b[^>]*\bclass=[\"\'][^\"\']*\bpage-head\b[^\"\']*[\"\'][^>]*>.*?</header\s*>', re.I | re.S)
H1 = re.compile(r'<h1\b[^>]*>.*?</h1\s*>', re.I | re.S)
BLOCK = re.compile(r'<!--psirt-branding:(head|title):begin-->(.*?)<!--psirt-branding:\1:end-->', re.S)
STATE = re.compile(r'<meta name="psirt-branding-original" content="([^"]*)">')


class _Attributes(HTMLParser):
    def __init__(self, value):
        super().__init__(convert_charrefs=True)
        self.attrs = {}
        self.feed(value)

    def handle_starttag(self, tag, attrs):
        self.attrs = dict(attrs)


def _policy(tag):
    return (_Attributes(tag).attrs.get('http-equiv') or '').lower() == 'content-security-policy'


def _content(tag, policy):
    found = CONTENT.search(tag)
    if not found:
        return tag
    value = escape(policy, quote=False).replace(found.group(1), '&quot;' if found.group(1) == '"' else '&#x27;')
    return tag[:found.start(2)] + value + tag[found.end(2):]


def _font_parts(policy):
    return [part for part in policy.split(';') if part.strip().split() and part.strip().split()[0].lower() == 'font-src']


def _allow_font(policy):
    parts = policy.split(';')
    found = False
    for index, part in enumerate(parts):
        values = part.split()
        if values and values[0].lower() == 'font-src':
            found = True
            if 'data:' not in values:
                parts[index] = ' font-src ' + ' '.join([v for v in values[1:] if v != "'none'"] + ['data:'])
    if not found:
        parts.append(' font-src data:')
    return ';'.join(parts)


def _restore_font(current, before):
    """Remove only our font change if another enhancement changed CSP later."""
    originals = iter(_font_parts(before))
    parts = []
    for part in current.split(';'):
        values = part.strip().split()
        if values and values[0].lower() == 'font-src':
            original = next(originals, None)
            if original is not None:
                # Preserve permissions added later, apart from our own data:.
                extras = [v for v in values[1:] if v != 'data:' and v not in original.split()[1:]]
                parts.append(original + (' ' + ' '.join(extras) if extras else ''))
        else:
            parts.append(part)
    return ';'.join(parts)


def strip(shell):
    saved = STATE.search(shell)
    if not saved:
        return shell
    state = json.loads(base64.b64decode(saved.group(1), validate=True).decode())
    index = 0

    def restore(match):
        nonlocal index
        tag = match.group()
        if not _policy(tag):
            return tag
        if index >= len(state['policies']):
            return tag
        original = state['policies'][index]
        index += 1
        if tag == original['after']:
            return original['before']
        current = _Attributes(tag).attrs.get('content') or ''
        before = _Attributes(original['before']).attrs.get('content') or ''
        return _content(tag, _restore_font(current, before))

    shell = META.sub(restore, shell)
    return BLOCK.sub(lambda match: state['h1'] if match.group(1) == 'title' else '', shell)


def enhance(shell):
    page = strip(shell)
    header = HEADER.search(page)
    heading = H1.search(header.group()) if header else None
    policies = [match for match in META.finditer(page) if _policy(match.group())]
    if not heading or not policies or not re.search(r'</head\s*>', page, re.I):
        return page
    title_start, title_end = header.start() + heading.start(), header.start() + heading.end()
    original_h1 = page[title_start:title_end]
    title = '<!--psirt-branding:title:begin--><h1 class="psirt-brand-title" lang="en">' + TITLE + '</h1><!--psirt-branding:title:end-->'
    page = page[:title_start] + title + page[title_end:]
    changes = []

    def patch(match):
        tag = match.group()
        if not _policy(tag):
            return tag
        policy = _Attributes(tag).attrs.get('content') or ''
        updated = _content(tag, _allow_font(policy))
        changes.append({'before': tag, 'after': updated})
        return updated

    page = META.sub(patch, page)
    state = base64.b64encode(json.dumps({'h1': original_h1, 'policies': changes}, ensure_ascii=False, separators=(',', ':')).encode()).decode()
    font = 'data:font/ttf;base64,' + base64.b64encode((ASSETS / 'UnifrakturCook-Bold.ttf').read_bytes()).decode()
    license_text = (ASSETS / 'UnifrakturCook-OFL.txt').read_text()
    if '*/' in license_text or '</style' in license_text.lower():
        raise ValueError('Font license is not safe as a CSS comment')
    css = '/*\n' + license_text + '\n*/\n' + (ASSETS / 'branding.css').read_text().replace('__PSIRT_BRAND_FONT_DATA__', font)
    block = '<!--psirt-branding:head:begin--><meta name="psirt-branding-original" content="' + state + '"><style id="psirt-branding-style">' + css + '</style><!--psirt-branding:head:end-->'
    return re.sub(r'</head\s*>', lambda match: block + match.group(), page, count=1, flags=re.I)
