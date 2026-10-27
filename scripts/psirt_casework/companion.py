"""Optional local decoration for the existing report shell; never fetches data.

Apply enhance() after a page's own renderer. Before reusing an enhanced report
as a shell, strip() removes only this module's blocks and script CSP hash.
"""
import base64
import hashlib
import re
from html import escape, unescape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = Path(__file__).with_name('assets')
IMAGES = ROOT / 'psirt-workbench/assets/ppmini'
BLOCK = re.compile(r'<!--psirt-companion:(style|widget|script):begin-->(.*?)<!--psirt-companion:\1:end-->', re.S)
META = re.compile(r'<meta\b[^>]*>', re.I)
CONTENT = re.compile(r'\bcontent\s*=\s*([\"\'])(.*?)\1', re.I | re.S)
SIDEBAR = re.compile(r'<aside\b[^>]*\bclass=[\"\'][^\"\']*\bsidebar\b[^\"\']*[\"\'][^>]*>.*?</aside\s*>', re.I | re.S)
STYLE = '''
#psirt-companion{display:flex;align-items:center;gap:8px;flex:0 0 auto;margin:14px 0 0;padding:8px 0 0;border-top:1px solid #77638a55;min-width:0}
#psirt-companion img{display:block;width:76px;height:auto;max-width:40%;object-fit:contain;flex:0 0 auto}
#psirt-companion .pc-controls{min-width:0;display:flex;flex-direction:column;gap:5px}
#psirt-companion small{font-size:10px;color:#b8accb;line-height:1.4}
#psirt-companion button{font-family:inherit;font-size:11px;line-height:1.4;color:#eadff8;background:#30233f;border:1px solid #8d70a7;border-radius:5px;padding:5px 7px;cursor:pointer;white-space:normal}
#psirt-companion button:focus-visible{outline:2px solid #dec7ff;outline-offset:3px}
#psirt-companion button:disabled{opacity:.75;cursor:default}
#psirt-companion button[hidden]{display:none}
#psirt-companion[hidden]{display:none}
@media(max-width:850px){#psirt-companion{margin-top:10px;padding-top:6px;max-width:240px}#psirt-companion img{width:60px}}
@media print{#psirt-companion{display:none}}
'''


def _hash(script):
    return "'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"


def _csp(shell, add=None, remove=()):
    """Edit script-src in the existing meta policy, preserving other directives."""
    def meta(match):
        tag = match.group()
        if not re.search(r'http-equiv\s*=\s*[\"\']Content-Security-Policy[\"\']', tag, re.I):
            return tag
        content = CONTENT.search(tag)
        if not content:
            return tag
        policy = unescape(content.group(2))
        parts = policy.split(';')
        found = False
        updated = []
        for part in parts:
            directive = part.strip().split()
            if directive and directive[0].lower() in ('script-src', 'script-src-elem'):
                if directive[0].lower() == 'script-src':
                    found = True
                for token in remove:
                    part = part.replace(' ' + token, '')
                if len(part.split()) == 1 and remove:
                    continue
                if add and add not in part.split():
                    part += ' ' + add
            updated.append(part)
        policy = ';'.join(updated)
        if add and not found:
            policy += (' ' if policy.rstrip().endswith(';') else '; ') + 'script-src ' + add
        value = escape(policy, quote=False)
        value = value.replace(content.group(1), '&quot;' if content.group(1) == '"' else '&#x27;')
        return tag[:content.start(2)] + value + tag[content.end(2):]
    return META.sub(meta, shell)


def strip(shell):
    """Remove our exact blocks and their actual script hashes, not page scripts."""
    from .branding import strip as strip_branding
    shell = strip_branding(shell)
    hashes = []
    for block in BLOCK.finditer(shell):
        if block.group(1) == 'script':
            script = re.search(r'<script\b[^>]*>(.*?)</script\s*>', block.group(2), re.S | re.I)
            if script:
                hashes.append(_hash(script.group(1)))
    result = BLOCK.sub('', shell)
    return _csp(result, remove=hashes) if hashes else result


def enhance(shell):
    """Return an idempotently decorated final page; unsupported shells unchanged."""
    page = strip(shell)
    sidebar = SIDEBAR.search(page)
    if not sidebar or '</head>' not in page or '</body>' not in page or not any(
            re.search(r'http-equiv\s*=\s*[\"\']Content-Security-Policy[\"\']', m.group(), re.I)
            for m in META.finditer(page)):
        return page
    if not all((IMAGES / name).is_file() for name in ('52-5-static.png', '52-5-animated.png')):
        from .branding import enhance as enhance_branding
        return enhance_branding(page)
    script = (ASSETS / 'companion.js').read_text()
    def uri(name):
        return 'data:image/png;base64,' + base64.b64encode((IMAGES / name).read_bytes()).decode()
    static = uri('52-5-static.png')
    animated = uri('52-5-animated.png')
    widget = ('<div id="psirt-companion" data-mode="static">'
              '<img src="' + static + '" data-static="' + static + '" data-animated="' + animated + '" '
              'data-mode="static" alt="" aria-hidden="true" width="340" height="256">'
              '<div class="pc-controls"><small>錢錢陪你開工</small>'
              '<button id="psirt-companion-toggle" type="button" aria-pressed="false" hidden>播放企鵝</button>'
              '</div></div>')
    def block(kind, body):
        return '<!--psirt-companion:' + kind + ':begin-->' + body + '<!--psirt-companion:' + kind + ':end-->'
    end = re.search(r'</aside\s*>$', sidebar.group(), re.I).start() + sidebar.start()
    page = page[:end] + block('widget', widget) + page[end:]
    page = page.replace('</head>', block('style', '<style id="psirt-companion-style">' + STYLE + '</style>') + '</head>', 1)
    page = page.replace('</body>', block('script', '<script id="psirt-companion-script">' + script + '</script>') + '</body>', 1)
    from .branding import enhance as enhance_branding
    return enhance_branding(_csp(page, add=_hash(script)))
