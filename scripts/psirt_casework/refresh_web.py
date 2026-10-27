"""Enhance only active loopback work pages; frozen report bytes stay untouched."""
import base64
import hashlib
import json
import re
from html import escape, unescape
from html.parser import HTMLParser
from pathlib import Path

ASSETS = Path(__file__).with_name('assets')
_META = re.compile(r'<meta\b(?:[^>\"\']|\"[^\"]*\"|\'[^\']*\')*>', re.I)
_BLOCK = re.compile(r'<!--PSIRT_REFRESH_(HEAD|BAR|SCRIPT)_BEGIN-->.*?<!--PSIRT_REFRESH_\1_END-->', re.S)
_POLICY = re.compile(r'<meta name="psirt-refresh-original-policy" content="([^"]*)">')

CSS = '''.psirt-refresh{margin:0 0 18px;padding:12px 15px;border:1px solid #9381b14d;border-radius:12px;background:#201d32;color:#e7dff0;font-size:13px;line-height:1.55}.psirt-refresh-row{display:flex;align-items:center;flex-wrap:wrap;gap:9px 14px}.psirt-refresh button,.psirt-refresh a{font:inherit}.psirt-refresh button{border:1px solid #a18abc;background:#353049;color:#f5edff;border-radius:7px;padding:6px 10px;cursor:pointer}.psirt-refresh button:disabled{opacity:.55;cursor:wait}.psirt-refresh a{color:#e1bfff}.psirt-refresh label{display:inline-flex;align-items:center;gap:6px}.psirt-refresh input{accent-color:#b696ec;width:auto}.psirt-refresh p{margin:5px 0}.psirt-refresh details{margin-top:5px}.psirt-refresh ul{margin:5px 0;padding-left:20px}.psirt-refresh [hidden]{display:none!important}.psirt-refresh-warn{color:#ffdb94}.psirt-refresh :focus-visible{outline:2px solid #e1bfff;outline-offset:3px}'''


class _Attributes(HTMLParser):
    def __init__(self, tag):
        super().__init__(convert_charrefs=True)
        self.attributes = {}
        self.feed(tag)

    def handle_starttag(self, tag, attrs):
        self.attributes = dict(attrs)


def _is_policy(tag):
    attrs = _Attributes(tag).attributes
    return (attrs.get('http-equiv') or '').lower() == 'content-security-policy'


def _digest(value):
    return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode()).digest()).decode() + "'"


def _merge(policy, script_hash, style_hash):
    # Browsers honor the first duplicate directive; retain that meaning.
    directives = {}
    for raw in policy.split(';'):
        parts = raw.split()
        if parts:
            directives.setdefault(parts[0].lower(), parts[1:])
    def allow(values, digest, style=False):
        # A hash/nonce disables CSP's unsafe-inline allowance. Do not accidentally
        # block the existing shell's inline styles and style attributes by adding
        # the toolbar hash to an otherwise permissive style policy.
        strict_inline = any(v.startswith(("'sha256-", "'sha384-", "'sha512-", "'nonce-")) for v in values)
        if style and "'unsafe-inline'" in values and not strict_inline:
            return list(dict.fromkeys(values))
        return list(dict.fromkeys([v for v in values if v != "'none'"] + [digest]))

    for name, digest in [('script-src', script_hash), ('style-src', style_hash)]:
        values = directives.get(name, directives.get('default-src', []))
        directives[name] = allow(values, digest, style=name.startswith('style-'))
    # If element-specific policies exist, they also govern these inline elements.
    for name, digest in [('script-src-elem', script_hash), ('style-src-elem', style_hash)]:
        if name in directives:
            directives[name] = allow(directives[name], digest, style=name.startswith('style-'))
    directives['connect-src'] = ["'self'"]
    return '; '.join(' '.join([key, *values]) for key, values in directives.items())


def strip(shell):
    """Restore the pre-enhancement shell, including its exact CSP meta tags."""
    saved = _POLICY.search(shell)
    if not saved:
        return shell
    policies = json.loads(base64.b64decode(unescape(saved.group(1))).decode())
    index = 0

    def restore(match):
        nonlocal index
        if not _is_policy(match.group()):
            return match.group()
        original = policies[index] if index < len(policies) else ''
        index += 1
        return original

    return _BLOCK.sub('', _META.sub(restore, shell))


def enhance(shell, latest):
    """Add an opt-out refresh toolbar to a current, local HTTP work page."""
    shell = strip(shell)
    main = re.search(r'<main\b[^>]*>', shell, re.I)
    head_end = re.search(r'</head\s*>', shell, re.I)
    body_end = re.search(r'</body\s*>', shell, re.I)
    if not (main and head_end and body_end):
        raise ValueError('Refresh toolbar requires a complete work-page shell')
    script = (ASSETS / 'refresh.js').read_text()
    script_hash, style_hash = _digest(script), _digest(CSS)
    original = []

    def policy(match):
        tag = match.group()
        if not _is_policy(tag):
            return tag
        original.append(tag)
        content = _Attributes(tag).attributes.get('content') or ''
        return '<meta http-equiv="Content-Security-Policy" content="' + escape(_merge(content, script_hash, style_hash), quote=True) + '">'

    shell = _META.sub(policy, shell)
    if not original:
        fallback = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'"
        meta = '<meta http-equiv="Content-Security-Policy" content="' + escape(_merge(fallback, script_hash, style_hash), quote=True) + '">'
        shell = re.sub(r'</head\s*>', lambda match: meta + match.group(), shell, count=1, flags=re.I)
    encoded = base64.b64encode(json.dumps(original, ensure_ascii=False).encode()).decode()
    head = '<!--PSIRT_REFRESH_HEAD_BEGIN--><meta name="psirt-refresh-original-policy" content="' + encoded + '"><style>' + CSS + '</style><!--PSIRT_REFRESH_HEAD_END-->'
    shell = re.sub(r'</head\s*>', lambda match: head + match.group(), shell, count=1, flags=re.I)
    config = json.dumps({'latest': latest}, ensure_ascii=False, separators=(',', ':'))
    run_id = escape(str(latest.get('run_id') or ''), quote=True)
    bar = '''<!--PSIRT_REFRESH_BAR_BEGIN--><aside class="psirt-refresh" id="psirt-refresh" aria-label="資料更新" data-run-id="''' + run_id + '''">
      <div class="psirt-refresh-row"><strong>資料更新</strong><button id="psirt-refresh-now" type="button">立即更新</button><label><input id="psirt-refresh-auto" type="checkbox" checked>開頁期間每 15 分鐘更新</label><span id="psirt-refresh-clock"></span></div>
      <p id="psirt-refresh-state" role="status" aria-live="polite">正在確認本機更新狀態…</p><p id="psirt-refresh-shown"></p>
      <p>讀取與保存本機紀錄本身不取數；自動更新開啟時，頁面依到期狀態觸發既有範圍更新。隔離離線工作頁僅重建報告，不取公司資料。</p>
      <p id="psirt-refresh-pending" class="psirt-refresh-warn" hidden><span id="psirt-refresh-pending-text"></span> <button id="psirt-refresh-apply" type="button">套用更新</button> <a id="psirt-refresh-open" target="_blank" rel="noopener noreferrer" hidden>開啟更新後頁面</a></p>
      <details><summary>本次執行與各來源擷取時間</summary><p id="psirt-refresh-attempt"></p><ul id="psirt-refresh-sources"></ul><p>關閉所有工作頁後不會再發起自動更新；已開始的當輪會繼續完成。服務仍開啟且已到期時，再開工作頁可能立即觸發一輪；不會補跑所有錯過的輪次。唯讀頁在可安全套用時自動更新，只保留搜尋與篩選；DT 深入分析或翻頁中會保留原頁，提供另開更新頁面。正在輸入或尚未保存時延後套用畫面，來源更新仍可執行；編輯內容不會被自動重載清除。</p></details>
      <pre id="psirt-refresh-config" hidden>''' + escape(config) + '''</pre></aside><!--PSIRT_REFRESH_BAR_END-->'''
    shell = re.sub(r'(<main\b[^>]*>)', lambda match: match.group() + bar, shell, count=1, flags=re.I)
    js = '<!--PSIRT_REFRESH_SCRIPT_BEGIN--><script>' + script + '</script><!--PSIRT_REFRESH_SCRIPT_END-->'
    return re.sub(r'</body\s*>', lambda match: js + match.group(), shell, count=1, flags=re.I)
