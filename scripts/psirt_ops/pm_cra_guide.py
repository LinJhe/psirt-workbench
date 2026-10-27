"""Generic offline workflow guide for the sanitized sharing edition.

Internal presentations and organization policy are deliberately absent.
The route and renderer interface remain compatible with the local workbench.
"""
import hashlib
import json
import re
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

ASSETS = Path(__file__).with_name('assets')
CONTENT = ASSETS / 'pm-cra-guide-20261021.json'
DOWNLOADS = ()


def load_content():
    data = json.loads(CONTENT.read_text(encoding='utf-8'))
    if data.get('schema') != 'psirt-pm-cra-guide/1':
        raise ValueError('InvalidGuideSchema')
    if [s['id'] for s in data['stages']] != list('ABCDEFG'):
        raise ValueError('InvalidGuideIdentity')
    ids = [s['id'] for s in data['sources']]
    if len(ids) != len(set(ids)):
        raise ValueError('InvalidGuideIdentity')
    for source in data['sources']:
        parsed = urlsplit(source['url'])
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('UnsafeGuideSource')
    for stage in data['stages']:
        if not set(stage['sources']) <= set(ids):
            raise ValueError('MissingGuideSource')
    return data


def content_hash():
    return hashlib.sha256(CONTENT.read_bytes()).hexdigest()


def download_artifacts():
    """The sharing edition does not include internal PDFs or presentations."""
    return {}


def render(shell=None, data=None):
    data = data or load_content()
    if shell:
        prefix = shell.split('<main>', 1)[0]
        prefix = re.sub(r'href="#([^\"]+)"', r'href="index.html#\1"', prefix)
        prefix = re.sub(r'<title>.*?</title>', '<title>PSIRT 流程指南 · 分享版</title>', prefix, count=1)
        prefix = prefix.replace('href="pm-cra-guide.html"', 'href="pm-cra-guide.html" aria-current="page"')
    else:
        prefix = ('<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">'
                  '<meta name="viewport" content="width=device-width,initial-scale=1">'
                  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\';">'
                  '<title>PSIRT 流程指南 · 分享版</title><style>body{font:16px/1.8 sans-serif;background:#f4eff7;color:#34283f}main{max-width:1000px;margin:auto;padding:24px}section{margin:24px 0;padding:24px;border:1px solid #cbb8da;border-radius:8px}a{color:#654181}</style></head><body>')
    e = escape
    out = [prefix, '<main data-guide-edition="share-example" data-content-sha256="'+content_hash()+'">',
           '<section><h1>'+e(data['title'])+'</h1><p>'+e(data['subtitle'])+'</p>',
           '<p class="banner warn">'+e(data['authority'])+'</p>',
           '<p>此頁是固定說明；不表示重新查詢案件或核准公司制度。</p>',
           '<nav aria-label="流程節點">'+' → '.join('<a href="#stage-'+s['id']+'">'+e(s['title'])+'</a>' for s in data['stages'])+'</nav></section>']
    for stage in data['stages']:
        out += ['<section id="stage-'+stage['id']+'"><h2>'+stage['id']+' · '+e(stage['title'])+'</h2>',
                '<dl><dt>輸入</dt><dd>'+e(stage['input'])+'</dd><dt>交付</dt><dd>'+e(stage['output'])+'</dd>',
                '<dt>確認界線</dt><dd>'+e(stage['boundary'])+'</dd></dl></section>']
    out += ['<section><h2>法遵與時程：先確認適用性</h2><ul>',
            *['<li>'+e(item)+'</li>' for item in data['compliance']], '</ul></section>',
            '<section><h2>公開參考與限制</h2>']
    for source in data['sources']:
        out.append('<p><a href="'+e(source['url'], quote=True)+'" target="_blank" rel="noopener noreferrer">'+e(source['title'])+'</a> — '+e(source['note'])+'</p>')
    out += ['<p>版本 '+e(data['version'])+'。分享版不包含公司教材、會議檔案或真實案件。</p></section></main></body></html>']
    return ''.join(out)
