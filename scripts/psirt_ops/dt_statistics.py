"""Offline DT occurrence statistics. No requests, database access or source mutation."""
import base64
import hashlib
import json
import re
from datetime import datetime
from html import escape
from pathlib import Path

VERSION = 'dt-statistics/1.1'
CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')
RATED_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFORMATIONAL'}


def build(capture, run_id, mode):
    dt, kev = (capture['sources'][n] for n in ('dt', 'kev'))
    scope = dt.get('scope') or {}
    instance = scope.get('instance', 'Unknown')
    expected = scope.get('project_uuids')
    warnings = []
    projects, components, vulnerabilities, findings = {}, {}, {}, {}

    def identity(*parts):
        return json.dumps(parts, ensure_ascii=False, separators=(',', ':'))

    def project(p):
        if not isinstance(p, dict) or not p.get('uuid'):
            warnings.append('專案 UUID 缺少'); return None
        pid = p['uuid']
        projects.setdefault(pid, {'id': pid, 'name': p.get('name') or pid,
                                 'version': p.get('version'), 'vendor': None})
        return pid

    def component(pid, c):
        if not pid or not c.get('uuid'):
            warnings.append('元件 UUID 缺少'); return None
        key = identity(instance, pid, c['uuid'])
        row = {'key': key, 'id': c['uuid'], 'project': pid, 'name': c.get('name'),
               'version': c.get('version'), 'cpe': c.get('cpe'), 'purl': c.get('purl'),
               'vendor': None}
        if key in components and any(components[key][k] != row[k] for k in ('name', 'version')):
            warnings.append('相同元件身份的名稱／版本衝突')
        components.setdefault(key, row)
        return key

    for p in dt.get('projects', []):
        project(p)
    inventory = set()
    for group in dt.get('components', []):
        pid = group.get('project_uuid')
        if pid in inventory:
            warnings.append('重複元件清單專案')
        inventory.add(pid)
        seen = set()
        for c in group.get('records', []):
            key = component(pid, c)
            if key in seen:
                warnings.append('元件清單重複 UUID')
            seen.add(key)
    inventory_keys = set(components)
    catalog = kev.get('raw') or {}
    kev_ok = kev.get('status') == 'SUCCESS' and kev.get('complete') is True and isinstance(catalog.get('vulnerabilities'), list)
    kev_ids = {r.get('cveID', '').upper() for r in catalog.get('vulnerabilities', [])}
    for raw in dt.get('raw') or []:
        pid = project(raw.get('project'))
        c, v = raw.get('component') or {}, raw.get('vulnerability') or {}
        ck = component(pid, c)
        if ck not in inventory_keys:
            warnings.append('Finding 元件未見於完整元件清單')
        native = v.get('uuid') or (identity(v.get('source'), v['vulnId']) if v.get('source') and v.get('vulnId') else None)
        if not ck or not native:
            warnings.append('Finding 身份不完整'); continue
        vk = identity(instance, native)
        ids = {str(v.get('vulnId') or '').upper()}
        # Only explicit source alias fields; never infer a CVE from a description.
        for alias in v.get('aliases') or []:
            if isinstance(alias, dict):
                ids.add(str(alias.get('cveId') or '').upper())
        cves = sorted(x for x in ids if CVE.fullmatch(x))
        source_severity = v.get('severity')
        severity = str(source_severity or '').strip().upper()
        rated = severity in RATED_SEVERITIES
        vr = {'key': vk, 'id': v.get('vulnId'), 'source': v.get('source'), 'cves': cves,
              'source_severity': source_severity, 'severity_rated': rated,
              'severity': severity if rated else 'UNKNOWN',
              'description': v.get('description') or '', 'cvss': v.get('cvssV3BaseScore'),
              'dt_kev': v.get('isKev'),
              'kev': bool(kev_ids.intersection(cves)) if kev_ok and cves else None}
        if vk in vulnerabilities and vulnerabilities[vk] != vr:
            warnings.append('同一漏洞身份的內容衝突')
        vulnerabilities.setdefault(vk, vr)
        fk = identity(instance, pid, c['uuid'], native)
        if fk in findings:
            warnings.append('重複 Finding 身份；已去重並標示不完整')
        a = raw.get('analysis') or {}
        findings.setdefault(fk, {'key': fk, 'project': pid, 'component': ck,
                                'vulnerability': vk, 'state': a.get('state'),
                                'suppressed': a.get('isSuppressed')})
    if expected is None or set(projects) != set(expected) or inventory != set(expected):
        warnings.append('專案範圍／元件 inventory 未完整對齊')
    if any(p.get('complete') is not True for p in dt.get('pages', [])):
        warnings.append('來源分頁未完整')
    complete = dt.get('status') == 'SUCCESS' and dt.get('complete') is True and not warnings
    fs = list(findings.values()); vs = list(vulnerabilities.values())
    observed = {'components': len(components), 'cves': len({c for v in vs for c in v['cves']}),
                'findings': len(fs), 'projects': len(projects),
                'kev': sum(vulnerabilities[f['vulnerability']]['kev'] is True for f in fs),
                'critical': sum(vulnerabilities[f['vulnerability']]['severity'] == 'CRITICAL' for f in fs)}
    counts = {k: n if complete else None for k, n in observed.items()}
    if not kev_ok or any(v['kev'] is None for v in vs):
        counts['kev'] = None
    unrated = sum(not vulnerabilities[f['vulnerability']]['severity_rated'] for f in fs)
    if unrated:
        counts['critical'] = None
    return {'schema': VERSION, 'run_id': run_id, 'mode': mode, 'synthetic': capture['synthetic'],
            'observed_at': dt.get('observed_at'), 'kev_observed_at': kev.get('observed_at'),
            'kev_catalog': catalog.get('catalogVersion'), 'kev_complete': kev_ok,
            'instance': instance, 'scope': scope, 'scope_note': capture['config'].get('dt_scope_note'),
            'status': 'SUCCESS' if complete else 'FAILED' if dt.get('status') == 'FAILED' else 'PARTIAL',
            'source_status': dt.get('status'), 'complete': complete, 'pages': dt.get('pages', []),
            'warnings': sorted(set(warnings)), 'counts': counts, 'observed_counts': observed,
            'severity_summary': {'known_critical_findings': observed['critical'],
                                 'unrated_findings': unrated},
            'projects': list(projects.values()), 'components': list(components.values()),
            'vulnerabilities': vs, 'findings': fs}


STYLE = '''
.dt-statistics{color:#d6d2e5}.dt-statistics h2{color:#ddc6ff}.dt-statistics p{line-height:1.8}
.sidebar a[aria-current=page]{background:#30223f;border:1px solid #9c78c4;color:#e4caff}
.dt-stats-cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin:22px 0}
.dt-statistics button,.dt-statistics input,.dt-statistics select{font:inherit;color:#e3d9f2;background:#191c2e;border:1px solid #65517d;border-radius:6px;padding:10px;max-width:100%}
.dt-statistics button{cursor:pointer}.dt-statistics button:hover,.dt-statistics button[aria-pressed=true]{background:#352548;border-color:#c4a0f0}
.dt-statistics button:focus-visible,.dt-statistics input:focus-visible,.dt-statistics select:focus-visible{outline:2px solid #a6e7ee;outline-offset:3px}
.dt-stats-cards button{text-align:left;min-width:0}.dt-stats-cards strong{display:block;font:30px/1.5 Consolas,monospace;color:#c5a5ff}.dt-stats-cards span{font-size:12px}
.dt-controls{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}.dt-controls label{font-size:12px;display:grid;gap:6px;min-width:140px}.dt-controls input{width:290px}
.dt-table-scroll{overflow:auto}.dt-table{width:100%;border-collapse:collapse;font-size:13px}.dt-table th,.dt-table td{padding:12px;border-bottom:1px solid #37334a;text-align:left;vertical-align:top}.dt-table th{background:#251e35;color:#d8baf6}.dt-table td{max-width:380px;overflow-wrap:anywhere}.dt-table button{font-size:12px;padding:5px 9px}.dt-table tr:hover{background:#201d30}
#dt-detail{margin:18px 0;padding:18px;border:1px solid #8c69b0;background:#151a2a;border-radius:8px}#dt-detail pre{color:#c9d3e7;max-height:300px}
.dt-pager{display:flex;align-items:center;gap:15px;margin:20px 0}.dt-statistics [hidden]{display:none!important}.dt-note{font-size:12px;color:#b9bfd4}.dt-status{border-left:3px solid #ae8ad8;padding:14px;background:#201c30}.dt-statistics a{color:#bcddec}
@media(max-width:1200px){.dt-stats-cards{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:600px){.dt-stats-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.dt-controls label{width:100%}}
'''


def render(shell, data):
    """Reuse the current header/theme; no SF/Jira payload copied into this page."""
    prefix = shell.split('<main>', 1)[0]
    prefix = re.sub(r'href="#([^\"]+)"', r'href="index.html#\1"', prefix)
    prefix = prefix.replace('<title>PSIRT 工作台', '<title>DT 統計')
    prefix = prefix.replace('href="dt-statistics.html"', 'href="dt-statistics.html" aria-current="page"')
    script = (Path(__file__).with_name('assets')/'dt-statistics-v1.js').read_text()
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    prefix = prefix.replace("default-src 'none';", "default-src 'none'; script-src 'sha256-"+digest+"';")
    prefix = prefix.replace('</head>', '<style>'+STYLE+'</style></head>')
    e = lambda x: escape('待確認／Unknown' if x is None else str(x), quote=True)
    def time(value):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00')).strftime('%Y/%m/%d %H:%M:%S %z')
        except (AttributeError, ValueError):
            return value
    labels = [('components','元件（專案內實體）'),('cves','不同 CVE（已識別）'),('findings','Findings'),
              ('kev','KEV findings'),('critical','Critical findings'),('projects','DT 專案（非產品）')]
    out = [prefix, '<main><section class="dt-statistics" id="dt-statistics"><h2>DT 統計 · 限定範圍</h2>',
           '<p class="dt-status">'+e(data['status'])+' · '+('歷史離線重播；本輪沒有重新查詢 API。' if data['mode']=='snapshot-replay' else '僅本輪授權範圍，非全公司統計。')+
           '<br>DT 來源時間：'+e(time(data['observed_at']))+'<br>KEV 來源時間：'+e(time(data['kev_observed_at']))+' · 目錄 '+e(data['kev_catalog'])+
           '<br>範圍：'+e(data['scope_note'])+'<br>實例：'+e(data['instance'])+'<br>Run：'+e(data['run_id'])+'</p>',
           '<p>Vendor：<b>待確認</b>。目前沒有經覆核的供應商對照；DT 專案不等於產品。</p>',
           '<p class="dt-note">統計涵蓋此快照中的全部 findings（含 suppressed 與 NOT_AFFECTED）。Finding 是元件與漏洞關聯，不等於確認受影響。KEV 以此輪 CISA 目錄比對明確 CVE；不以分數或描述猜測。此處包含既有 KEV，首頁「本輪選樣」只比較其選定窗口，兩者數字不必相等。卡片為範圍總數，下面篩選只改變明細。</p>']
    if data['synthetic']:
        out.append('<p class="banner bad">合成測試資料，不是真實案件。</p>')
    if not data['complete']:
        out.append('<p class="banner bad">來源失敗／分頁或身份資料不完整：總數 Unknown；明細僅為已觀測資料，不代表完整清單。</p>')
    if data['severity_summary']['unrated_findings']:
        out.append('<p class="banner warn">已觀測：已知 Critical '+str(data['observed_counts']['critical'])+
                   ' 筆；未評級 '+str(data['severity_summary']['unrated_findings'])+
                   ' 筆。Critical 總量 Unknown；請以「未評級／未知」篩選查看，原始 severity 保留於明細。</p>')
    out.append('<div class="dt-stats-cards">')
    for key,label in labels:
        out.append('<button type="button" data-dt-view="'+key+'" aria-pressed="false"><span>'+label+'</span><strong data-dt-metric="'+key+'">'+e(data['counts'][key])+'</strong><small>查看'+('已觀測' if data['counts'][key] is None else '對應')+'明細 →</small></button>')
    out += ['</div><div class="dt-controls"><label>搜尋名稱／版本／CVE／UUID<input id="dt-search" type="search" placeholder="輸入 CVE 或元件名稱"></label>',
            '<label>專案<select id="dt-project"><option value="">全部專案</option></select></label>',
            '<label>元件版本<select id="dt-component"><option value="">全部元件版本</option></select></label>',
            '<label>嚴重程度<select id="dt-severity"><option value="">全部</option>'+''.join('<option>'+s+'</option>' for s in ('CRITICAL','HIGH','MEDIUM','LOW','INFO','INFORMATIONAL'))+'<option value="UNKNOWN">未評級／未知</option></select></label>',
            '<label>KEV<select id="dt-kev"><option value="">全部</option><option value="true">是</option><option value="false">否</option><option value="unknown">待確認</option></select></label>',
            '<label>排序<select id="dt-sort"><option value="name">名稱／ID</option><option value="severity">嚴重程度優先</option></select></label>',
            '<button type="button" id="dt-clear">清除篩選</button></div><h3 id="dt-view-title">元件明細</h3>',
            '<p id="dt-results" role="status" aria-live="polite"></p><div id="dt-detail" hidden></div>',
            '<div class="dt-table-scroll" tabindex="0" aria-label="DT 明細表，可左右捲動"><table class="dt-table"><thead id="dt-head"></thead><tbody id="dt-rows"></tbody></table></div>',
            '<div class="dt-pager"><button id="dt-prev" type="button">上一頁</button><span id="dt-page"></span><button id="dt-next" type="button">下一頁</button></div>',
            '<noscript>互動明細需要啟用瀏覽器 JavaScript；統計與來源仍可閱讀，完整明細可開啟下方 JSON。</noscript>',
            '<details><summary>計算規則、完整性與來源分頁</summary><p>元件鍵＝實例＋專案 UUID＋元件 UUID；Finding 鍵另含漏洞 UUID（缺少時使用 source＋vulnId）。不同 CVE 以明確 CVE ID／來源 alias 去重；無 CVE 身份的 native 漏洞不計為 CVE。父子 metrics 不累加、相同 PURL 不刪除跨專案實體。Critical 依來源 severity；KEV 是同輪 CISA 命中 finding 數。缺少 KEV 來源或 CVE 對照時總數 Unknown，仍可查看已知命中。</p><pre>'+e(json.dumps({'scope':data['scope'],'complete':data['complete'],'observed_counts':data['observed_counts'],'warnings':data['warnings'],'pages':data['pages']},ensure_ascii=False,indent=2))+'</pre></details>',
            '<p><a href="dt-statistics.json">統計與明細 JSON（全範圍，非目前篩選）</a> · <a href="capture.json">當輪原始證據</a> · <a href="manifest.json">檔案驗證</a> · <a href="index.html">返回工作總覽</a></p>',
            '<pre id="dt-data" hidden>'+escape(json.dumps(data,ensure_ascii=False,separators=(',', ':')))+'</pre>',
            '</section></main><script>'+script+'</script></body></html>']
    return ''.join(out)
