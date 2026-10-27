"""Local, script-free HTML view of the existing analysis; never fetches data."""
import html
import json
import hashlib
from datetime import datetime
from pathlib import Path
from .reports import sf_recommendation, source_url
from .decision_guide import attach as attach_decision_guide, case_link
from .kev_learning import attach as attach_kev_learning


def esc(value):
    return html.escape('待確認／Unknown' if value is None or value == '' else str(value), quote=True)


def fold(label, value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
    return '<details><summary>'+esc(label)+'</summary><pre>'+esc(text)+'</pre></details>'


def readable_time(value):
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00')).strftime('%Y/%m/%d %H:%M:%S %z')
    except (ValueError, AttributeError):
        return value


def model(capture, data, comparisons, mode, run_id):
    from .sf_messages import email_coverage
    from .statistics import build as build_statistics
    sources = capture['sources']
    statistics = data.get('statistics') or build_statistics(capture, comparisons)
    kev, jira, matches = (statistics[n]['counts'] for n in ('kev', 'jira', 'kev_dt'))
    def count(name, value):
        src = sources[name]
        return value if src['status']=='SUCCESS' and src['complete'] else None
    metrics = {
        'kev_catalog':kev['catalog'], 'kev_window':kev['window'],
        'kev_week':kev['week'], 'kev_added':kev['added'],
        'dt_matches':matches['findings'], 'dt_cves':matches['cves'], 'dt_projects':matches['projects'],
        'sf_week_new':count('salesforce',sum(r['new_case_in_window'] for r in data['sf_activity'])),
        'sf_week_messages':email_coverage(sources['salesforce'])['count'],
        'sf_added':(comparisons['salesforce'].get('counts') or {}).get('added'),
        'sf_email_added':(comparisons['salesforce'].get('email_counts') or {}).get('added'),
        'jira_window_new':jira['window_created'], 'jira_window_updated':jira['window_updated'],
        'jira_week_new':jira['week_created'], 'jira_week_updated':jira['week_updated'],
        'jira_open':jira['open'], 'jira_total':jira['total'], 'jira_done':jira['done'],
        'jira_unknown':jira['unknown'], 'jira_added':jira['added'],
    }
    return {'schema':'psirt-html-view/2','run_id':run_id,'mode':mode,'synthetic':capture['synthetic'],
            'captured_at':capture['captured_at'],'window_start':capture['config']['window_start'],
            'cutoff':capture['config']['cutoff'],'metrics':metrics,
            'sf_email_coverage':email_coverage(sources['salesforce']), 'statistics':statistics,
            'statuses':{n:s['status'] for n,s in sources.items()}}


STYLE = '''
:root{font-family:Segoe UI,Microsoft JhengHei,sans-serif;color:#34464d;background:#f5f6f3;line-height:1.75;scroll-behavior:smooth}
body{margin:0}.sidebar{position:fixed;inset:0 auto 0 0;width:236px;background:#e9efed;border-right:1px solid #d7e1dd;padding:32px 22px;display:flex;flex-direction:column;z-index:10}
.brand-mark{background:#647f79;color:#fff;width:42px;height:42px;border-radius:13px;display:grid;place-items:center;font-weight:600;letter-spacing:1px}
.sidebar nav{display:flex;flex-direction:column;gap:8px;margin-top:38px}.sidebar nav a{padding:12px 14px;color:#415d60;border-radius:9px;font-size:14px;font-weight:600}
.sidebar nav a:hover,.sidebar nav a:focus-visible{background:#d8e4df;color:#23473e}.nav-index{font-size:11px;color:#7a918b;margin-right:12px}.sidebar-bottom{margin-top:auto;padding-top:30px;border-top:1px solid #d4dfda;color:#637b74;font-size:12px}
.page-head{margin-left:236px;padding:40px 40px 12px;max-width:1450px}.page-head h1{font-size:30px;font-weight:600;letter-spacing:-.7px;color:#304742;margin:12px 0}.page-head p{color:#72807d;margin:6px 0;font-size:13px}
main{max-width:1450px;margin-left:236px;padding:16px 40px 40px}h2{margin:0;font-size:22px;font-weight:600;letter-spacing:-.4px;color:#38544e}h3{margin:5px 0;font-size:16px;font-weight:600}
section{background:#fff;border:1px solid #e1e7e1;border-radius:16px;padding:28px;margin:26px 0;scroll-margin-top:24px;box-shadow:0 2px 8px #314d4010}section:target{outline:2px solid #b4cbc1;outline-offset:4px}
.banner{padding:14px 18px;border-radius:10px;border:1px solid #d0e0d7;background:#eaf2eb;color:#4b6859;font-size:14px}.warn{background:#f7f0e4;border-color:#e9dcc3;color:#806845}.bad{background:#f7eae6;border-color:#e8cfc5;color:#915c4a}
.health,.metrics{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}.health>div{flex:1;min-width:170px;background:#f6f8f6;padding:12px 16px;border-radius:10px;font-size:13px}.metric{flex:1;min-width:150px;border:1px solid #e0e8e4;background:#f7faf9;padding:16px 18px;border-radius:12px}
.metric strong{display:block;font-size:28px;font-weight:500;color:#4e716c;letter-spacing:-1px}.metric span{font-size:12px;color:#768780}.muted{color:#76847e;font-size:13px}.tag{font-size:11px;display:inline-block;padding:2px 8px;border-radius:5px;background:#edf1f2;color:#59717b;margin:0 6px 4px 0;font-weight:500}
.SUCCESS{background:#e3eee4;color:#54725c}.FAILED,.PARTIAL{background:#f3e2dc;color:#956652}
article{border-top:1px solid #e8ede9;padding:20px 0}article p{margin:7px 0;font-size:14px}.cardgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:26px}
details{background:#f8f9f7;border:1px solid #e5eae4;border-radius:9px;margin:12px 0;padding:11px 15px}summary{cursor:pointer;font-size:13px;font-weight:500;color:#61776f;display:list-item}summary:focus-visible{outline:2px solid #8cab9d;outline-offset:4px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.8 Consolas,Microsoft JhengHei,monospace;max-height:500px;overflow:auto;padding-top:12px}a{color:#507184;overflow-wrap:anywhere}small{display:block;font-size:11px;color:#7c8881}footer{font-size:12px;color:#77837c;margin:28px 0}ul{padding-left:23px}
@media(max-width:850px){.sidebar{position:relative;width:100%;padding:20px}.sidebar nav{flex-direction:row;flex-wrap:wrap;margin-top:15px;gap:3px}.sidebar nav a{padding:8px}.sidebar-bottom{display:none}.page-head{margin:0;padding:24px 20px 8px}main{margin:0;padding:12px 20px}.cardgrid{grid-template-columns:1fr}section{padding:20px}.page-head h1{font-size:25px}}
@media(prefers-reduced-motion:reduce){:root{scroll-behavior:auto}}

/* Nordic 02: warm paper, forest accents, stronger typography and clear rhythm. */
body{background:#f6f5f1;color:#303c36;font-family:Segoe UI,Microsoft JhengHei,sans-serif;font-size:15px}
.sidebar{width:244px;background:#efeee8;border-color:#e1e0d7;padding:36px 24px}
.brand-mark{background:#35594b;border-radius:12px;width:44px;height:44px}
.sidebar nav{margin-top:48px;gap:7px}.sidebar nav a{font-size:15px;font-weight:500;padding:14px 12px;display:flex;align-items:center;gap:12px;color:#48534c}
.sidebar nav a:hover{background:#e2e7dd}.sidebar nav svg{width:19px;height:19px;flex-shrink:0;color:#698174}
.sidebar nav .nav-index{margin-left:auto;margin-right:0;color:#889288}.sidebar-bottom{color:#7b8278;border-color:#dadcd1;line-height:1.9}
.page-head{margin-left:244px;padding:44px 44px 8px;max-width:1500px}.page-head h1{font-size:38px;letter-spacing:-1.2px;font-weight:600;margin:10px 0 12px;color:#263e32;line-height:1.35}
.page-head p{font-size:14px;color:#737c71}.page-head .eyebrow{font-size:11px;letter-spacing:2.5px;color:#7d897b}
.head-top{display:flex;align-items:center;justify-content:space-between;gap:20px}.edition{border:1px solid #d9ded3;border-radius:30px;padding:5px 12px;font-size:11px;letter-spacing:1px;color:#7a8574;background:#fafaf6}
main{margin-left:244px;padding:16px 44px 44px;max-width:1500px}.workspace-links{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin:0 0 24px}
.workspace-link{padding:24px;border:1px solid #dfe4d9;border-radius:13px;background:#fffefa;color:#364c3e;display:block;box-shadow:0 2px 4px #53614405}
.workspace-link:hover{border-color:#93aa92;background:#f2f6ee}.workspace-link .overline{font-size:10px;letter-spacing:2px;color:#86917e;text-transform:uppercase}.workspace-link h3{font-size:19px;line-height:1.5;margin:12px 0 8px}.workspace-link p{font-size:12px;color:#7c8375;margin:0;line-height:1.8}
.workspace-link .arrow{float:right;color:#6e8667;font-size:22px;font-weight:300}.workspace-link:nth-child(2){background:#f1f4f5;border-color:#dce4e7}.workspace-link:nth-child(3){background:#f3f1e9;border-color:#e5e1d5}
.banner{border:0;border-radius:8px;background:#e8eee2;color:#58704b;font-size:13px;padding:12px 18px;line-height:1.8}.bad{background:#f4e6df;color:#8f5946}.warn{background:#f5eddb;color:#8a7246}
main>.muted{margin:14px 0 24px}.method-note{margin:12px 0 24px;background:transparent;border:0;padding:0 3px}.method-note summary{color:#87907f;font-size:12px}.method-note p{font-size:13px;padding:12px 0;max-width:950px}
section{border:1px solid #e6e7df;background:#fffefa;border-radius:14px;padding:28px 30px;margin:26px 0;box-shadow:none}h2{font-size:23px;font-weight:600;color:#314d3e}
.section-intro{font-size:13px;color:#7b8476;margin:8px 0 22px}.health{gap:20px;margin:16px 0;padding:12px 0;border-top:1px solid #eceee5;border-bottom:1px solid #eceee5}.health>div{background:transparent;padding:0;min-width:180px;font-size:12px}.health small{font-size:11px;line-height:1.9;color:#8a9283}
.metrics{gap:14px;margin:22px 0}.metric{border:0;background:#f2f4ed;border-radius:10px;padding:18px 20px;min-width:155px}.metric strong{font-size:40px;color:#4c6c50;font-weight:400;line-height:1.5;margin-top:5px}.metric span{font-size:12px;color:#7b8672}
.metric:nth-child(2){background:#eef2f3}.metric:nth-child(2) strong{color:#617b8b}.metric:nth-child(3){background:#f3f0e8}.metric:nth-child(3) strong{color:#8d8267}
.tag{font-size:10px;background:#ecf0e9;color:#6a7b60;border-radius:5px}.SUCCESS{background:#e6eede;color:#667b55}.FAILED,.PARTIAL{background:#f2e0d5;color:#945b40}
article{padding:23px 0;border-color:#e7e9df}article h3{font-size:17px;color:#344d3e}.cardgrid{gap:30px}article p{font-size:14px;line-height:1.9}.muted{color:#85907c}.section-intro + .health{margin-top:8px}
details{border-color:#e5e8de;background:#f8f9f3;border-radius:7px;padding:12px 15px;margin:12px 0}summary{color:#748267;font-size:12px;font-weight:500}pre{font-size:12px;line-height:1.9;color:#59654f}footer{color:#909884;padding-top:12px;font-size:12px}a{color:#587364}
@media(min-width:1600px){main,.page-head{padding-right:70px;padding-left:70px}}
@media(max-width:1000px) and (min-width:851px){main,.page-head{padding-left:25px;padding-right:25px}.workspace-links{gap:10px}.workspace-link{padding:17px}.workspace-link h3{font-size:16px}}
@media(max-width:850px){.sidebar{position:relative;width:100%;padding:20px 24px}.sidebar nav{margin-top:18px;gap:5px}.sidebar nav a{padding:8px;font-size:13px}.sidebar nav .nav-index{display:none}.page-head{margin:0;padding:26px 22px 8px}.page-head h1{font-size:29px}.edition{font-size:9px}main{margin:0;padding:12px 22px 30px}.workspace-links{grid-template-columns:1fr;gap:10px}.workspace-link{padding:16px 20px}.workspace-link h3{display:inline;margin-right:14px;font-size:17px}.workspace-link .overline{display:none}.workspace-link p{display:inline}section{padding:23px 20px}.metric strong{font-size:32px}.sidebar-bottom{display:none}.sidebar nav>div{display:none}}
'''


def tailwind():
    assets=Path(__file__).with_name('assets')
    css=(assets/'tailwind-2.2.19.min.css').read_bytes()
    provenance=json.loads((assets/'provenance.json').read_text())
    if hashlib.sha256(css).hexdigest()!=provenance['tailwind-2.2.19.min.css']['sha256']:
        raise ValueError('TailwindAssetHashMismatch')
    license_text=(assets/'TAILWIND-LICENSE.txt').read_text()
    return '/* '+license_text+' */\n'+css.decode()


def render(capture, data, comparisons, mode, run_id):
    vm = model(capture,data,comparisons,mode,run_id)
    sources = capture['sources']
    sources_complete = all(s['status']=='SUCCESS' and s['complete'] for s in sources.values())
    statistics = vm['statistics']
    statistics_complete = all(statistics[n]['complete'] for n in ('kev','jira','kev_dt')) and not statistics['jira']['keys']['unknown']
    complete = sources_complete and vm['sf_email_coverage']['complete'] and statistics_complete
    week = statistics['periods']['calendar_week']
    week_label = str(week['start'])+' ～ '+str(week['end'])
    def metric(key,label):
        value=vm['metrics'][key]
        target = ('jira-count-evidence' if key.startswith('jira_') else
                  'dt-match-evidence' if key.startswith('dt_') else
                  {'kev_window':'kev-window-evidence', 'kev_week':'kev-week-evidence',
                   'kev_added':'kev-delta-evidence', 'kev_catalog':'kev-catalog-evidence'}.get(key))
        content = f'<span>{esc(label)}</span><strong data-metric="{key}">{esc(value)}</strong>'
        if target: content = '<a href="#'+target+'">'+content+'</a>'
        return '<div class="metric">'+content+'</div>'
    def kev_list(kind, label):
        rows = {r.get('cveID'):r for r in (sources['kev'].get('raw') or {}).get('vulnerabilities', [])}
        ids = statistics['kev']['ids'][kind]
        table = '<table><thead><tr><th>CVE</th><th>原廠／產品</th><th>漏洞名稱</th><th>加入目錄日期</th></tr></thead><tbody>'
        for key in ids or []:
            r = rows.get(key, {})
            table += '<tr data-kev="'+esc(key)+'"><td>'+esc(key)+'</td><td>'+esc(r.get('vendorProject'))+' / '+esc(r.get('product'))+'</td><td>'+esc(r.get('vulnerabilityName'))+'</td><td>'+esc(r.get('dateAdded'))+'</td></tr>'
        table += '</tbody></table>'
        if not ids: table = '<p>'+('Unknown：來源／比較未完整。' if statistics['kev']['counts'][kind] is None else '此範圍為 0；不代表目錄沒有既有 KEV。')+'</p>'
        return '<div id="kev-'+('delta' if kind=='added' else kind)+'-evidence"><details><summary>'+esc(label)+'</summary>'+table+'</details></div>'
    def health(names):
        items=[]
        for name in names:
            src=sources[name]
            items.append('<div><b>'+esc(name.upper())+'</b> <span class="tag '+esc(src['status'])+'">'+esc(src['status'])+'</span><small>觀測 '+esc(readable_time(src.get('observed_at')))+'</small><small>'+('分頁已讀完' if src['complete'] else '分頁／來源未完整，請查看證據')+'</small></div>')
            if name == 'salesforce' and not vm['sf_email_coverage']['complete']:
                items.append('<div class="banner warn">EmailMessage 郵件覆蓋待確認；已觀測 '+str(vm['sf_email_coverage']['observed_count'])+' 筆，不代表完整總數。Case 索引狀態與郵件完整性分開判斷。</div>')
        return '<div class="health">'+''.join(items)+'</div>'
    def evidence(names):
        return fold('查詢範圍、分頁、錯誤與比較基準', {n:{'source':{k:v for k,v in sources[n].items() if k in ('scope','pages','errors','observed_at','source_updated_at','source_version','complete')},
                    'comparison':comparisons[n]} for n in names})
    def sf_card(row):
        c=row['case']
        messages=[{'Id':m['Id'],'MessageDate':m.get('MessageDate'),'Incoming':m.get('Incoming'),'Status':m.get('Status'),'TextBody':m.get('TextBody')} for m in row['messages']]
        return ('<article data-case="'+esc(c['CaseNumber'])+'"><h3>'+esc(c['CaseNumber'])+'</h3><p>'+esc(c.get('Subject'))+'</p>'
                '<p><span class="tag">'+esc(c.get('Status'))+'</span> '+esc(sf_recommendation(row))+'</p>'
                '<p class="muted">Jira 引用：'+esc(', '.join(row['jira_keys']))+' · 本窗口訊息 '+esc(row['message_count'])+('（已觀測 '+str(len(messages))+' 筆）' if row['message_count'] is None else '')+'</p>'
                +fold('回覆原文與關聯證據',{'case':c,'link_evidence':row.get('link_evidence'), 'messages':messages})+'</article>')
    def jira_card(a):
        target = source_url(capture, 'jira', a['key'])
        title = ('<a href="'+esc(target)+'">'+esc(a['key'])+'</a>') if target else esc(a['key'])
        return ('<article data-issue="'+esc(a['key'])+'"><h3>'+title+' <span class="tag">'+esc(a['status_raw'])+'</span></h3>'
                '<p>Assignee：'+esc(a['assignee'])+' <span class="muted">（非承接證明）</span></p>'
                '<p>已確認接收者：'+esc(a['accepted_by'])+'</p><p>下一步：'+esc(a['source_next_action'])+'</p>'
                '<p class="muted">系統建議：'+esc(a['suggested_action'])+'</p><p>追蹤日：'+esc(a['next_follow_up_at'])+' · 修補期限：'+esc(a['remediation_due_at'])+'</p>'
                +case_link(a['key'])+fold('最新來源、卡點背景與覆核欄位',a)+'</article>')
    label=('四來源完整取得；草稿待人工覆核' if complete else
           'Salesforce 郵件覆蓋待確認：Case 索引成功不代表郵件完整，郵件統計為 Unknown' if sources_complete and not vm['sf_email_coverage']['complete'] else
           '來源已回應，統計欄位或識別資料仍有缺口：請查看 Unknown 的計數證據' if sources_complete else
           '本輪來源 FAILED／PARTIAL：只顯示本次已取得內容，完整統計為 Unknown')
    out=['<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
         '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
         '<title>PSIRT 工作台 · '+esc(run_id)+'</title><style data-framework="tailwind-2.2.19">'+tailwind()+'</style><style>'+STYLE+'</style></head><body class="antialiased">',
         '<aside class="sidebar" aria-label="左側導覽"><div class="flex items-center gap-3"><div class="brand-mark">PSIRT</div><div><div class="font-semibold tracking-wide">PSIRT</div><div class="text-xs text-gray-500">Product Security</div></div></div>',
         '<nav aria-label="報告區域"><div class="px-3 text-xs tracking-widest text-gray-500 uppercase mb-2">工作總覽</div><a href="#kev-dt"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/></svg>KEV / DT<span class="nav-index">01</span></a><a href="#salesforce"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 6 9 7 9-7"/></svg>Salesforce<span class="nav-index">02</span></a><a href="#jira"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>Jira<span class="nav-index">03</span></a>',
         '<div class="px-3 text-xs tracking-widest text-gray-500 uppercase mt-6 mb-2">報告與證據</div><a href="Weekly_PSIRT_Company_Format.md">Weekly 範例模板</a><a href="Vance_Action_List.md">完整行動清單</a><a href="manifest.json">執行紀錄</a></nav>',
         '<div class="sidebar-bottom"><div class="font-medium mb-2">唯讀觀測 · 本機草稿</div><div>每輪獨立保存<br>確認證據，再決定下一步。</div></div></aside>',
         '<header class="page-head"><div class="head-top"><div class="eyebrow">PRODUCT SECURITY</div><span class="edition">NORDIC 02 · 本機草稿</span></div><h1>PSIRT 工作總覽</h1>',
         '<p>依這份資料確認待辦，從漏洞線索、外部通報到工程追蹤。</p>',
         '<p>擷取完成 '+esc(readable_time(vm['captured_at']))+' · '+esc(mode)+'</p>',
         '</header><main>',
         '<div class="workspace-links"><a class="workspace-link" href="#kev-dt"><div class="overline">VULNERABILITY SIGNALS</div><span class="arrow">↗</span><h3>KEV / DT</h3><p>新增漏洞線索與產品範圍</p></a><a class="workspace-link" href="#salesforce"><div class="overline">EXTERNAL REPORTS</div><span class="arrow">↗</span><h3>Salesforce</h3><p>通報、回覆與開單評估</p></a><a class="workspace-link" href="#jira"><div class="overline">ENGINEERING FOLLOW-UP</div><span class="arrow">↗</span><h3>Jira</h3><p>負責人、承接與下一步</p></a></div>',
         '<div class="banner '+('' if complete else 'bad')+'">'+label+'</div>']
    if mode=='snapshot-replay':out.append('<p class="banner warn">歷史 snapshot-replay：顯示原擷取時間，沒有重新查詢 API。</p>')
    if capture['synthetic']:out.append('<p class="banner bad">合成測試資料，不是真實案件。</p>')
    out += ['<details class="method-note"><summary>統計期間、執行版本與數字讀法</summary><p>查詢期間 '+esc(vm['window_start'])+' ～ '+esc(vm['cutoff'])+'<br>資料截止當週 '+esc(week_label)+'（台北週一起算；平台顯示慣例）<br>Run '+esc(run_id)+'<br>原始擷取時間 '+esc(vm['captured_at'])+'<br>相較上次只比較同範圍完整基準。首次、失敗及不相容基準顯示 Unknown，不當作零。命中與原始狀態都不是正式安全判定。</p></details>',
            '<section id="kev-dt"><h2>01　KEV / DT</h2><p class="section-intro">既有 KEV、期間加入目錄與本次差異分開；新增 0 不代表沒有 KEV。</p>',health(('kev','dt')),
            '<p>查詢期間 '+esc(vm['window_start'])+' ～ '+esc(vm['cutoff'])+'<br>資料截止當週 '+esc(week_label)+'</p>',
            '<div class="metrics">'+metric('kev_catalog','目錄總數 · 不同 CVE')+metric('kev_window','查詢期間加入 · dateAdded')+metric('kev_week','資料截止當週加入 · dateAdded')+metric('kev_added','相較上次 · KEV 新增')+'</div>',
            '<p class="muted">dateAdded 是 CISA 加入目錄的日期，只有日精度，不是首次公開或首次遭利用日期。比較基準觀測：'+esc(comparisons['kev'].get('last_successful_at'))+' → '+esc(sources['kev'].get('observed_at'))+'。</p>',
            kev_list('window','查詢期間 KEV 清單'),kev_list('week','資料截止當週 KEV 清單'),kev_list('added','相較上次新增清單'),
            '<div id="kev-catalog-evidence">'+fold('目錄計數與版本證據', {'count':statistics['kev']['counts']['catalog'],'observed':statistics['kev']['observed_counts']['catalog'],'declared_rows':statistics['kev'].get('declared_rows'),'observed_rows':statistics['kev'].get('observed_rows'),'warnings':statistics['kev']['warnings'],'catalogVersion':(sources['kev'].get('raw') or {}).get('catalogVersion'),'dateReleased':(sources['kev'].get('raw') or {}).get('dateReleased'),'source':'capture.json#/sources/kev/raw'})+'</div>',
            '<h3>既有 KEV 對照 DT</h3><p>完整已取得 KEV 目錄 × '+esc(capture['config']['dt_scope_note'])+'；含既有線索，重跑不因新增 0 而消失。</p>',
            '<div class="metrics">'+metric('dt_cves','命中 · 不同 CVE')+metric('dt_matches','命中 · 不同 finding')+metric('dt_projects','命中 · DT 專案（非產品）')+'</div>',
            '<p class="muted">僅識別碼候選，不等於產品受影響、未修復或已遭攻擊；須覆核版本、analysis 與證據。</p>']
    if not statistics['kev_dt']['complete']:out.append('<p class="banner bad">來源失敗／分頁或識別資料不完整：完整命中總數 Unknown；以下只列已觀測線索，不能下無命中結論。</p>')
    out.append('<div id="dt-match-evidence">'+fold('已觀測候選與原始證據定位（非完整總數）',statistics['kev_dt'])+'<a href="dt-statistics.html">前往 DT 統計查看元件與漏洞明細</a></div>')
    out += [evidence(('kev','dt')),'</section>',
            '<section id="salesforce"><h2>02　Salesforce</h2><p class="section-intro">先看需要回覆、查重與開單評估的通報，再查看其他收件。</p>',health(('salesforce',)),
            '<div class="metrics">'+metric('sf_week_new','查詢期間新 Case · created')+metric('sf_week_messages','查詢期間 EmailMessage · 含自動回覆')+metric('sf_added','相較上次 · Case 新增')+metric('sf_email_added','相較上次 · 訊息新增')+'</div>',
            '<p class="muted">含 Closed 案；候選需查重與人工評估。未找到 Jira 不代表必須開單。來源不完整時，以下只是已觀測部分。</p>']
    priority=[r for r in data['sf_activity'] if r['candidate'] or r['jira_keys'] or r['intake_hint']=='EXISTING_HANDLING_STATED_KEY_UNVERIFIED']
    priority.sort(key=lambda r:(not r['candidate'],bool(r['jira_keys']),r['case']['CaseNumber']))
    out += [sf_card(r) for r in priority]
    if not priority:out.append('<p>已取得資料中未列優先處理項目；先確認來源完整性。</p>')
    rest=[r for r in data['sf_activity'] if r not in priority]
    out.append('<details><summary>其他收件與通知 · 已觀測 '+str(len(rest))+' 案</summary>'+''.join(sf_card(r) for r in rest)+'</details>')
    out += [evidence(('salesforce',)),'</section><section id="jira"><h2>03　Jira</h2><p class="section-intro">對齊負責人、實際承接與下一份交付證據。</p>',health(('jira',)),
            '<div class="metrics">'+metric('jira_open','非 Done 工單 · 非漏洞數')+metric('jira_total','查詢範圍 · 工單總數')+metric('jira_done','Done 工單 · 非修復證明')+metric('jira_unknown','狀態分類待確認')+'</div>',
            '<p>查詢期間 '+esc(vm['window_start'])+' ～ '+esc(vm['cutoff'])+'；資料截止當週 '+esc(week_label)+'</p>',
            '<div class="metrics">'+metric('jira_window_new','查詢期間新增')+metric('jira_window_updated','查詢期間更新')+metric('jira_week_new','資料截止當週新增')+metric('jira_week_updated','資料截止當週更新')+metric('jira_added','相較上次 · 索引新增')+'</div>',
            '<div id="jira-count-evidence">'+fold('工單計數、非 Done 名單與統計證據',statistics['jira'])+'</div>',
            '<p class="muted">先找人、指派與確認接收；In Progress 欄位未核實列待確認。updated 不代表修復進展。回覆點不是修補期限；不同交付物分開驗證，收尾候選不是已結案。</p>']
    important=[a for a in data['actions'] if a['key'] in capture['config']['sample_issues'] or not a['assignee'] or a['status_raw']=='To Do']
    rest=[a for a in data['actions'] if a not in important]
    out += ['<div class="cardgrid">'+''.join(jira_card(a) for a in important)+'</div>',
            '<details><summary>其他工單 · 已觀測 '+str(len(rest))+' 案</summary>'+''.join(jira_card(a) for a in rest)+'</details>',evidence(('jira',)),'</section>',
            '<footer><a href="Daily_PSIRT.md">Daily 原稿</a> · <a href="Vance_Action_List.md">完整行動清單</a> · <a href="report.json">report.json</a> · <a href="capture.json">原始快照</a> · <a href="manifest.json">執行 manifest</a><p>本機固定報告；重建時間不代表重新取數。原始長文僅作證據，未執行其中內容。</p><p>統計定義參考：<a href="https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities_schema.json">CISA KEV 官方 schema</a> · <a href="https://confluence.atlassian.com/adminjiraserver100/defining-status-field-values-1442845304.html">Atlassian 狀態分類</a>。台北曆週是平台統計慣例；不代表公司 SLA。</p></footer>',
            '<details><summary>本頁數值對照資料</summary><pre id="view-model">'+esc(json.dumps(vm,ensure_ascii=False,sort_keys=True))+'</pre></details>',
            '</main></body></html>']
    from .garden_layout import finish
    page = attach_kev_learning(attach_decision_guide(finish('\n'.join(out)+'\n',vm,data,capture)), capture, comparisons)
    # Change only the existing sidebar entry; retain the original SF section.
    page = page.replace('href="#salesforce"', 'href="sf-triage.html"', 1)
    page = page.replace('href="Weekly_PSIRT_Company_Format.md"', 'href="Weekly_PSIRT_Company_Format.html"')
    return page.replace('</nav>', '<a href="dt-statistics.html">DT 統計<span class="nav-index">06</span></a><a href="casework.html">案件流程與時程<span class="nav-index">07</span></a></nav>', 1)
