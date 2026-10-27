"""Nordic presentation layer; all numbers come from the existing report model."""
from html import escape
import json
import re


def text(value):
    return escape('Unknown' if value is None else str(value),quote=True)


STYLE = '''
/* Scandinavian workspace: forest, ivory, ink; no remote assets or scripts. */
body{background:#f5f4ef;color:#243c34;font-family:Segoe UI,Microsoft JhengHei,sans-serif}
.sidebar{width:258px;padding:38px 26px;background:#203e35;border:0;color:#f2f1e7;box-shadow:6px 0 30px #203e3508}
.sidebar .brand-mark{background:#dce5cd;color:#294638;width:45px;height:45px;font-size:14px;border-radius:50%}
.sidebar .text-gray-500{color:#91a99a}.sidebar nav{margin-top:56px;gap:8px}.sidebar nav>div{font-size:10px;letter-spacing:2px;color:#9bb1a3}
.sidebar nav a{font-size:14px;color:#e5eadd;font-weight:400;padding:15px 12px;border:1px solid transparent;border-radius:8px;gap:13px}
.sidebar nav a:hover,.sidebar nav a:focus-visible{color:#fff;background:#355247;border-color:#577060}
.sidebar nav svg{color:#bed0bc;stroke-width:1.3}.sidebar nav .nav-index{color:#93ab99;font-size:10px}
.sidebar-bottom{color:#99afa0;border-color:#486151;font-size:11px;padding-top:23px;line-height:2}
.page-head{margin-left:258px;padding:48px 48px 10px;max-width:1560px}.page-head .eyebrow{font-size:10px;color:#7c8a79;letter-spacing:3px}.page-head h1{font-size:46px;font-weight:500;letter-spacing:-1.7px;color:#243e32;line-height:1.3;margin:22px 0 14px}.page-head p{font-size:13px;color:#7c8577;line-height:1.9}
.edition{background:#e9ede2;color:#687b58;border:0;padding:8px 15px;font-size:10px;letter-spacing:1.5px}
main{margin-left:258px;padding:20px 48px 48px;max-width:1560px}.workspace-links{gap:20px;margin:0 0 25px;grid-template-columns:repeat(3,minmax(0,1fr))}
.workspace-link,.workspace-link:nth-child(2),.workspace-link:nth-child(3){position:relative;background:#fffefa;border:1px solid #e1e5d9;border-radius:14px;padding:24px 26px 20px;box-shadow:0 6px 16px #273c2c03;min-height:195px}
.workspace-link:hover{background:#f9faf2;border-color:#a6b893;transform:translateY(-2px);transition:transform .15s}
.workspace-link .kpi-top{display:flex;align-items:center;justify-content:space-between;gap:8px}.workspace-link .overline{font-size:11px;letter-spacing:1px;color:#66785f;font-weight:500;display:block}
.workspace-link .kpi-dot{height:8px;width:8px;border-radius:50%;background:#8ba87a}.workspace-link:nth-child(2) .kpi-dot{background:#8ca8b5}.workspace-link:nth-child(3) .kpi-dot{background:#bcae8b}
.workspace-link .kpi-number{display:block;font-size:57px;font-weight:300;line-height:1.15;letter-spacing:-2px;color:#375638;margin:22px 0 6px;font-variant-numeric:tabular-nums}.workspace-link:nth-child(2) .kpi-number{color:#5b7d89}.workspace-link:nth-child(3) .kpi-number{color:#8d7e5d}
.workspace-link h3{font-size:13px;font-weight:500;margin:0 0 15px;line-height:1.6;color:#55664d}.workspace-link .kpi-bottom{padding-top:12px;border-top:1px solid #e9ecdf;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#929a85;gap:8px}.workspace-link .arrow{float:none;font-size:19px;color:#7e9272}
.banner{background:#e7ecdf;color:#65794e;font-size:12px;padding:12px 17px;border-radius:7px;display:flex;align-items:center;gap:10px}.banner:before{content:'';width:6px;height:6px;flex:none;border-radius:50%;background:#779f56}.banner.bad{background:#f1e4da;color:#8f654a}.banner.bad:before{background:#b78261}.banner.warn{background:#efe9d9;color:#8f7b4e}.banner.warn:before{background:#ab9457}
.method-note{margin:13px 0 22px;background:transparent;border:0;padding:0}.method-note summary{font-size:11px;color:#909a82}
section{border:1px solid #e5e8dc;border-radius:14px;padding:28px 30px;background:#fffefa;box-shadow:0 5px 16px #273c2c02;margin:24px 0}section:target{outline:1px solid #9ab18a;outline-offset:5px}h2{font-size:22px;font-weight:500;letter-spacing:-.4px;color:#344d38}.section-intro{font-size:12px;color:#8e9782;line-height:1.9;margin:9px 0 20px}
.health{margin:17px 0;padding:12px 0;border-color:#edf0e5;gap:24px}.health>div{font-size:11px;background:transparent;padding:0}.health small{font-size:10px;color:#929c88;line-height:1.9}.tag{font-size:10px;font-weight:400;letter-spacing:.2px}.SUCCESS{background:#e7eedf;color:#6d8757}.FAILED,.PARTIAL{background:#f2e3d6;color:#916b4d}
.metrics{gap:12px;margin:20px 0}.metric{background:#f0f3e9;border-radius:9px;padding:16px 20px;min-width:150px}.metric span{font-size:11px;color:#8a967c}.metric strong{font-size:35px;font-weight:300;color:#657d50;margin-top:6px}.metric:nth-child(2){background:#eef2f3}.metric:nth-child(3){background:#f4f0e6}
article{padding:23px 0;border-color:#e8eddf}article h3{font-size:16px;font-weight:500;color:#3f573b}article p{font-size:13px;color:#58674f;line-height:1.9}article .muted{color:#929b85}.cardgrid{gap:32px}.muted{font-size:12px;color:#929b85}
details{background:#f8faf3;border:1px solid #e7ecde;border-radius:7px;padding:11px 14px;margin:12px 0}summary{font-size:11px;color:#819473}pre{color:#66745d;font-size:12px}footer{font-size:11px;color:#9ca58e;border-top:1px solid #e1e7d9;padding:22px 0}footer a{color:#6e8662}
@media(min-width:1650px){main,.page-head{padding-left:72px;padding-right:72px}}
@media(max-width:1100px) and (min-width:851px){.sidebar{width:218px;padding:32px 18px}.page-head,main{margin-left:218px;padding-left:28px;padding-right:28px}.workspace-links{gap:12px}.workspace-link{padding:20px}.page-head h1{font-size:38px}}
@media(max-width:850px){.sidebar{position:relative;width:100%;padding:22px}.sidebar nav{flex-direction:row;margin-top:20px;gap:3px}.sidebar nav a{padding:10px;font-size:12px}.sidebar nav>div{display:none}.sidebar-bottom{display:none}.page-head{margin:0;padding:26px 22px 8px}.page-head h1{font-size:30px;margin:16px 0 12px}.edition{font-size:9px;padding:6px 10px}main{margin:0;padding:16px 22px 30px}.workspace-links{grid-template-columns:1fr;gap:10px}.workspace-link,.workspace-link:nth-child(2),.workspace-link:nth-child(3){min-height:0;padding:18px 20px}.workspace-link .kpi-number{font-size:40px;margin:8px 0}.workspace-link h3{display:block;font-size:13px;margin:0 0 10px}.workspace-link .kpi-bottom{padding-top:8px}.workspace-link .overline{display:block}.cardgrid{grid-template-columns:1fr}section{padding:22px 20px}}
@media(prefers-reduced-motion:reduce){.workspace-link:hover{transform:none;transition:none}}
/* Data identity survives the shared header used by every report page. */
.page-head p#psirt-data-context{position:relative;z-index:2;display:flex;align-items:baseline;flex-wrap:wrap;gap:3px 12px;width:100%;max-width:100%;margin:3px 0;padding:3px 8px;border-left:3px solid #a9d5c2;background:#17282adb;color:#e1eee8;font:12px/1.4 "Segoe UI","Microsoft JhengHei",sans-serif;letter-spacing:0;overflow-wrap:anywhere;box-sizing:border-box}
.page-head p#psirt-data-context.psirt-data-synthetic{border-color:#ffb6c9;background:#3b1c2ce8;color:#ffe3eb}
.page-head .psirt-data-context strong{font:700 13px/1.4 "Segoe UI","Microsoft JhengHei",sans-serif;color:inherit;letter-spacing:0}
.page-head .psirt-data-context span{color:inherit}
.workspace-link .kpi-note{display:block;line-height:1.65;overflow-wrap:anywhere}
.workspace-link .kpi-bottom>span:first-child{min-width:0}
@media print{.page-head p#psirt-data-context,.page-head p#psirt-data-context.psirt-data-synthetic{color:#222;background:#fff;border-color:#444}}
'''


def data_identity(page, vm, capture):
    """Replace the existing source-time line, rather than adding another hero row."""
    if capture.get('synthetic') is True:
        kind, label = 'synthetic', '合成驗收資料・不得作日常現況'
    elif capture.get('synthetic') is False and vm.get('mode') in ('snapshot-replay', 'report-rebuild'):
        kind, label = 'snapshot', '真實來源快照・未重新取數'
    elif capture.get('synthetic') is False and vm.get('mode') == 'live':
        kind, label = 'live', '真實來源・依擷取時間判讀'
    else:
        kind, label = 'unknown', '來源性質／取數方式待確認'
    banner = ('<p id="psirt-data-context" class="psirt-data-context psirt-data-' + kind + '" data-source-kind="' + kind + '">'
              '<strong>' + text(label) + '</strong><span>來源擷取：' + text(capture.get('captured_at')) + '</span></p>')
    # Retain a <p> here: compact work-page CSS distinguishes the generic intro
    # from the last (source-time) paragraph. Later garden/branding passes retain it.
    header = re.search(r'<header\b[^>]*>.*?</header>', page, re.S)
    if header:
        original = header.group(0)
        amended, replaced = re.subn(r'<p>擷取完成 .*?</p>', lambda _: banner, original, count=1, flags=re.S)
        if not replaced:
            amended = original.replace('</header>', banner + '</header>', 1)
        page = page[:header.start()] + amended + page[header.end():]
    if '<title>PSIRT 工作台' in page:
        # Preserve the prefix that existing sub-page renderers replace with their
        # own page name; the data identity must remain visible in those titles.
        return page.replace('<title>PSIRT 工作台', '<title>PSIRT 工作台【' + text(label) + '】', 1)
    return page.replace('<title>', '<title>【' + text(label) + '】', 1)


def finish(page, vm, data, capture):
    """Replace decorative entry tiles with honest action-oriented overview cards."""
    sf=capture['sources']['salesforce']
    candidates=sum(row['candidate'] for row in data['sf_activity']) if sf['status']=='SUCCESS' and sf['complete'] else None
    query=(vm.get('statistics') or {}).get('periods',{}).get('query',{})
    start=query.get('start',vm.get('window_start'));end=query.get('end',vm.get('cutoff'))
    kev=capture['sources']['kev'];jira=capture['sources']['jira']
    delta=vm['metrics']['kev_added'] if kev.get('status')=='SUCCESS' and kev.get('complete') else None
    scope=jira.get('scope')
    if isinstance(scope,dict) and 'project' in scope:
        scope_label='專案 '+text(scope.get('project'))+'；來源選樣 '+text(scope.get('selection'))
    else:
        scope_label=text(json.dumps(scope,ensure_ascii=False,sort_keys=True) if scope is not None else None)
    kev_foot=('<span class="kpi-note">查詢期間：'+text(start)+' ～ '+text(end)+'</span>'
              '<span class="kpi-note">相較上次新增：'+text(delta)+'；0 不表示沒有既有 KEV。</span>'
              '<span class="kpi-note">來源觀測：'+text(kev.get('observed_at'))+'</span>')
    jira_foot=('<span class="kpi-note">範圍：'+scope_label+'</span>'
               '<span class="kpi-note">來源觀測：'+text(jira.get('observed_at'))+'</span>'
               '<span class="kpi-note">工作流狀態計數；不是漏洞數或修復完成證明。</span>')
    cards=[('kev-dt','KEV / DT',vm['metrics'].get('kev_window'),'查詢期間 KEV · dateAdded',kev_foot),
           ('salesforce','Salesforce',candidates,'開單評估候選','需查重與人工確認'),
           ('jira','Jira',vm['metrics']['jira_open'],'非 Done 工作流工單',jira_foot)]
    markup='<div class="workspace-links" aria-label="優先處理總覽">'
    for anchor,title,value,label,foot in cards:
        markup+=('<a class="workspace-link" href="#'+anchor+'"><div class="kpi-top"><span class="overline">'+title+'</span><span class="kpi-dot" aria-hidden="true"></span></div>'
                 '<strong class="kpi-number" data-overview="'+anchor+'">'+text(value)+'</strong><h3>'+label+'</h3>'
                 '<div class="kpi-bottom"><span>'+foot+'</span><span class="arrow" aria-hidden="true">↗</span></div></a>')
    markup+='</div>'
    start=page.index('<div class="workspace-links">')
    end=page.index('</a></div>',start)+len('</a></div>')
    page=page[:start]+markup+page[end:]
    page=page.replace('</head>','<style data-theme="nordic-forest">'+STYLE+'</style></head>',1)
    page=page.replace('<span class="edition">NORDIC 02 · 本機草稿</span>', '<span class="edition">FOREST / 03 · 本機草稿</span>',1)
    page=page.replace('<h1>PSIRT 工作總覽</h1>','<h1>每日安全工作台</h1>',1)
    return data_identity(page,vm,capture)
