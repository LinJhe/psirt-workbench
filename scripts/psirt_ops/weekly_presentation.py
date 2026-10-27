"""Report-only presentation rules and an example six-table presentation structure.

No capture/review mutation, no API access. Company judgments remain with humans.
"""
import copy
import hashlib
import json
import re
from datetime import date
from html import escape
from pathlib import Path
from .sf_messages import email_coverage

ROOT=Path(__file__).resolve().parents[2]
DEFAULT=ROOT/'doc/psirt-weekly-presentation/report-presentation.json'
TEMPLATE=Path(__file__).with_name('assets')/'weekly-company-template-v1.json'


def load_presentation(path=None):
    p=Path(path) if path else DEFAULT
    if not p.exists():
        if path:raise ValueError('PresentationFileMissing')
        return {'schema':'psirt-weekly-presentation/1','meetings':{},'overrides':[]}
    obj=json.loads(p.read_text())
    if obj.get('schema')!='psirt-weekly-presentation/1':raise ValueError('UnsupportedPresentationSchema')
    if not isinstance(obj.get('meetings'),dict) or not isinstance(obj.get('overrides'),list):raise ValueError('InvalidPresentationConfig')
    for day,meeting in obj['meetings'].items():
        date.fromisoformat(day)
        if not isinstance(meeting,dict):raise ValueError('InvalidMeeting')
    for r in obj['overrides']:
        date.fromisoformat(r['report_date'])
        if not re.fullmatch(r'Q-\d{6}-\d+',r['case_number']) or r.get('exclude') is not True or not r.get('decision_source'):
            raise ValueError('InvalidPresentationOverride')
    return obj


def value(v):
    return '待確認／Unknown' if v is None or v=='' else str(v)


def build(capture,analysis,triage,presentation,report_date):
    from .statistics import build as build_statistics
    statistics = analysis.get('statistics') or build_statistics(capture, {})
    date.fromisoformat(report_date)
    template=json.loads(TEMPLATE.read_text());blocks=copy.deepcopy(template['blocks'])
    meeting=presentation.get('meetings',{}).get(report_date,{})
    rules=[r for r in presentation.get('overrides',[]) if r['report_date']==report_date and r['exclude']]
    excluded={r['case_number'] for r in rules};sfrows=[];suppressed=[]
    sources=capture['sources'];jira=sources['jira'];jira_ok=jira.get('status')=='SUCCESS' and jira.get('complete') is True
    mail_coverage=email_coverage(sources['salesforce'])
    issues={r['key']:r for r in jira.get('raw') or []}
    def issue_row(row,external):
        f=row['fields'];summary=f.get('summary');number=re.search(r'Q-\d{6}-\d+',summary or '')
        from psirt_casework.effective import summary as manual_summary
        text=manual_summary(analysis.get('effective_manual',{}).get('cases',{}).get(row['key']))
        if text: summary=(summary or '')+'\n'+text
        cells=[row['key'],number.group() if number else None,summary] if external else [row['key'],summary,(f.get('priority') or {}).get('name')]
        return [value(x) for x in cells+[f.get('status',{}).get('name'),(f.get('assignee') or {}).get('displayName'),f.get('updated')]]
    # Report issues selected by explicit case references in their summaries.
    # No hard-coded organization issue list is included in this share edition.
    reported = [issue_row(row, True) for row in issues.values()
                if re.search(r'Q-\d{6}-\d+', row.get('fields', {}).get('summary', ''))]
    for row in triage['rows']:
        if not set(row['tags'])&{'new_case','incoming','outbound'}:continue
        if row['classification'].startswith('一般通知'):continue
        number=row['number']
        if number in excluded:suppressed.append({'case_number':number,'case_id':row['id'],'target':'weekly_reported_sf_row'});continue
        refs=row['jira']['evidence'];link='、'.join(r['key']+'（引用候選）' for r in refs) if refs else '指定範圍未找到' if jira_ok else 'Unknown · Jira '+value(jira.get('status'))
        f=row['fields'];sfrows.append([link,value(number),'通報主張／待覆核：'+value(f['Subject']['value']),
                                      'SF 原始：'+value(f['Status']['value'])+'；待覆核',value(f['accepted_by']['value']),value(f['LastModifiedDate']['value'])])
    if not mail_coverage['complete']:
        sfrows.append(['Unknown','Salesforce','郵件資料不完整；來信與回覆數待確認，已觀測案件仍保留。',
                       'Unknown · EmailMessage','待確認',value(sources['salesforce'].get('observed_at'))])
    sbom=[[label,'Unknown','只涵蓋快照明示的 DT 範圍；此表不推定組織全量。'] for label in template['sbom_labels']]
    kev=[];kev_ok=statistics['kev']['counts']['window'] is not None
    dt_ok=statistics['kev_dt']['complete']
    projects={f.get('project',{}).get('uuid'):f.get('project',{}).get('name','Unknown') for f in sources['dt'].get('raw') or []}
    for r in analysis['kev_window']:
        hits={projects.get(f['project_id']) or f['project_id'] or 'Unknown' for f in statistics['kev_dt']['findings'] if r['cveID'].upper() in f['cve_ids']}
        match='、'.join(sorted(hits))+'（已觀測候選，非已確認受影響）'+('；完整總數 Unknown' if not dt_ok else '') if hits else '本輪已取得範圍未命中；組織影響 Unknown' if kev_ok and dt_ok else 'Unknown；來源不完整'
        kev.append([value(r.get(k)) for k in ('cveID','vendorProject','product','vulnerabilityName','dateAdded','dueDate')]+[match])
    if not kev:kev=[['日期窗內 0 筆' if kev_ok else 'Unknown · KEV '+value(sources['kev'].get('status')),'','','','','','公司影響 Unknown']]
    open_rows=[issue_row(r,False) for r in analysis['open_issues']]
    for r in analysis.get('unknown_issues', []):
        row = issue_row(r,False)
        row[3] += '（狀態分類待確認；不併入非 Done 計數）'
        open_rows.append(row)
    if not open_rows and not jira_ok:open_rows=[['Unknown','本輪 Jira 資料未取得','','Unknown · '+value(jira.get('status')),'Unknown','Unknown']]
    from psirt_casework.effective import summary as manual_summary
    for key,record in analysis.get('effective_manual',{}).get('cases',{}).items():
        text=manual_summary(record)
        if key not in issues and record.get('record_version') and text:
            open_rows.append([key,'本機追蹤；不代表已確認未結案\n'+text,'Unknown','Unknown · 本輪來源未取得','待確認／Unknown','待確認／Unknown'])
    for b in blocks:
        key=b.get('key')
        if key=='meeting':
            b['rows']=[[label,value(v)] for label,v in zip(template['meeting_labels'],[report_date,meeting.get('time'),meeting.get('location',template['location']),meeting.get('host'),meeting.get('recorder'),meeting.get('attendees','')])]
            b['rows'][-1][1]=meeting.get('attendees','')
        elif key=='reported':b['rows']=reported+sfrows
        elif key=='sbom':b['rows']=sbom
        elif key=='kev':b['rows']=kev
        elif key=='jira_open':b['rows']=open_rows
        elif key=='jira_count':b['text']='1. 未結案（'+(str(statistics['jira']['counts']['open'])+' 筆' if statistics['jira']['counts']['open'] is not None else 'Unknown')+'）— 依非 Done 工作流分類，非漏洞數'
    return {'schema':'psirt-weekly-view/1','report_date':report_date,'blocks':blocks,
            'audit':{'template_sha256':hashlib.sha256(TEMPLATE.read_bytes()).hexdigest(),'applied_overrides':rules,
                     'excluded_sf_rows':suppressed,'source_window':{k:capture['config'].get(k) for k in ('window_start','cutoff')},
                     'source_status':{k:s['status'] for k,s in sources.items()},'statistics':statistics,
                     'sf_email_coverage':mail_coverage,'meeting_configured':bool(meeting)}}


def markdown(model):
    def cell(x):return escape(str(x)).replace('|','\\|').replace('\n','<br>')
    out=[]
    for b in model['blocks']:
        if b['type']=='heading':out+=['#'*b['level']+' '+b['text'],'']
        elif b['type']=='paragraph':out+=[b['text'],'']
        elif b['type']=='list':out+=['- '+x for x in b['items']]+['']
        elif b['type']=='table':
            out+=['| '+' | '.join(cell(x) for x in b['headers'])+' |','|'+'|'.join('---' for _ in b['headers'])+'|']
            out+=['| '+' | '.join(cell(x) for x in row)+' |' for row in b['rows']];out+=['']
    return '\n'.join(out)+'\n'


def html(model):
    out=['<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Weekly PSIRT '+escape(model['report_date'])+'</title><style>body{font:15px/1.6 sans-serif;margin:24px;color:#192038}table{border-collapse:collapse;width:100%;display:block;overflow:auto;margin:12px 0 24px}td,th{border:1px solid #ccd0db;padding:9px;text-align:left;min-width:65px}th{background:#eeeaf4}td{max-width:800px;overflow-wrap:anywhere}h2{margin-top:28px}h3{margin-top:18px}</style></head><body>']
    for b in model['blocks']:
        if b['type']=='heading':out.append(f'<h{b["level"]}>'+escape(b['text'])+f'</h{b["level"]}>')
        elif b['type']=='paragraph':out.append('<p>'+escape(b['text'])+'</p>')
        elif b['type']=='list':out.append('<ul>'+''.join('<li>'+escape(x)+'</li>' for x in b['items'])+'</ul>')
        elif b['type']=='table':out.append('<table><tbody><tr>'+''.join('<th>'+escape(x)+'</th>' for x in b['headers'])+'</tr>'+''.join('<tr>'+''.join('<td>'+escape(str(x)).replace('\n','<br>')+'</td>' for x in row)+'</tr>' for row in b['rows'])+'</tbody></table>')
    return ''.join(out)+'</body></html>'
