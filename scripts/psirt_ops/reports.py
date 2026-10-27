"""Deterministic Daily/Weekly/action drafts. Source excerpts are not decisions."""
import json
import re
from .sf_messages import email_items, email_coverage
from .statistics import build as build_statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
from urllib.parse import quote, urlsplit


def source_url(capture, source, identifier):
    """Use only an explicitly captured HTTPS origin; never assume a tenant."""
    scope = capture.get('sources', {}).get(source, {}).get('scope')
    base = scope.get('instance') if isinstance(scope, dict) else None
    if not isinstance(base, str) or '\\' in base or any(ord(c) <= 32 or ord(c) == 127 for c in base):
        return None
    try:
        parsed = urlsplit(base)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.query or parsed.fragment or parsed.path not in ('', '/'):
            return None
        _ = parsed.port
    except ValueError:
        return None
    path = '/browse/' if source == 'jira' else '/lightning/r/Case/'
    suffix = '' if source == 'jira' else '/view'
    return base.rstrip('/') + path + quote(str(identifier), safe='') + suffix


def cell(value):
    if value is None or value == '':
        return '待確認／Unknown'
    return str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('|','\\|').replace('\r',' ').replace('\n','<br>')


def in_window(value, cfg):
    if not value:
        return False
    return datetime.fromisoformat(cfg['window_start']) <= datetime.fromisoformat(value.replace('Z','+00:00')) <= datetime.fromisoformat(cfg['cutoff'])


def excerpt(value, limit=350):
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False) if value else ''
    return re.sub(r'\s+', ' ', value).strip()[:limit]


def link(key, capture=None):
    target = source_url(capture or {}, 'jira', key)
    return f'[{cell(key)}]({target})' if target else cell(key)


def analyze(capture, comparisons, review):
    sources, cfg = capture['sources'], capture['config']
    statistics = build_statistics(capture, comparisons)
    jira, sf, kev, dt = (sources[n] for n in ('jira','salesforce','kev','dt'))
    issues = jira.get('raw') or []
    detail = jira.get('details', {})
    open_keys = set(statistics['jira']['keys']['open'])
    unknown_keys = set(statistics['jira']['keys']['unknown'])
    # One issue per key. Missing workflow categories remain visible for review.
    unique_issues = {r['key']: r for r in issues}
    new_issues = [unique_issues[key] for key in statistics['jira']['keys']['window_created']]
    updated = [unique_issues[key] for key in statistics['jira']['keys']['window_updated']]
    open_issues = [r for key, r in unique_issues.items() if key in open_keys]
    unknown_issues = [r for key, r in unique_issues.items() if key in unknown_keys]
    explicit, primary = {}, {}
    for row in issues:
        key = row['key']
        f = detail.get(key, row)['fields']
        for number in set(re.findall(r'Q-\d{6}-\d+', f.get('summary',''))):
            primary.setdefault(number,set()).add(key)
        texts = [f.get('summary',''), f.get('description','')]
        texts += [c.get('body','') for c in f.get('comment',{}).get('comments',[])]
        for text in texts:
            for number in set(re.findall(r'Q-\d{6}-\d+', str(text))):
                explicit.setdefault(number, set()).add(key)
    sf_rows = []
    emails = [row for _,row in email_items(sf)]
    for case in sf.get('raw') or []:
        messages = [m for m in emails if m.get('ParentId') == case['Id']]
        is_new = in_window(case.get('CreatedDate'), cfg)
        if not messages and not is_new:
            continue
        own = case['CaseNumber']
        refs = {own}
        link_evidence = []
        for message in messages:
            numbers = set(re.findall(r'Q-\d{6}-\d+', str(message.get('TextBody',''))))
            refs.update(numbers)
            for number in sorted(numbers):
                keys = sorted(primary.get(number, explicit.get(number, set())))
                if keys:
                    link_evidence.append({'email_id':message['Id'], 'referenced_case':number, 'jira_keys':keys})
        matches = sorted(set().union(*(primary.get(n, explicit.get(n,set())) for n in refs)))
        # Transparent intake hints, not a vulnerability or spam adjudication.
        subject = case.get('Subject','')
        security_hint = bool(re.search(r'PSIRT|vulnerab|credential|authentication|lockout|security report|overflow|XSS',subject,re.I))
        notification_hint = bool(re.search(r'messages in quarantine',subject,re.I))
        duplicate_note = any(not m.get('Incoming') and 'previously reported' in m.get('TextBody','').lower() for m in messages)
        intake = ('EXISTING_HANDLING_STATED_KEY_UNVERIFIED' if duplicate_note else
                  'AUTOMATED_NOTIFICATION_SUBJECT_HINT' if notification_hint else
                  'SECURITY_SUBJECT_HINT' if security_hint else 'INTAKE_REVIEW_REQUIRED')
        sf_rows.append({'case': case, 'new_case_in_window': is_new, 'messages': messages,
                        'message_count':len(messages) if email_coverage(sf)['complete'] else None,
                        'jira_keys': matches, 'link_status': 'EXPLICIT_CASE_REFERENCE' if matches else 'NO_LINK_FOUND_NEEDS_REVIEW',
                        'link_evidence':link_evidence, 'intake_hint':intake,
                        'candidate': not matches and security_hint and not notification_hint and not duplicate_note,
                        'link_search_scope': 'all issue summaries + selected details/comments + explicit case IDs in window emails; not all historical comments'})
    raw_kev = kev.get('raw') or {}
    kev_rows = {r.get('cveID', '').upper():r for r in raw_kev.get('vulnerabilities', [])}
    window_kev = [kev_rows[key] for key in statistics['kev']['ids']['window']]
    changes = comparisons['kev'].get('changes')
    candidates = changes['added'] if changes is not None else window_kev
    basis = 'COMPATIBLE_BASELINE_DIFF' if changes is not None else 'DATE_ADDED_WINDOW_NOT_DIFF'
    matches = []
    candidate_ids = {r['cveID'] for r in candidates}
    for finding in dt.get('raw') or []:
        vulnerability = finding.get('vulnerability', {})
        ids = {vulnerability.get('vulnId')}
        ids.update(a.get('cveId') for a in vulnerability.get('aliases', []) if isinstance(a,dict))
        hits = candidate_ids & ids
        for cve in sorted(hits):
            matches.append({'cve': cve, 'finding': finding, 'classification': 'CANDIDATE_ONLY',
                            'evidence': 'capture.json#/sources/dt/raw (id='+finding['id']+')'})
    background = {r['票號']: r for r in capture.get('background',{}).get('rows',[])}
    actions = []
    action_issues = [r for r in unique_issues.values() if r in open_issues or r in unknown_issues or r['key'] in cfg['sample_issues']]
    for row in action_issues:
        key = row['key']; issue = detail.get(key, row); f = issue['fields']
        comments = f.get('comment',{}).get('comments',[])
        latest = max(comments, key=lambda c:c.get('updated', c.get('created','')), default=None)
        assignee = f.get('assignee')
        human = review.get('reviews',{}).get(key,{})
        # Values from review are kept visibly separate and need explicit evidence.
        verified = human.get('verification') == 'VERIFIED_BY_HUMAN' and bool(human.get('evidence_ref')) and bool(human.get('reviewer'))
        status = f.get('status',{}).get('name')
        reasons = []
        normal_flow = '依來源狀態持續追蹤'
        if status == 'To Do':
            normal_flow = '先確認工作歸屬、指派與接收；不自動轉狀態'
        elif status == 'In spec evaluate':
            normal_flow = '保留原狀態，確認產品方案與承接範圍'
        if jira['status'] != 'SUCCESS':
            reasons = ['SOURCE_INCOMPLETE']
        elif status == 'In Progress':
            if assignee is None:
                reasons.append('MISSING_ASSIGNEE')
            if not (verified and human.get('accepted_by')):
                reasons.append('OWNER_ACCEPTANCE_UNVERIFIED')
            if not (verified and human.get('source_next_action')):
                reasons.append('FIELD_UNVERIFIED_NEXT_ACTION')
            if not (verified and (human.get('next_follow_up_at') or human.get('remediation_due_at'))):
                reasons.append('FIELD_UNVERIFIED_TRACKING_DATE')
        historical = background.get(key, {})
        actions.append({'key': key, 'status_raw': status,
                        'assignee': (assignee or {}).get('displayName'),
                        'latest_source_excerpt': excerpt(latest.get('body')) if latest else excerpt(f.get('description')),
                        'latest_source_comment_id': latest.get('id') if latest else None,
                        'latest_source_time': latest.get('updated') if latest else f.get('updated'),
                        'source_detail_fetched': key in detail,
                        'source_due_date': f.get('duedate'),
                        'source_finish_eta': f.get('customfield_11504'),
                        'accepted_by': human.get('accepted_by') if verified else None,
                        'source_next_action': human.get('source_next_action') if verified else None,
                        'next_follow_up_at': human.get('next_follow_up_at') if verified else None,
                        'remediation_due_at': human.get('remediation_due_at') if verified else None,
                        'human_review': human, 'human_review_verified': bool(verified),
                        'suggested_action': historical.get('下一步') or '確認接收者、下一交付物及由窗口提出的追蹤日。',
                        'background_as_of': capture.get('background', {}).get('as_of') if historical else None,
                        'background_gap': historical.get('缺口'),
                        'background_owner': historical.get('已確認 Owner／待確認窗口'),
                        'background_evidence': historical.get('已具備證據'),
                        'normal_flow': normal_flow, 'review_reasons': reasons,
                        'evidence_ref': 'capture.json#/sources/jira/'+('details/'+key if key in detail else 'raw (key='+key+')')})
    return {'new_issues': new_issues, 'updated_issues': updated, 'open_issues': open_issues,
            'unknown_issues': unknown_issues, 'statistics': statistics,
            'sf_activity': sf_rows, 'kev_window': window_kev, 'kev_candidates': candidates,
            'kev_basis': basis, 'kev_dt_matches': matches,
            'kev_dt_complete': all(s.get('status') == 'SUCCESS' and s.get('complete') is True for s in (kev, dt)), 'actions': actions}


def health_lines(capture, comparisons):
    lines = ['| 來源 | 狀態 | 觀測時間 | 完整性 | 前次完整成功時間 | 比較 |', '|---|---|---|---|---|---|']
    for name, src in capture['sources'].items():
        diff = comparisons[name]
        lines.append('| '+' | '.join(cell(x) for x in (name,src['status'],src.get('observed_at'),src.get('complete'),diff.get('last_successful_at'),diff['comparison']))+' |')
    return lines


def action_markdown(capture, data):
    lines = ['# Action List — 未發布草稿', '',
             '來源狀態與 Assignee 是觀測；實際承接需另有回覆。未結案不等於未修復漏洞數。',
             '建議依本輪來源與人工覆核整理；未確認日期不代填，背景僅採用明確隨快照提供的紀錄。', '']
    for a in data['actions']:
        lines += [f"## {a['key']} — {cell(a['status_raw'])}", '',
                  f"- 來源：{link(a['key'], capture)}；{cell(a['evidence_ref'])}",
                  f"- Assignee（非承接證明）：{cell(a['assignee'])}",
                  f"- 正常流程下一站：{a['normal_flow']}",
                  f"- 最新來源節錄：{cell(a['latest_source_excerpt'])}（{cell(a['latest_source_time'])}；本輪補讀詳情={a['source_detail_fetched']}）",
                  f"- 查詢期間 Jira 更新：{'有 updated 時間落在窗口；內容進展仍看節錄／歷程' if any(r['key']==a['key'] for r in data['updated_issues']) else '未見 updated 落在窗口；不代表沒有工作'}",
                  f"- 快照附帶的技術證據背景：{cell(a['background_evidence'])}",
                  f"- 快照附帶的技術缺口／卡點背景：{cell(a['background_gap'])}",
                  f"- 待找的接收者／快照附帶的詢問路徑：{cell(a['background_owner'])}",
                  f"- 人工覆核接受者：{cell(a['accepted_by'])}",
                  f"- 來源已確認下一步：{cell(a['source_next_action'])}",
                  f"- 系統建議下一步（非來源承諾）：{cell(a['suggested_action'])}",
                  f"- 追蹤日：{cell(a['next_follow_up_at'])}；修補期限：{cell(a['remediation_due_at'])}",
                  f"- 原始 Jira Due Date：{cell(a['source_due_date'])}；Finish ETA：{cell(a['source_finish_eta'])}（不可自動當修補承諾）",
                  f"- 例外查證：{cell(', '.join(a['review_reasons']))}", '']
        from psirt_casework.effective import summary
        manual_text=summary(data.get('effective_manual',{}).get('cases',{}).get(a['key']))
        if manual_text: lines += ['- '+cell(manual_text),'']
    from psirt_casework.effective import summary
    covered={a['key'] for a in data['actions']}
    for key,record in data.get('effective_manual',{}).get('cases',{}).items():
        text=summary(record)
        if key not in covered and text:lines += ['## '+cell(key)+' — 本機追蹤；本輪來源狀態待確認','','- '+cell(text),'']
    lines += ['## 證據覆核提醒', '', '逐案核對產品／版本、修補內容、驗證結果與交付範圍；未執行產品掃描、PoC 或正式安全分類。']
    return '\n'.join(lines)+'\n'


def sf_table(data, capture=None):
    lines = ['| SF Case | 查詢期間新案（created） | 查詢期間訊息數 | Jira 明確文字引用 | 處理建議 |', '|---|---|---|---|---|']
    for r in data['sf_activity']:
        c=r['case']; number=c['CaseNumber']
        target=source_url(capture or {}, 'salesforce', c['Id'])
        label=f'[{number}]({target})' if target else number
        lines.append('| '+' | '.join(cell(x) for x in (
            label,
            r['new_case_in_window'],r.get('message_count'),', '.join(r['jira_keys']) or '已查範圍未找到',
            sf_recommendation(r))) + ' |')
    if not data['sf_activity']:
        lines += ['| 未見可列活動；先確認來源狀態與查詢完整性 | — | — | — | — |']
    return lines


def sf_recommendation(row):
    if row['jira_keys']:
        return '沿引用舊 Case 對回既有 Jira；不是已修復／正式同案判定'
    if row['intake_hint']=='EXISTING_HANDLING_STATED_KEY_UNVERIFIED':
        return '既有對外回覆稱重複且已內部追蹤；核對原 Jira key，勿直接重開'
    if row['candidate']:
        return '開單評估候選（標題線索）；先查原案／重複／是否需 action'
    if row['intake_hint']=='AUTOMATED_NOTIFICATION_SUBJECT_HINT':
        return '隔離通知標題線索；先對回原信，不直接列漏洞開單'
    return '收件待篩選；不能僅憑未找到 Jira 就要求開單'


def sf_excerpts(data):
    lines = ['## Salesforce 最新回覆證據','']
    for row in data['sf_activity']:
        lines += ['### '+row['case']['CaseNumber'], '',
                  '- Case 狀態：'+cell(row['case'].get('Status'))+'；Closed='+str(row['case'].get('IsClosed')),
                  '- 標題：'+cell(row['case'].get('Subject')),
                  '- 收件提示（非正式分類）：'+row['intake_hint'],
                  '- 關聯查核範圍：所有 Jira 摘要＋選定案件詳情／留言＋信內明確 Case 編號；未涵蓋所有歷史留言。',
                  '- 關聯證據：'+cell(row['link_evidence'])]
        for m in sorted(row['messages'], key=lambda r:r.get('MessageDate','')):
            lines.append('- '+cell(m.get('MessageDate'))+'；'+('外部來信' if m.get('Incoming') else 'SF 對外訊息紀錄')+
                         '；EmailMessage '+cell(m['Id'])+'；Status='+cell(m.get('Status'))+'：'+cell(excerpt(m.get('TextBody'),600)))
        lines += ['']
    return lines


def daily_markdown(capture, data, comparisons, mode, run_id):
    stats = data.get('statistics') or build_statistics(capture, comparisons)
    kev, jira, matches = (stats[n]['counts'] for n in ('kev','jira','kev_dt'))
    week = stats['periods']['calendar_week']
    lines = ['# PSIRT Daily — 未發布草稿','',f'Run：{run_id}；模式：{mode}；來源原始擷取：{capture["captured_at"]}',
             f"窗口：{capture['config']['window_start']} ～ {capture['config']['cutoff']}",
             'snapshot-replay 是歷史重播，不是今日查詢。來源成功也不是產品安全判定。','',
             '## 來源健康','',*health_lines(capture,comparisons),'',
             '## 案件待跟進','',
             '回覆日、工程交付、獨立驗證與正式收束分開；以下內容依快照來源判讀。',
             '完整 Owner／來源節錄／卡點背景／接收者／建議與日期見 [Action List](Vance_Action_List.md)。','',
             '## A：KEV → DT 候選比對','',
             f"- KEV 目錄不同 CVE：{cell(kev['catalog'])}；查詢期間 dateAdded：{cell(kev['window'])}；資料截止當週：{cell(kev['week'])}（{week['start']} ～ {week['end']}）。dateAdded 是加入目錄日期，僅日精度。",
             f"- 相較上次完整基準新增：{cell(kev['added'])}；0 不代表沒有既有 KEV。基準觀測：{cell(comparisons['kev'].get('last_successful_at'))}。",
             f"- 全目錄對照既有 DT 範圍：不同 CVE {cell(matches['cves'])}、finding {cell(matches['findings'])}、專案 {cell(matches['projects'])}（不是產品數）。完整性：{stats['kev_dt']['complete']}；{cell(capture['config']['dt_scope_note'])}。",
             f"- 已觀測命中：{cell(stats['kev_dt']['observed_counts'])}。不等於正式受影響；識別碼及 capture 證據位置見 report.json#/analysis/statistics/kev_dt。",
             f"- 以下保留本輪選樣列：{data['kev_basis']}；與全目錄既有命中分開。",
             '', '| CVE | 專案／版本 | 元件／版本 | 原始 Analysis | 證據 |','|---|---|---|---|---|']
    for m in data['kev_dt_matches']:
        f=m['finding'];p=f['project'];c=f['component']
        lines.append('| '+' | '.join(cell(x) for x in (m['cve'],p.get('name')+' / '+str(p.get('version')),c.get('name')+' / '+str(c.get('version')),f.get('analysis'),m['evidence']))+' |')
    lines += ['', '## B-SF：新案／新回覆與 Jira 核對','',*sf_table(data, capture),
              '', '僅查核 scope 內所有狀態 Case 與窗口內 EmailMessage；Closed 案也包含。未找到關聯不是必須開單。',
              'SF 收件總覽：'+('郵件資料 Unknown；以下僅為已觀測活動。' if not email_coverage(capture['sources']['salesforce'])['complete'] else '')+str(len(data['sf_activity']))+' 案有窗口內活動；'+str(sum(r['candidate'] for r in data['sf_activity']))+' 案屬標題線索開單評估候選（非漏洞件數；來源不完整時僅代表已觀測部分）。',
              '', *sf_excerpts(data), '## B-Jira：非 Done 工單、期間新增與更新','',
              f"- 非 Done 工單：{cell(jira['open'])}；Done：{cell(jira['done'])}；分類待確認：{cell(jira['unknown'])}；查詢範圍總數：{cell(jira['total'])}。工單數不是漏洞數，Done 不是產品修復證明。",
              '- 已觀測非 Done：'+(', '.join(link(key, capture) for key in stats['jira']['keys']['open']) or '未見；完整性不足時不代表零'),
              f"- created 新增：{'Unknown' if jira['window_created'] is None else jira['window_created']}（查詢期間）；含已結案。",
              f"- updated 落在查詢期間：{cell(jira['window_updated'])}；updated 不能當 created 或修復完成。",
              f"- 資料截止當週 created：{cell(jira['week_created'])}；updated：{cell(jira['week_updated'])}。",
              '- 新增工單：'+(', '.join(link(r['key'], capture) for r in data['new_issues']) or '已觀測索引未見；須以完整性判斷'),'',
              '## 比較基準與異動','', '| 來源 | 比較結果 | 新增／修改／移除 | 基準引用 |', '|---|---|---|---|']
    for n,c in comparisons.items():
        lines.append('| '+' | '.join(cell(x) for x in (n,c['comparison'],c.get('counts'),c.get('baseline_ref')))+' |')
    coverage = email_coverage(capture['sources']['salesforce'])
    lines += ['', 'SF EmailMessage 覆蓋：'+coverage['coverage']+'；窗口內郵件數：'+cell(coverage['count'])+'；已觀測：'+str(coverage['observed_count']),
              'SF EmailMessage ID 異動（獨立於 Case 計數）：'+cell(comparisons['salesforce'].get('email_counts'))]
    lines += ['', '首次／失敗／partial／不相容的 counts 為 null，不報零。期間活動清單可在補跑重現，不把每天清單加總成累積事件。',
              '人工覆核在 output-dir/human_review.json；本程式只讀既有內容，不會覆寫。',
              '逐案待確認事項見 Action List；未更新全範圍 DT 統計，Weekly B 不沿用舊數字作今天結果。']
    from psirt_casework.effective import summary
    manual_lines=[(key,summary(c)) for key,c in data.get('effective_manual',{}).get('cases',{}).items()]
    if any(text for _,text in manual_lines):
        lines += ['','## 本機案件紀錄（同輪有效人工版本）','']
        lines += ['- '+cell(key)+'：'+cell(text) for key,text in manual_lines if text]
    return '\n'.join(lines)+'\n'


def issue_table(rows, external=False):
    headers = '工單 | SF Case | 摘要 | 狀態 | 負責人 | 最後異動' if external else '工單 | 摘要 | 優先級 | 狀態 | 負責人 | 最後異動'
    lines = ['| '+headers+' |','|---|---|---|---|---|---|']
    for r in rows:
        f=r['fields'];case=re.search(r'Q-\d{6}-\d+',f.get('summary',''))
        values = [link(r['key'])]
        if external: values += [case.group() if case else None, f.get('summary')]
        else: values += [f.get('summary'),f.get('priority',{}).get('name')]
        values += [f.get('status',{}).get('name'),(f.get('assignee') or {}).get('displayName'),f.get('updated')]
        lines.append('| '+' | '.join(cell(v) for v in values)+' |')
    return lines


def weekly_markdown(capture, data, comparisons, mode, presentation=None, report_date=None):
    """Compatibility wrapper; presentation stays independent of source capture."""
    from .sf_triage import build as triage_build
    from .weekly_presentation import build, markdown
    triage=triage_build(capture,comparisons,{'schema':'psirt-human-review/1','reviews':{}},'standalone',mode,capture['captured_at'])
    return markdown(build(capture,data,triage,presentation or {'meetings':{},'overrides':[]},report_date or capture['config']['cutoff'][:10]))
