"""Offline, evidence-first SF work view. No writes, network, or safety decisions."""
import base64
import hashlib
import json
import re
from datetime import datetime
from html import escape
from pathlib import Path
from zoneinfo import ZoneInfo
from .sf_messages import email_items, email_coverage

VERSION = 'sf-triage/1'
KEY = re.compile(r'\b[A-Z][A-Z0-9]+-\d+\b')
STATE_LABELS = {'SOURCE_VALUE':'來源欄位', 'EXPLICIT_EMPTY':'來源明確空值',
                'NOT_FETCHED':'欄位未取到', 'NOT_STATED':'可讀文字未辨識；待人工判讀',
                'REPORTED_UNVERIFIED':'通報者提供／待確認', 'UNKNOWN':'Unknown',
                'HUMAN_REVIEW':'人工覆核（與來源分列）'}


def clean(value):
    """Minimal display copy, never a full mail/attachment export."""
    text = str(value or '')
    text = re.sub(r'-----BEGIN [^-\n]+-----.*?(?:-----END [^-\n]+-----|\Z)', '[加密／金鑰區塊不展示、未解密]', text, flags=re.S)
    text = re.split(r'(?im)^\s*(?:best regards|kind regards|regards|sincerely|on .+ wrote:|寄件者[:：])',text)[0]
    text = re.sub(r'(?im)^\s*(?:dear|hi|hello)\b[^\n]*\n', '',text)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[聯絡地址省略]',text)
    text = re.sub(r'(?i)\bodt_[\w-]{12,}|\bBearer\s+[\w.=-]+', '[憑證省略]',text)
    text = re.sub(r'(?im)^.*(?:password|secret|api[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+.*$', '[敏感欄位省略]',text)
    text = re.sub(r'(https?://[^\s?]+)\?[^\s]+',r'\1?[參數省略]',text)
    return text.strip()


def taiwan(value):
    try:
        t=datetime.fromisoformat(value.replace('Z','+00:00'))
        return t.astimezone(ZoneInfo('Asia/Taipei')).isoformat() if t.tzinfo else None
    except (ValueError,AttributeError,TypeError):return None


def within(value, cfg):
    try:
        t=datetime.fromisoformat(value.replace('Z','+00:00'))
        return datetime.fromisoformat(cfg['window_start'])<=t<=datetime.fromisoformat(cfg['cutoff'])
    except (ValueError,AttributeError,TypeError,KeyError):return None


def ref(source, collection, index, identity, field, src):
    return {'path':f'capture.json#/sources/{source}/{collection}/{index}/{field}',
            'source_id':identity,'field':field,'observed_at':src.get('observed_at')}


def field(value=None, state='UNKNOWN', refs=(), src=None):
    return {'value':value,'state':state,'source_status':(src or {}).get('status','UNKNOWN'),
            'observed_at':(src or {}).get('observed_at'),'evidence_refs':list(refs)}


def native(row, key, reference, src):
    state='NOT_FETCHED' if key not in row else 'EXPLICIT_EMPTY' if row[key] is None or row[key]=='' else 'SOURCE_VALUE'
    value=row.get(key)
    if isinstance(value,str):value=clean(value)[:1800]
    return field(value,state,[reference],src)


def extract(pattern, texts, src):
    for text,r in texts:
        match=re.search(pattern,text,re.I|re.M)
        if match:return field(clean(match.group(1)).strip(' *'), 'REPORTED_UNVERIFIED',[r],src)
    return field(None,'NOT_STATED' if texts else 'NOT_FETCHED',[r for _,r in texts],src)


def source_summary(src):
    return {k:src.get(k) for k in ('status','complete','observed_at','scope','detail_scope','errors')}


def build(capture, comparisons, review, run_id, mode, generated_at):
    sf,jira=(capture['sources'][x] for x in ('salesforce','jira'))
    cfg=capture['config'];cases=sf.get('raw') or [];emails=email_items(sf)
    coverage=email_coverage(sf)
    sf_ok=sf.get('status')=='SUCCESS' and sf.get('complete') is True
    jira_ok=jira.get('status')=='SUCCESS' and jira.get('complete') is True
    comp=comparisons.get('salesforce',{})
    comparable=sf_ok and comp.get('comparison')=='COMPARABLE'
    added={x.get('Id',x.get('id')) for x in (comp.get('changes') or {}).get('added',[])} if comparable else set()
    email_added={x.get('Id',x.get('id')) for x in (comp.get('email_changes') or {}).get('added',[])} if comparable else set()
    email_comparable=comparable and coverage['complete'] and comp.get('email_changes') is not None
    known_review=review.get('schema')=='psirt-human-review/1'
    reviews=review.get('reviews',{}) if known_review else {}
    by_case={};duplicates={};seen={}
    for i,e in emails:
        by_case.setdefault(e.get('ParentId'),[]).append((i,e))
        if e.get('Incoming') is True and e.get('TextBody') and e.get('Subject') and e.get('MessageDate'):
            # Exact bytes plus subject/date; never reduce to vulnerability count.
            sig=hashlib.sha256(json.dumps([e['Subject'],e['TextBody'],e['MessageDate']],ensure_ascii=False).encode()).hexdigest()
            seen.setdefault(sig,[]).append((i,e))
    for sig,group in seen.items():
        if len({e.get('ParentId') for _,e in group})>1:
            for i,e in group:
                duplicates.setdefault(e['ParentId'],[]).append({'basis':'相同主旨、完整正文 SHA256 與 MessageDate；僅候選，未合併',
                    'signature_sha256':sig,'case_ids':sorted({x['ParentId'] for _,x in group}),
                    'email_ids':[x['Id'] for _,x in group],
                    'evidence_refs':[ref('salesforce','emails',j,x['Id'],'TextBody',sf) for j,x in group]})
    # An observed mail must remain accessible even when its parent index is partial.
    indexed={c.get('Id') for c in cases}
    case_inputs=list(enumerate(cases))+[(None,{'Id':cid}) for cid in by_case if cid not in indexed]
    # Each case searches the same Jira fields. Serialize them once, preserving
    # detail precedence and the original raw index used in evidence references.
    jira_details=jira.get('details') or {}
    jira_texts=[(j,issue.get('key'),json.dumps(jira_details.get(issue.get('key'),issue).get('fields',{}),ensure_ascii=False))
                for j,issue in enumerate(jira.get('raw') or [])]
    rows=[]
    for i,c in case_inputs:
        cid=c.get('Id');number=c.get('CaseNumber');messages=by_case.get(cid,[])
        cr=lambda k:ref('salesforce','raw',i,cid,k,sf)
        fs={k:native(c,k,cr(k),sf) for k in ('CaseNumber','Subject','CreatedDate','LastModifiedDate','Status','IsClosed')}
        owner=c.get('Owner')
        fs['source_owner']=native({'Name':owner.get('Name')} if isinstance(owner,dict) else {},'Name',cr('Owner/Name'),sf)
        texts=[];message_rows=[];reference_texts=[]
        for j,m in messages:
            er=lambda k:ref('salesforce','emails',j,m.get('Id'),k,sf)
            body=clean(m.get('TextBody'))
            for name in ('Subject','TextBody'):
                if m.get(name):
                    reference_texts.append((str(m[name]),{**er(name),'incoming':m.get('Incoming'),'message_date':m.get('MessageDate')}))
            # Never infer a reporter claim from outbound/quoted acknowledgement.
            if m.get('Incoming') is True and body:texts.append((body,er('TextBody')))
            message_rows.append({'id':m.get('Id'),'parent_id':cid,
                'message_date':native(m,'MessageDate',er('MessageDate'),sf),
                'modified_date':native(m,'LastModifiedDate',er('LastModifiedDate'),sf),
                'incoming':native(m,'Incoming',er('Incoming'),sf),
                'subject':native(m,'Subject',er('Subject'),sf),
                'excerpt':field(body[:1800] or None,'SOURCE_VALUE' if body else 'EXPLICIT_EMPTY' if 'TextBody' in m else 'NOT_FETCHED',[er('TextBody')],sf),
                'body_display_truncated':len(body)>1800,
                'reply_nature':'來信；非正式受理證明' if m.get('Incoming') is True else '自動確認文字提示；非人工受理' if re.search(r'automated response',body,re.I) else '回信性質待確認',
                'in_window':within(m.get('MessageDate'),cfg),
                'first_in_baseline':m.get('Id') in email_added if email_comparable else None})
        if c.get('Description'):texts.append((clean(c['Description']),cr('Description')))
        subject=clean(c.get('Subject'))
        subject_texts=[(subject,cr('Subject'))] if subject else []
        product=extract(r'^\s*Product\s*[:：]\s*([^\n]+)',texts,sf)
        version=extract(r'^\s*(?:Firmware|Version)\s*[:：]\s*([^\n]+)',texts,sf)
        if product['value'] is None:
            product=extract(r'(?:report\s*[—:–-]\s*|vulnerability in\s+(?:the\s+)?)([^\n]+?)\s+v\d[\w.]*',subject_texts+[(re.sub(r'\s+',' ',t),r) for t,r in texts],sf)
        if version['value'] is None and product['value']:
            version=extract(re.escape(product['value'])+r'\s+(v\d[\w.]*)',subject_texts+[(re.sub(r'\s+',' ',t),r) for t,r in texts],sf)
        fs.update(product=product,version=version,
                  product_field=native(c,'Product__c',cr('Product__c'),sf),
                  description_field=native(c,'Description',cr('Description'),sf))
        if fs['product_field']['value']:fs['product']=fs['product_field']
        fs['reporter_severity']=extract(r'\bSeverity\s*[:：]?\s*\**(Critical|High|Medium|Low|Informational)\b',texts,sf)
        fs['cvss_version']=extract(r'\bCVSS\s*[:/]?\s*(\d\.\d)\b',texts,sf)
        fs['cvss_score']=extract(r'\bCVSS\s*[:/]?\s*\d\.\d\s+(10(?:\.0)?|[0-9](?:\.\d)?)\b',texts,sf)
        fs['cvss_vector']=extract(r'\b(CVSS:\d\.\d/[A-Za-z0-9:/._-]+)',texts,sf)
        fs['company_decision']=field();fs['company_reviewer']=field();fs['company_decided_at']=field()
        fs['accepted_by']=field();fs['first_seen']=field()  # A delta does not prove earliest observation.
        fs['risk_description']=field(texts[0][0][:900],'REPORTED_UNVERIFIED',[texts[0][1]],sf) if texts else field(None,'NOT_FETCHED',[],sf)
        fs['attack_prerequisites']=extract(r'^\s*(?:Access|Attack prerequisites|Preconditions)\s*[:：]\s*([^\n]+)',texts,sf)
        fs['reproduction']=extract(r'(Steps to Reproduce|reproduction logs|proof.of.concept|PoC)',texts,sf)
        fs['public_status']=extract(r'([^\n]*(?:not shared|remain confidential|published nothing)[^\n]*)',texts,sf)
        evidence_texts=subject_texts+texts
        relationship_texts=subject_texts+reference_texts
        if c.get('Description'):relationship_texts.append((clean(c['Description']),cr('Description')))
        candidates={}
        for t,reference in relationship_texts:
            for key in KEY.findall(t):
                if re.fullmatch(r'[A-Z][A-Z0-9_]*-\d+', key):candidates.setdefault(key,[]).append(reference)
        if number and jira_texts:
            number_pattern=re.compile(r'(?<![\w-])'+re.escape(number)+r'(?![\w-])')
            for j,key,hay in jira_texts:
                # The cheap literal check only skips impossible matches. Keep
                # the existing Unicode word/hyphen boundaries for every hit.
                if number in hay and number_pattern.search(hay):
                    candidates.setdefault(key,[]).append(ref('jira','details' if key in jira_details else 'raw',key if key in jira_details else j,key,'fields',jira))
        human=[]
        for key,r in reviews.items():
            if not isinstance(r,dict):continue
            er=r.get('evidence_ref','')
            if not isinstance(er,str) or not any(s and re.search(r'(?<![\w-])'+re.escape(s)+r'(?![\w-])',er) for s in (cid,number)):continue
            verified=r.get('verification')=='VERIFIED_BY_HUMAN' and bool(r.get('reviewer'))
            # Existing review schema: preserve evidence and acceptance, do not
            # invent a formal-link assertion from a generic verified note.
            human.append({'jira_key':key,'verified':bool(verified),
                'evidence_ref':clean(er),'reviewer':clean(r.get('reviewer')),
                'accepted_by':clean(r.get('accepted_by')) or None,
                'note':clean(r.get('note'))[:600],
                'source_next_action':clean(r.get('source_next_action')) or None,
                'review_date':r.get('reviewed_at'),
                'ref':'human_review_used.json#/reviews/'+key})
            if verified and r.get('accepted_by'):
                fs['accepted_by']=field(clean(r['accepted_by']),'HUMAN_REVIEW',[{'path':'human_review_used.json#/reviews/'+key+'/accepted_by','source_id':key,'field':'accepted_by','observed_at':r.get('reviewed_at')}])
            effective=r.get('effective_acceptance')
            if effective is not None:
                fs['accepted_by']=field()
                if effective.get('state')=='CONFIRMED':
                    fs['accepted_by']=field(clean(effective['value']),'HUMAN_REVIEW',[{'path':'effective_manual_used.json#/cases/'+key+'/fields/accepted_by','source_id':key,'field':'accepted_by','observed_at':r.get('reviewed_at')}])
        verified_evidence=[r for r in human if r['verified']]
        link={'status':'VERIFIED_REVIEW_EVIDENCE' if verified_evidence else 'CANDIDATE' if candidates else 'NOT_FOUND_IN_SCOPE' if jira_ok else 'UNDETERMINED',
              'current_status':'AVAILABLE_IN_SCOPE' if jira_ok else 'UNKNOWN_SOURCE_INCOMPLETE',
              'query_status':jira.get('status'),'evidence':[{'key':k,'evidence_refs':v} for k,v in sorted(candidates.items())],
              'verified_review_evidence':verified_evidence,'formal_link':'UNKNOWN',
              'note':'核實人工紀錄與候選引用分列；通用覆核標記不等同正式主案關聯。失敗時目前狀態 Unknown；舊證據日期未載則待確認。'}
        # A verified SF/Jira relationship is usable only when the original source
        # contains an explicit relationship, not a key in unstructured text.
        # Current adapter does not fetch such a field: leave formal_link Unknown.
        classification='一般通知文字提示／待覆核' if re.search('messages in quarantine',subject,re.I) else '安全通報文字提示／待覆核' if re.search('PSIRT|vulnerab|security report|lockout',subject,re.I) else '未分類待檢視'
        gaps=[label for k,label in [('product','產品／服務'),('version','版本'),('risk_description','問題描述'),('attack_prerequisites','攻擊前提'),('public_status','公開狀態')] if not fs[k]['value']]
        # A lexical clue never establishes obtained/reviewed technical evidence.
        gaps.append('重現證據')
        fs['reproduction_verification']=field(None,'UNKNOWN',fs['reproduction']['evidence_refs'],sf)
        encrypted=any(re.search('encrypted|加密',t,re.I) for t,_ in evidence_texts)
        if encrypted:gaps.append('加密內容／附件未實讀，技術證據待授權人員核對')
        tags=[]
        if within(c.get('CreatedDate'),cfg) is True:tags.append('new_case')
        if any(x['in_window'] is True and x['incoming']['value'] is True for x in message_rows):tags.append('incoming')
        if any(x['in_window'] is True and x['incoming']['value'] is False for x in message_rows):tags.append('outbound')
        if classification=='未分類待檢視':tags.append('unclassified')
        if link['formal_link']=='UNKNOWN':tags.append('link_pending')
        if cid in duplicates:tags.append('duplicate')
        rows.append({'id':cid,'number':number,'fields':fs,'messages':message_rows,'tags':tags,
                     'classification':classification,'classification_evidence':cr('Subject'),
                     'case_in_window':within(c.get('CreatedDate'),cfg),
                     'first_in_baseline':cid in added if comparable else None,
                     'gaps':gaps,'jira':link,'human_reviews':human,'duplicate_candidates':duplicates.get(cid,[]),
                     'next_action':'建議／待覆核：核對通報原文與'+('、'.join(gaps[:3]) if gaps else '技術證據')+'；重現證據待人工核實；依現行公司流程人工確認是否建案。',
                     'deadline':'待確認；不判逾期','review_conflict_notice':'來源與人工紀錄並列，不自動覆蓋或視為一致。' if human else None})
    rows.sort(key=lambda r:(not bool(set(r['tags'])&{'incoming','new_case','duplicate'}),r['fields']['CreatedDate']['value'] or ''),reverse=False)
    counts={tag:sum(tag in r['tags'] for r in rows) for tag in ('new_case','incoming','outbound','unclassified','link_pending','duplicate')}
    return {'schema':VERSION,'run_id':run_id,'mode':mode,'synthetic':capture.get('synthetic'),
            'generated_at':generated_at,'original_capture_at':capture.get('captured_at'),
            'sources':{n:source_summary(capture['sources'][n]) for n in ('salesforce','jira')},
            'window':{k:cfg.get(k) for k in ('window_start','cutoff')},
            'comparison':{k:comp.get(k) for k in ('comparison','baseline_ref','last_successful_at','counts','email_counts')},
            'increments':{'cases':len(added) if comparable else None,'emails':len(email_added) if email_comparable else None},
            'email_coverage':coverage,
            'observed_counts':counts,'counts':{k:n if coverage['complete'] else None for k,n in counts.items()},
            'index_count':len(cases) if sf_ok else None,'observed_index_count':len(cases),
            'review_schema_status':'SUPPORTED' if known_review else 'UNKNOWN_SCHEMA_NOT_INTERPRETED',
            'state_labels':STATE_LABELS,'rows':rows}


def render(shell,data,editable=False):
    from .dt_statistics import STYLE
    from psirt_casework.report_version import section as report_section, ASSET as REPORT_SCRIPT
    from psirt_casework.work_page import compact_shell
    prefix=shell.split('<main>',1)[0]
    prefix=re.sub(r'href="#([^\"]+)"',r'href="index.html#\1"',prefix)
    prefix=prefix.replace('<title>PSIRT 工作台','<title>SF 通報判讀')
    prefix=prefix.replace('href="sf-triage.html"','href="sf-triage.html" aria-current="page"')
    script=REPORT_SCRIPT.read_text()+'\n'+(Path(__file__).with_name('assets')/'sf-triage-v1.js').read_text()
    from psirt_casework.inbox_web import assets as inbox_assets, section as inbox_section
    inbox_script,inbox_style=inbox_assets()
    script+='\n'+inbox_script
    digest=base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    prefix=prefix.replace("default-src 'none';","default-src 'none'; script-src 'sha256-"+digest+"';"+(" connect-src 'self';" if editable else ''))
    prefix=prefix.replace('</head>','<style>'+inbox_style+'</style></head>')
    prefix=prefix.replace('</head>','<style>'+STYLE+' .sf-detail pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:400px;overflow:auto}.sf-detail{padding:16px;background:#171a2a}.sf-detail dl{display:grid;grid-template-columns:minmax(100px,1fr) minmax(150px,4fr);gap:10px}.sf-detail dd{margin:0;overflow-wrap:anywhere}.sf-detail details{margin:8px 0}.sf-list{min-width:1050px} #sf-rows td{max-width:240px} .sf-brief{display:-webkit-box;-webkit-line-clamp:6;-webkit-box-orient:vertical;overflow:hidden;white-space:pre-line} </style></head>')
    prefix=compact_shell(prefix)
    e=lambda x:escape(str(x) if x is not None else 'Unknown',quote=True)
    notice=('本機工作頁；讀取與保存本機紀錄本身不取數；自動更新開啟時，頁面依到期狀態觸發既有範圍更新。' if editable else '歷史離線重播／本機重建；本輪未查 API。' if data['mode'] in ('snapshot-replay','report-rebuild') else '取數當輪結果；限定已設定來源範圍。')
    out=[prefix,'<main><section class="dt-statistics" id="sf-triage"><div class="work-page-title"><h2>Salesforce · 通報判讀</h2>']
    if data['synthetic']:out.append('<span class="work-synthetic">合成驗收案例，不是真實公司通報。</span>')
    if not editable:out.append('<span class="work-mode">固定報告 · 唯讀</span>')
    out.append('</div>')
    if data.get('inbox'):out.append(inbox_section(editable))
    out.append('<details class="work-run-evidence"><summary>本頁報告批次與更新說明</summary><p class="dt-status">'+notice+'</p><p>報告產生：'+e(taiwan(data['generated_at']))+'<br>Run：'+e(data['run_id'])+'</p></details>')
    for name,s in data['sources'].items():
        out.append('<p>'+e(name)+'：<b>'+e(s['status'])+'</b>；完整性 '+e(s['complete'])+'；擷取 '+e(taiwan(s['observed_at']))+'</p>')
    out += ['<details><summary>範圍、原始時間、比較基準與日期窗</summary><pre>'+e(json.dumps({k:data[k] for k in ('sources','comparison','window','original_capture_at','review_schema_status')},ensure_ascii=False,indent=2))+'</pre></details>',
       '<p class="dt-note">已取索引不等於全部待辦。篩選數字是 Case 數，EmailMessage 增量另列；各篩選可能重疊，不能加總成漏洞數。通報者主張不等於確認受影響；Jira 引用不是正式關聯。Source Owner/Queue 不等於實際承接。期限待確認。</p>',
       '<p>相較上次完整基準首次出現：Case <b id="sf-case-delta">'+e(data['increments']['cases'])+'</b>；EmailMessage <b id="sf-email-delta">'+e(data['increments']['emails'])+'</b>。首次基準／不相容／來源失敗為 Unknown；與日期窗內新建分開。</p>',
       '<div class="dt-controls"><label>Case 編號／產品／主旨搜尋<input id="sf-search" type="search" placeholder="例如 61755 或產品文字"></label><label>作業視角<select id="sf-filter">']
    for key,label in [('all','全部已取索引（非全部待辦）'),('new_case','日期窗內新建 Case'),('incoming','日期窗內新來信'),('outbound','日期窗內回覆（性質另查）'),('unclassified','未分類待檢視'),('link_pending','關聯待確認'),('duplicate','重複候選（不合併）')]:
        out.append('<option value="'+key+'">'+label+(' · '+e(data['index_count']) if key=='all' else ' · '+e(data['counts'][key]))+'</option>')
    out += ['</select></label><button id="sf-clear">清除篩選</button></div><p id="sf-results" role="status" aria-live="polite"></p>',
       '<div class="dt-table-scroll" tabindex="0" aria-label="SF 判讀表，可左右捲動"><table class="dt-table sf-list"><thead><tr>'+''.join('<th>'+x+'</th>' for x in ['Case／建立時間','產品／版本','通報摘要','評級來源','工具提示缺口','Jira 證據／狀態','下一步'])+'</tr></thead><tbody id="sf-rows"></tbody></table></div>',
       '<div class="dt-pager"><button id="sf-prev">上一頁</button><span id="sf-page"></span><button id="sf-next">下一頁</button></div>',
       '<p>來信待辦的人工覆核僅儲存在本機；下方 Case 索引供查核。不寄信、不建／併案、不執行附件。公司建案時點仍須依受控流程人工確認；不自行採用「補齊才開」或「一律立即開」。</p>',
       ('<p>來源更新請使用頁頂更新控制，或連線維護後的 Salesforce 重試；讀回本機狀態與產生報告不取信。當輪範圍與完整性以來源狀態為準。</p>' if editable else '<p>本份歷史 HTML 為唯讀，開啟或重新整理不會查 API；請使用既有 Launch-PSIRT 開啟目前工作頁更新。當輪資料時間及完整性以頁首與 manifest 為準。</p>'),
       report_section(data,editable,'salesforce')+'<p><a href="index.html">返回工作總覽</a> · <a href="index.html#salesforce">原 Salesforce 區段</a></p>',
       '<noscript>互動需 JavaScript，亦可讀取判讀 JSON；所有來源內容只以文字顯示。</noscript>',
       '<pre id="sf-data" hidden>'+escape(json.dumps(data,ensure_ascii=False,separators=(',',':')))+'</pre></section></main><script>'+script+'</script></body></html>']
    return ''.join(out)
