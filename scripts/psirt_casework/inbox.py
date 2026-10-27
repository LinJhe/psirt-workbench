"""Observed incoming mail ledger and personal workflow, independent of fetch deltas.

Immutable report artifacts carry compact source evidence forward. No API calls,
no writes during reads, no automatic acknowledgement, and no inferred closure.
"""
import copy
import re
import threading
from pathlib import Path
from .store import Invalid, Conflict, encoded, timestamp
from psirt_daily.pipeline import no_symlinks, read_json, sha
from psirt_ops.sf_triage import clean
from psirt_ops.sf_messages import email_items, email_coverage

SCHEMA = 'psirt-sf-inbox/1'
STATES = {'unreviewed':'尚未檢視', 'pending':'待處理', 'following':'待追蹤', 'done':'已完成（本機）'}
_BOOTSTRAP_LOCK = threading.Lock()
_BOOTSTRAP_CACHE = None  # Bounded to one pinned legacy root; never caches raw captures.


def identity(instance, email_id):
    return 'sfmail-'+sha(encoded([instance,email_id]).encode())


def instance_of(capture):
    source=capture['sources']['salesforce']
    value=source.get('scope',{}).get('instance')
    return value or ('synthetic://fixture' if capture.get('synthetic') else None)


def merge(rows, capture, run_id):
    """Union of observed incoming IDs; absence is never a deletion or completion."""
    source=capture['sources']['salesforce'];instance=instance_of(capture)
    messages=email_items(source)
    if not instance:
        if messages: raise Invalid('SF 來源 instance 未取得，不能建立穩定郵件識別')
        return
    cases={c.get('Id'):c for c in source.get('raw') or []}
    for index,message in messages:
        if message.get('Incoming') is not True:continue
        mid=message.get('Id')
        if not isinstance(mid,str) or not mid or len(mid)>100:raise Invalid('SF EmailMessage ID 不合法')
        key=identity(instance,mid);old=rows.get(key);at=source.get('observed_at')
        if old and timestamp(at)<timestamp(old['last_observed_at']):
            old['first_observed_at']=min(old['first_observed_at'],at,key=timestamp)
            continue
        case=cases.get(message.get('ParentId'),{})
        rows[key]={'id':key,'instance':instance,'email_id':mid,'case_id':message.get('ParentId'),
                   'case_number':case.get('CaseNumber') or (old or {}).get('case_number'),
                   'subject':clean(message.get('Subject'))[:500], 'excerpt':clean(message.get('TextBody'))[:1800],
                   'message_date':message.get('MessageDate'),
                   'first_observed_at':min((old or {}).get('first_observed_at',at),at,key=timestamp),
                   'last_observed_at':at,'source_status':source.get('status'),
                   'evidence_ref':f'runs/{run_id}/capture.json#/sources/salesforce/emails/{index}',
                   'evidence_sha256':sha(encoded(message).encode())}


def checked_artifact(run, manifest, name):
    path=run/name;no_symlinks(path);raw=path.read_bytes()
    if sha(raw)!=manifest.get('artifacts_sha256',{}).get(name):raise Invalid('SF inbox 來源雜湊不一致')
    return read_json(raw)


def _stat(path):
    no_symlinks(path)
    value=path.stat()
    return (str(path),value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def _bootstrap(root, names, synthetic, pinned):
    """Read each unique old capture once, then cache compact evidence by file stats."""
    from .mail_triage import merge_index
    global _BOOTSTRAP_CACHE
    paths=[];missing=[]
    for name in sorted(set(names)):
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_+.-]+',name) or name in ('.','..'):
            raise Invalid('SF inbox 歷史 run ID 不合法')
        run=root/'runs'/name
        no_symlinks(run)
        for filename in ('manifest.json','capture.json'):
            path=run/filename;no_symlinks(path)
            if not path.is_file():missing.append(name);break
        else:paths.extend((run/'manifest.json',run/'capture.json'))
    def fingerprint():return (str(root),synthetic,pinned,tuple(missing),tuple(_stat(p) for p in paths))
    with _BOOTSTRAP_LOCK:
        key=fingerprint()
        if _BOOTSTRAP_CACHE and _BOOTSTRAP_CACHE[0]==key:
            return copy.deepcopy(_BOOTSTRAP_CACHE[1])
        rows={};index={};seen=set()
        for offset in range(0,len(paths),2):
            manifest_path=paths[offset];run=manifest_path.parent
            manifest=read_json(manifest_path.read_bytes())
            capture_hash=manifest.get('artifacts_sha256',{}).get('capture.json')
            if not capture_hash:raise Invalid('SF inbox 歷史 capture 未列入清單')
            # Every referenced file is verified, including repeated rebuilds with
            # identical captures; decode the large object only once per hash.
            raw=(run/'capture.json').read_bytes()
            if sha(raw)!=capture_hash:raise Invalid('SF inbox 來源雜湊不一致')
            if capture_hash in seen:continue
            capture=read_json(raw)
            if capture.get('synthetic')!=synthetic:raise Invalid('SF inbox 禁止合成與真實歷史混用')
            merge(rows,capture,run.name);merge_index(index,capture,run.name);seen.add(capture_hash)
        if fingerprint()!=key:raise Conflict('SF inbox 歷史來源在驗證期間變更，請重讀')
        result=(rows,index,sorted(set(missing)))
        _BOOTSTRAP_CACHE=(key,copy.deepcopy(result))
        return result


def _history_data(root, synthetic, state=None):
    """Use latest cumulative artifact; bootstrap old roots from verified captures.

    Only completed runs (manifest present) enter the ledger. Failed/partial source
    observations may contribute known mail, never a claim of complete coverage.
    """
    root=Path(root);state_path=root/'state.json'
    if not state_path.exists():return {}, [], {}, []
    if state is None:state=read_json(state_path.read_bytes())
    latest=Path(state['latest_run'])
    if latest.parent!=root/'runs':raise Invalid('SF inbox 歷史路徑不合法')
    no_symlinks(latest/'manifest.json');raw=(latest/'manifest.json').read_bytes()
    if sha(raw)!=state['manifest_sha256']:raise Invalid('SF inbox 歷史清單雜湊不一致')
    manifest=read_json(raw)
    if 'sf-inbox.json' in manifest['artifacts_sha256']:
        previous=checked_artifact(latest,manifest,'sf-inbox.json')
        if previous.get('schema')!=SCHEMA or previous.get('synthetic')!=synthetic:raise Invalid('SF inbox 模式不一致')
        rows={r['id']:copy.deepcopy(r['source']) for r in previous['rows']};runs=previous['history_runs']
        from .mail_triage import INDEX_VERSION
        if previous.get('message_index_schema')==INDEX_VERSION and isinstance(previous.get('message_index'),dict):
            return rows,runs,copy.deepcopy(previous['message_index']),previous.get('triage_history_missing',[])
        # Existing /1 artifacts remain valid. Only their pinned history is scanned;
        # an unrelated newer run must not leak into a response under construction.
        _,index,missing=_bootstrap(root,runs,synthetic,state['manifest_sha256'])
        return rows,runs,index,missing
    runs=[]
    for run in sorted((root/'runs').iterdir()):
        no_symlinks(run)
        if not (run/'manifest.json').is_file():continue
        no_symlinks(run/'manifest.json');m=read_json((run/'manifest.json').read_bytes())
        # Legacy bootstrap must not absorb a newer run while the caller renders
        # a pinned older capture. Modern roots use the cumulative artifact above.
        if manifest.get('completed_at') and m.get('completed_at') and timestamp(m['completed_at'])>timestamp(manifest['completed_at']):continue
        runs.append(run.name)
    rows,index,missing=_bootstrap(root,runs,synthetic,state['manifest_sha256'])
    return rows,runs,index,missing


def history(root, synthetic, state=None):
    """Compatibility wrapper for consumers of the original incoming-only ledger."""
    rows,runs,_,_=_history_data(root,synthetic,state)
    return rows,runs


def build(root, capture, manual, comparison, run_id, generated_at, history_state=None):
    from .mail_triage import INDEX_VERSION, RULE_VERSION, annotate, merge_index
    rows,runs,index,missing=_history_data(root,capture['synthetic'],history_state)
    merge(rows,capture,run_id)
    merge_index(index,capture,run_id)
    source=capture['sources']['salesforce'];instance=instance_of(capture)
    current={identity(instance,m['Id']) for _,m in email_items(source) if m.get('Incoming') is True and instance}
    records={r['id']:r for r in manual.get('records',[]) if r['kind']=='sf_email'}
    result=[]
    for key,s in rows.items():
        record=records.get(key);p=record['payload'] if record else {}
        result.append({'id':key,'source':s,'in_current_capture':key in current,
                       'needs_recheck':bool(record and p.get('source_digest')!=s['evidence_sha256']),
                       'state':p.get('state','unreviewed'),'record':record,
                       'revisions':[r for r in manual.get('revisions',[]) if r['kind']=='sf_email' and r['id']==key]})
    contexts=annotate(result,index)
    result.sort(key=lambda r:(not r['needs_recheck'],r['triage']['attention']=='reference',
                             r['triage']['attention']!='priority',r['state']=='done',
                             r['source'].get('message_date') or '',r['id']))
    source_success=source.get('status')=='SUCCESS' and source.get('complete') is True
    coverage=email_coverage(source)
    complete=coverage['complete']
    comparable=complete and comparison.get('comparison')=='COMPARABLE' and comparison.get('email_changes') is not None
    new=len({m['Id'] for m in comparison['email_changes']['added'] if m.get('Incoming') is True}) if comparable else None
    health={k:source.get(k) for k in ('status','complete','observed_at','scope','attempted','attempted_at',
                                    'auth_blocked','auth_error_code','auth_blocked_at','skipped_reason')}
    # Source health records its declared successful attempt. Legacy captures may
    # lack EmailMessage data, so inbox coverage independently remains Unknown.
    health['last_successful_at']=source.get('observed_at') if source_success else comparison.get('last_successful_at')
    health['errors']=[{k:v for k,v in error.items() if k in ('type','http_status','cause','error_code') and
                      (type(v) is int or isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',v))}
                     for error in source.get('errors',[]) if isinstance(error,dict)]
    return {'schema':SCHEMA,'synthetic':capture['synthetic'],'run_id':run_id,'generated_at':generated_at,
            'source':health,
            'window':{k:capture['config'].get(k) for k in ('window_start','cutoff')},
            'coverage':coverage['coverage'],'email_coverage':coverage,
            'new_incoming':new,'comparison':comparison.get('comparison','UNKNOWN'),
            'counts':{state:sum(r['state']==state for r in result) for state in STATES},
            'needs_recheck':sum(r['needs_recheck'] for r in result),
            'known_total':len(result),'manual_sha256':sha(encoded(manual).encode()),
            'history_runs':sorted(set(runs+[run_id])), 'rows':result,
            'triage_rule_version':RULE_VERSION,'message_index_schema':INDEX_VERSION,'message_index':index,
            'triage_contexts':contexts,'triage_history_missing':missing,
            'limits':['數量為此輸出目錄已觀測的來信，非全信箱；首次帶入的歷史信沒有本機處理紀錄。',
                      '新收到依上次完整基準比較，只計 Incoming；重建報告不代表重新收信。',
                      '尚未檢視／待處理／待追蹤跨日保留，只有人工保存才改變狀態。',
                      '已完成只代表這封信的本機處理，不代表正式案件結案或弱點修復。',
                      '來源失敗／不完整時，新收到為 Unknown；已觀測待辦保留，不代表未抓到的信不存在。']}


def validate_record(data, inbox):
    row=next((r for r in inbox['rows'] if r['id']==data['id']),None)
    if not row:raise Invalid('郵件不在本機已觀測清單；禁止憑空標記')
    p=data['payload'];s=row['source']
    if p.get('instance')!=s['instance'] or p.get('email_id')!=s['email_id']:raise Invalid('郵件來源識別不一致')
    if p.get('source_digest')!=s['evidence_sha256']:raise Conflict('郵件證據已變更，請重新讀取後確認')
