"""Evidence-bound case timing projections. Pure input/output; no network or writes."""
import hashlib
from datetime import datetime, timedelta
from .store import STAGES, DATE_KINDS, TZ, encoded, timestamp
from .dashboard import build as build_dashboard
from .effort import summarize_work, unique_work

RULE_VERSION = 'case-timing/5'


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def case_ids(payload):
    return sorted(set(payload.get('case_ids', []) + ([payload['case_id']] if payload.get('case_id') else [])))


def union_minutes(intervals):
    """Elapsed waiting: union, not the sum of overlapping waits."""
    if not intervals: return 0
    ordered=sorted(intervals)
    start,end=ordered[0]; total=0
    for a,b in ordered[1:]:
        if a<=end: end=max(end,b)
        else: total+=(end-start).total_seconds()/60;start,end=a,b
    return round(total+(end-start).total_seconds()/60, 3)


def stage_visits(revisions):
    visits=[]
    for rev in sorted(revisions,key=lambda r:r['version']):
        p=rev['payload']
        # Legacy records retain their original first-version identity. New Store
        # revisions carry the server-selected visit ID; corrected times do not split it.
        identity=p.get('stage_visit_id')
        if not identity:
            identity=visits[-1]['id'] if visits and p.get('stage')==visits[-1]['stage'] else str(rev['id'])+':'+str(rev['version'])
        if not visits or identity!=visits[-1]['id']:
            visits.append({'id':identity,'event':'reentry' if p.get('stage_event')=='reenter' else 'transition' if visits else 'initial',
                           'first_version':rev['version'], 'revisions':[]})
        visit=visits[-1]
        visit.update(stage=p.get('stage','unknown'), confirmation=p.get('stage_confirmation','pending'),
                     entered_at=p.get('entered_at') or None, exited_at=p.get('exited_at') or None,
                     entry_evidence=p.get('entry_evidence') or None, exit_evidence=p.get('exit_evidence') or None,
                     evidence=p.get('evidence') or None, reviewer=p.get('reviewer') or None)
        visit['revisions'].append(rev['version'])
    for i,v in enumerate(visits):
        v['current']=i==len(visits)-1 and not v['exited_at']
        entered,exited=timestamp(v['entered_at']),timestamp(v['exited_at'])
        v['duration_minutes']=round((exited-entered).total_seconds()/60,3) if entered and exited and v['entry_evidence'] and v['exit_evidence'] and v['confirmation']=='confirmed' else None
        v['unclosed_history']=i<len(visits)-1 and not exited
    return visits


def deadline(item,kind,as_of):
    base={'kind':kind,'label':DATE_KINDS[kind],'at':item.get('at') or None,'basis':item,'state':'UNKNOWN'}
    at=timestamp(item.get('at'))
    if item.get('confirmation')!='confirmed' or not at or not item.get('evidence') or not item.get('confirmed_by'): return base
    if kind=='remediation' and not all(item.get(k) for k in ('basis_version','trigger_event','scope')): return base
    if kind in ('estimate','ai_suggestion'):
        base['state']='REFERENCE_ONLY';return base
    complete=timestamp(item.get('completed_at')) if item.get('completion_evidence') else None
    if complete and complete<=as_of:
        base['state']='COMPLETED_LATE' if complete>at else 'COMPLETED'
    elif at<=as_of:
        base['state']={'followup':'FOLLOWUP_DUE','commitment':'COMMITMENT_OVERDUE','remediation':'REMEDIATION_DUE_EXCEEDED'}[kind]
    else: base['state']='CONFIRMED_FUTURE'
    return base


from .effective import conflicts as review_conflicts, resolve, summary


def build(capture,manual,legacy,as_of,previous=None,fallback=None,run_id='',fallback_ref='last_successful_capture.json',effective=None):
    effective=effective or resolve(manual,legacy)
    moment=timestamp(as_of)
    if not moment: raise ValueError('as_of required')
    jira=capture['sources']['jira']
    fresh=jira.get('status')=='SUCCESS' and jira.get('complete') is True
    source=jira if fresh or jira.get('raw') else (fallback or jira)
    stale=source is not jira
    source_rows={r.get('key',r.get('id')):r for r in source.get('raw') or []}
    source_indices={r.get('key',r.get('id')):i for i,r in enumerate(source.get('raw') or [])}
    records=manual.get('records',[]); revisions=manual.get('revisions',[])
    cases={r['id']:r for r in records if r['kind']=='case'}
    work=unique_work([r for r in records if r['kind']=='worklog']); waits=[r for r in records if r['kind']=='wait']; deliveries=[r for r in records if r['kind']=='delivery']
    ids={k for k,r in source_rows.items() if r.get('fields',{}).get('status',{}).get('statusCategory',{}).get('key')!='done'}|set(cases)
    for rec in work+waits+deliveries: ids.update(case_ids(rec['payload']))
    rows=[]
    week_start=(moment-timedelta(days=moment.weekday())).replace(hour=0,minute=0,second=0,microsecond=0)
    legacy_reviews=legacy.get('reviews',{}) if legacy.get('schema')=='psirt-human-review/1' else {}
    for key in sorted(ids):
        r=source_rows.get(key,{}); f=r.get('fields',{}); saved=cases.get(key);p=saved['payload'] if saved else {}
        old=legacy_reviews.get(key,{})
        resolved=effective['cases'].get(key,{'fields':{},'record_version':None})
        ef=resolved['fields']
        def confirmed(name):
            return ef.get(name,{}).get('value') if ef.get(name,{}).get('state')=='CONFIRMED' else None
        conflict=review_conflicts(p,old) if saved else {'items':[],'state':'LEGACY_READ_ONLY' if old else 'NONE','legacy_digest':digest(old),'legacy':old}
        verified=p.get('stage_confirmation')=='confirmed' and p.get('evidence') and p.get('reviewer') and not p.get('exited_at')
        entered=timestamp(p.get('entered_at'))
        verified=verified and (not entered or entered<=moment)
        stage=p.get('stage','unknown') if verified else 'unknown'
        elapsed=round((moment-entered).total_seconds()/60,3) if verified and entered and entered<=moment and p.get('entry_evidence') else None
        history=stage_visits([v for v in revisions if v['kind']=='case' and v['id']==key])
        accepted=p.get('accepted_by') if p.get('acceptance')=='confirmed' and p.get('owner_kind')=='person' and all(p.get(k) for k in ('acceptance_evidence','accepted_at')) else None
        own_work=[w for w in work if key in case_ids(w['payload'])]
        own_waits=[w for w in waits if w['payload'].get('case_id')==key]
        intervals=[];wait_unknown=False
        for w in own_waits:
            a=timestamp(w['payload'].get('start')); b=timestamp(w['payload'].get('end')) or moment
            if a and a<=moment and b>=a and w['payload'].get('evidence'): intervals.append((a,min(b,moment)))
            else: wait_unknown=True
        dates={kind:deadline(p.get('dates',{}).get(kind,{}),kind,moment) for kind in DATE_KINDS}
        accepted=confirmed('accepted_by')
        for kind in DATE_KINDS:
            field=ef.get('dates.'+kind,{})
            if field.get('state')=='CONFLICT': dates[kind]['state']='UNKNOWN'
            if not saved and field.get('value'):
                dates[kind]=deadline({'at':field['value'],'confirmation':'confirmed' if field['state']=='CONFIRMED' else 'pending','evidence':field.get('evidence'),'confirmed_by':old.get('reviewer')},kind,moment)
        # Each displayed manual field uses the same versioned authority as reports.
        rows.append({'id':key,'summary':f.get('summary') or key,'jira_status':f.get('status',{}).get('name'),
          'jira_status_category':f.get('status',{}).get('statusCategory',{}).get('key'),
          'assignee':(f.get('assignee') or {}).get('displayName'),'source_present':bool(r),'source_historical':stale,
          'source_observed_at':source.get('observed_at'),'source_status':jira.get('status'),'source_complete':fresh,
          'source_ref':(fallback_ref if stale else 'capture.json')+'#/sources/jira/raw/'+str(source_indices[key]) if key in source_indices else None,
          'product':p.get('product') or None,'product_version':p.get('product_version') or None,
          'record':saved,'stage':stage,'stage_label':STAGES.get(stage,STAGES['unknown'])[0],
          'entered_at':p.get('entered_at') or None,'elapsed_minutes':elapsed,'stage_visits':history,
          'accepted_by':accepted,'dates':dates,'deliverable':confirmed('deliverable'),'exit_conditions':confirmed('exit_conditions'),
          'next_action':confirmed('next_action'),'blocker':confirmed('blocker'),
          'effective_manual':resolved,'manual_summary':summary(resolved),
          'worklogs':own_work,'actual_minutes':summarize_work(own_work,moment)['actual_minutes'],
          'waits':own_waits,'waiting_minutes':union_minutes(intervals) if own_waits and not wait_unknown else None,
          'deliveries':[d for d in deliveries if key in case_ids(d['payload'])],
          'legacy_review':conflict,'revisions':[v for v in revisions if v['kind']=='case' and v['id']==key]})
    stage_ids={k:[r['id'] for r in rows if r['stage']==k] for k in STAGES}
    categories={'commitment_overdue':[r['id'] for r in rows if r['dates']['commitment']['state']=='COMMITMENT_OVERDUE'],
      'followup_due':[r['id'] for r in rows if r['dates']['followup']['state']=='FOLLOWUP_DUE'],
      'remediation_exceeded':[r['id'] for r in rows if r['dates']['remediation']['state']=='REMEDIATION_DUE_EXCEEDED'],
      'deadline_unknown':[r['id'] for r in rows if r['dates']['remediation']['state']=='UNKNOWN'],
      'acceptance_unknown':[r['id'] for r in rows if not r['accepted_by']],
      'stage_unknown':stage_ids['unknown'], 'conflicts':[r['id'] for r in rows if r['legacy_review']['state']=='CONFLICT']}
    compatibility={'scope':jira.get('scope'),'synthetic':capture.get('synthetic'),'rule':RULE_VERSION,'week_start':week_start.isoformat()}
    comparable=bool(previous and previous.get('compatibility')==compatibility and previous.get('source',{}).get('complete') and fresh and timestamp(previous['as_of'])<=moment)
    prior_visits={v['id'] for v in (previous or {}).get('weekly',{}).get('stage_changes',[])}
    prior_reentries={v['id'] for v in (previous or {}).get('weekly',{}).get('reentries',[])}
    entries=[{'case_id':r['id'],**v} for r in rows for v in r['stage_visits'] if v['stage']!='unknown' and v['confirmation']=='confirmed' and v['entry_evidence'] and v['reviewer'] and timestamp(v['entered_at']) and week_start<=timestamp(v['entered_at'])<=moment]
    transitions=[{'case_id':r['id'],**v} for r in rows for i,v in enumerate(r['stage_visits']) if i>0 and r['stage_visits'][i-1]['confirmation']=='confirmed' and r['stage_visits'][i-1]['stage']!=v['stage'] and v['stage']!='unknown' and v['confirmation']=='confirmed' and v['entry_evidence'] and v['reviewer'] and timestamp(v['entered_at']) and week_start<=timestamp(v['entered_at'])<=moment]
    reentries=[v for v in entries if v.get('event')=='reentry']
    received=[d for d in deliveries if week_start<=timestamp(d['payload']['received_at'])<=moment]
    effort=summarize_work(work,moment)
    wait_intervals=[]; wait_unknown=False
    for w in waits:
        p=w['payload'];a=timestamp(p.get('start'));b=timestamp(p.get('end')) or moment
        if a and a<=moment and b>=a and p.get('evidence'): wait_intervals.append((a,min(b,moment)))
        else: wait_unknown=True
    result={'schema':RULE_VERSION,'run_id':run_id,'synthetic':capture.get('synthetic'),'as_of':moment.isoformat(),
      'source':{'status':jira.get('status'),'complete':fresh,'observed_at':jira.get('observed_at'),'displayed_at':source.get('observed_at'),'historical':stale,'scope':jira.get('scope'),'index_count':len(jira.get('raw') or []) if fresh else None},
      'compatibility':compatibility,'manual_sha256':digest(manual),'manual_available':manual.get('available'),
      'manual_version':sum(r['version'] for r in records),'legacy_sha256':digest(legacy),'legacy_schema_supported':legacy.get('schema')=='psirt-human-review/1',
      'write_authority':'Store only; legacy human_review.json read-only; conflicts explicit',
      'cases':rows,'stages':{k:{'label':STAGES[k][0],'count':len(v) if fresh else None,'observed_count':len(v),'case_ids':v} for k,v in stage_ids.items()},
      'counts':{'total':len(rows) if fresh else None,**{k:len(v) if fresh else None for k,v in categories.items()}},
      'observed_count':len(rows),'category_case_ids':categories,
      'worklogs':work,'waits':waits,'deliveries':deliveries,
      'effort':{**effort,
         'waiting_union_minutes':union_minutes(wait_intervals) if waits and not wait_unknown else None},
      'weekly':{'start':week_start.isoformat(),'end':moment.isoformat(),'comparison':'COMPARABLE' if comparable else 'UNKNOWN',
         'reason':None if comparable else '需要同範圍、同週期、同規則且來源完整的可比較基線',
         'stage_change_count':len(transitions) if comparable else None,'stage_changes':transitions,
         'new_stage_changes':[v for v in transitions if v['id'] not in prior_visits] if comparable else None,'stage_entries':entries,
         'reentry_count':len(reentries) if comparable else None,'reentries':reentries,
         'new_reentries':[v for v in reentries if v['id'] not in prior_reentries] if comparable else None,
         'received_count':len(received) if comparable else None,'observed_received_count':len(received),'received':received,
         'accepted_count':sum(d['payload'].get('acceptance')=='accepted' for d in received) if comparable else None},
      'limits':['候選階段分類，非核准公司 SOP','未填期限不是準時；未填工時不是零','案件各列共用工時不能相加；總工時以唯一工作 ID 計算','本機結案節點不等於 Jira 關單或修復完成','沒有以等待時間扣除期限；沒有計算工作日 SLA']}
    result['dashboard']=build_dashboard(result)
    return result
