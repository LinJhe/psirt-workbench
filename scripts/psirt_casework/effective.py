"""One field-level human authority, frozen before any report is generated.

Source Jira fields never enter this resolver. Legacy remains immutable evidence.
Conflicting fields are withheld until the reviewer selects the Store version and
records the exact legacy digest. Pending inputs remain visible as pending.
"""
import hashlib
import copy
from .store import encoded, STAGES, DATE_KINDS, timestamp, Invalid


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def conflicts(p, old):
    pairs={'accepted_by':'accepted_by','next_action':'source_next_action',
           'dates.followup':'next_follow_up_at','dates.remediation':'remediation_due_at'}
    items=[]
    for field, legacy in pairs.items():
        current=p.get('dates',{}).get(field.split('.')[1],{}).get('at') if field.startswith('dates.') else p.get(field)
        same=current==old.get(legacy)
        if current and old.get(legacy) and field.startswith('dates.'):
            try:same=timestamp(current)==timestamp(old[legacy])
            except Invalid:pass
        if old.get(legacy) and not same:
            items.append({'field':field,'legacy':old[legacy],'store':current})
    resolved=bool(items and p.get('legacy_resolution') and p.get('reviewer') and p.get('correction_reason') and p.get('legacy_digest')==digest(old))
    return {'items':items,'state':'RESOLVED_EXPLICITLY' if resolved else 'CONFLICT' if items else 'NONE',
            'legacy_digest':digest(old),'resolution':p.get('legacy_resolution'),'choice':'store' if resolved else None,'legacy':old}


def resolve(manual, legacy):
    saved={r['id']:r for r in manual.get('records',[]) if r['kind']=='case'}
    old=legacy.get('reviews',{}) if legacy.get('schema')=='psirt-human-review/1' else {}
    cases={}; reviews={}; sf_reviews=copy.deepcopy(old)
    for key in sorted(set(saved)|set(old)):
        record=saved.get(key); p=(record or {}).get('payload',{}); prior=old.get(key,{})
        conflict=conflicts(p,prior) if record else {'state':'LEGACY_READ_ONLY','items':[],'legacy':prior,'legacy_digest':digest(prior)}
        blocked={i['field'] for i in conflict['items']} if conflict['state']=='CONFLICT' else set()
        fields={}
        def put(name,value,confirmed,evidence=None):
            state='CONFLICT' if name in blocked else 'CONFIRMED' if value and confirmed else 'PENDING' if value else 'UNKNOWN'
            fields[name]={'value':value or None,'state':state,'evidence':evidence or None,'source':'store' if record else 'legacy',
                          'source_version':record['version'] if record else digest(prior)}
        if record:
            checked=p.get('record_confirmation')=='confirmed' and p.get('reviewer') and p.get('evidence')
            put('stage',p.get('stage') if p.get('stage')!='unknown' else None,p.get('stage_confirmation')=='confirmed' and p.get('evidence') and p.get('reviewer') and not p.get('exited_at'),p.get('evidence'))
            put('accepted_by',p.get('accepted_by'),p.get('acceptance')=='confirmed' and p.get('owner_kind')=='person' and p.get('accepted_at') and p.get('acceptance_evidence'),p.get('acceptance_evidence'))
            for name in ('deliverable','next_action','blocker','exit_conditions'):put(name,p.get(name),checked,p.get('evidence'))
            for kind in DATE_KINDS:
                item=p.get('dates',{}).get(kind,{})
                confirmed=item.get('confirmation')=='confirmed' and item.get('evidence') and item.get('confirmed_by') and kind!='ai_suggestion'
                if kind=='remediation':confirmed=confirmed and all(item.get(k) for k in ('basis_version','trigger_event','scope'))
                put('dates.'+kind,item.get('at'),confirmed,item)
        else:
            verified=prior.get('verification')=='VERIFIED_BY_HUMAN' and prior.get('reviewer') and prior.get('evidence_ref')
            for name,source in [('accepted_by','accepted_by'),('next_action','source_next_action'),('dates.followup','next_follow_up_at')]:put(name,prior.get(source),verified,prior.get('evidence_ref'))
            # Old due-date text lacks the policy/version/trigger needed for a formal deadline.
            put('dates.remediation',prior.get('remediation_due_at'),False,prior.get('evidence_ref'))
        def value(name):
            f=fields.get(name,{})
            return f.get('value') if f.get('state')=='CONFIRMED' else None
        review={**prior,'verification':('VERIFIED_BY_HUMAN' if any(f['state']=='CONFIRMED' for f in fields.values()) else 'UNVERIFIED'),'reviewer':p.get('reviewer') or prior.get('reviewer') or 'local field resolver',
                'evidence_ref':('effective_manual_used.json#/cases/'+key) if record else prior.get('evidence_ref'),
                'accepted_by':value('accepted_by'),'source_next_action':value('next_action'),
                'next_follow_up_at':value('dates.followup'),'remediation_due_at':value('dates.remediation')}
        cases[key]={'id':key,'record_version':record['version'] if record else None,'fields':fields,'conflict':conflict}
        reviews[key]=review
        if key in sf_reviews:
            sf_reviews[key]['accepted_by']=value('accepted_by')
            sf_reviews[key]['effective_acceptance']=fields.get('accepted_by',{})
            sf_reviews[key]['source_next_action']=value('next_action')
    return {'schema':'psirt-effective-manual/1','manual_sha256':digest(manual),'legacy_sha256':digest(legacy),
            'cases':cases,'review':{'schema':'psirt-human-review/1','reviews':reviews},
            'sf_review':{'schema':'psirt-human-review/1','reviews':sf_reviews}}


def summary(case):
    if not case:return ''
    labels={'stage':'階段','accepted_by':'承接','deliverable':'下一交付','next_action':'下一步','blocker':'卡點',
            **{'dates.'+k:v for k,v in DATE_KINDS.items()}}
    states={'CONFIRMED':'已確認','PENDING':'待確認','CONFLICT':'衝突未解決','UNKNOWN':'待確認'}
    parts=[]
    for name,label in labels.items():
        f=case['fields'].get(name,{})
        if not f.get('value'):continue
        value=STAGES.get(f['value'],(f['value'],))[0] if name=='stage' else f['value']
        parts.append(label+'：'+str(value)+'（'+states[f['state']]+'）')
    return '本機人工 v'+str(case.get('record_version') or 'legacy')+'；'+'；'.join(parts) if parts else ''
