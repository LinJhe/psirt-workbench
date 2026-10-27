"""Clearly synthetic correspondence for rule, persistence and browser acceptance."""
import copy

from psirt_sf_fixtures import sample as base


def sample():
    capture=base()
    source=capture['sources']['salesforce']
    source.update(status='SUCCESS',complete=True,observed_at='2026-10-26T09:00:00+08:00')
    source['scope']['instance']='https://synthetic-mail-review.invalid'
    source['scope']['email_window_start']='2026-10-19T00:00:00+08:00'
    capture['config'].update(window_start='2026-10-19T00:00:00+08:00',cutoff=source['observed_at'])
    capture['captured_at']=source['observed_at']
    bodies=[
        ('report','DEMO vulnerability report','Example board v1.0 has a buffer overflow. A public PoC exists; this is an unverified reporter claim.'),
        ('question','DEMO bounty and technical follow-up','What is the bounty range? Has the engineering team reproduced the issue?'),
        ('notice','DEMO system notification','System notification: quarantine may contain a researcher message. Please inspect the quarantine.'),
        ('advert','DEMO webinar invitation','Marketing webinar invitation. Unsubscribe from this promotion.'),
        ('encrypted','DEMO encrypted material','-----BEGIN PGP MESSAGE-----\nSYNTHETIC_CIPHERTEXT\n-----END PGP MESSAGE-----'),
        ('html','DEMO HTML-only inquiry',None),
        ('quoted','DEMO quoted history','Any update on the report?\nOn Monday Example wrote:\nCritical vulnerability. We disclose tomorrow.'),
    ]
    source['raw']=[];source['emails']=[]
    for i,(key,subject,body) in enumerate(bodies):
        parent='case-'+key
        source['raw'].append({'Id':parent,'id':parent,'CaseNumber':'Q-DEMO-'+str(90000+i),
                              'Subject':subject,'Status':'New','IsClosed':False,
                              'Owner':{'Name':'SYNTHETIC queue'},'CreatedDate':'2026-10-19T18:00:00+08:00',
                              'LastModifiedDate':'2026-10-26T08:00:00+08:00'})
        email={'Id':'mail-'+key,'ParentId':parent,'Incoming':True,'Subject':subject,'TextBody':body,
               'MessageDate':'2026-10-19T20:00:00+08:00','Status':'0'}
        if key=='html':
            email['HtmlBody']='<p>What is the PGP public key?</p><img src="https://tracking.invalid/probe"><script>window.mailExecuted=1</script>'
        if key=='encrypted':email['HasAttachment']=True
        source['emails'].append(email)
    for mid,parent,body,status,date in [
        ('auto-reply','case-report','Automatic reply: your report has been received.','3','2026-10-19T20:01:00+08:00'),
        ('human-partial','case-question','The bounty range follows the published policy. The technical question remains open.','3','2026-10-20T09:00:00+08:00'),
        ('draft-reply','case-question','Draft: technical analysis is still pending.','5','2026-10-20T10:00:00+08:00'),
        ('before-incoming','case-question','An older outgoing message cannot answer a later question.','3','2026-10-19T09:00:00+08:00'),
    ]:
        source['emails'].append({'Id':mid,'ParentId':parent,'Incoming':False,'Subject':'Re: DEMO correspondence',
                                 'TextBody':body,'MessageDate':date,'Status':status})
    return capture


def review_request(row, operation='review-save', **overrides):
    source=row['source']
    payload={'instance':source['instance'],'email_id':source['email_id'],
             'source_digest':source['evidence_sha256'],'state':'following',
             'reviewer':'SYNTHETIC reviewer','next_action':'Confirm the remaining technical question.',
             'outcome':'','followup_at':'','review_version':'1','analysis_digest':row['triage']['input_digest'],
             'reviewed_category':'inquiry','reviewed_summary':'Synthetic two-question review.',
             'reviewed_attention':'normal','answer_assessment':'unchecked','reply_ids':'',
             'answer_note':'','reviewed_reply_fact':'unknown','reply_note':''}
    if row.get('record'):payload['correction_reason']='Synthetic review correction'
    payload.update(overrides)
    return {'kind':'sf_email','id':row['id'],'payload':payload,
            'expected_version':(row.get('record') or {}).get('version',0),'operation_id':operation}


def failed(capture):
    result=copy.deepcopy(capture)
    result['sources']['salesforce'].update(status='FAILED',complete=False,raw=None,emails=[],
        observed_at='2026-10-26T10:00:00+08:00',attempted=True,attempted_at='2026-10-26T10:00:00+08:00',
        auth_blocked=True,auth_blocked_at='2026-10-26T10:00:00+08:00',
        auth_error_code='INVALID_OPERATION_WITH_EXPIRED_PASSWORD',
        errors=[{'type':'HTTPError','http_status':401,'error_code':'INVALID_OPERATION_WITH_EXPIRED_PASSWORD'}])
    result['captured_at']=result['config']['cutoff']='2026-10-26T10:00:00+08:00'
    return result
