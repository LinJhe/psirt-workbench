"""Synthetic intake evidence; never real case IDs, contacts or credentials."""
import copy
from psirt_dt_fixtures import sample as dt_sample


def sample():
    c=dt_sample();s=c['sources']['salesforce'];s['emails']=[]
    for i,title in enumerate(['Ordinary link notice','Security report — Example SDK v1.00','Old pending example','Duplicate message','Duplicate message']):
        cid='case-'+str(i);date='2026-10-17T01:00:00+0000' if i!=2 else '2026-09-01T01:00:00+0000'
        s['raw'].append({'Id':cid,'id':cid,'CaseNumber':'Q-202610-9000'+str(i),'Subject':title,'CreatedDate':date,'LastModifiedDate':date,'Status':'New','IsClosed':False,'Owner':{'Name':'Fixture queue'}})
        if i==2:continue
        body=('Impact\nAn old link may remain valid.\nSeverity\n*Medium*\nSteps to Reproduce\nUser action.' if i==0 else
              'A potential vulnerability in the Example SDK v1.00. The encrypted archive contains reproduction logs.' if i==1 else
              'Product: Example board\nFirmware: 1.10\nIssue: Sample claim\nSeverity: High (CVSS 3.1 9.6)\nAccess: unauthenticated\nNot shared publicly.')
        s['emails'].append({'Id':'email-'+str(i),'ParentId':cid,'Incoming':True,'MessageDate':date,'Subject':title,'TextBody':body})
    s['raw'][2]['Product__c']=None
    return c


def failure():
    c=sample();c['sources']['jira'].update(status='FAILED',complete=False,raw=None);return c


def hostile():
    c=sample();c['sources']['salesforce']['emails'][0]['TextBody']='<img src="https://evil.invalid/probe" onerror="window.pwned=1"><script>window.pwned=1</script>\nContact: someone@example.invalid\n-----BEGIN PGP MESSAGE-----\nHIDDEN_CIPHERTEXT\n-----END PGP MESSAGE-----\napi_key: HIDDEN_SECRET'
    return c
