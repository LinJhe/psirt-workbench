import copy
import json
import sys
from pathlib import Path
from unittest.mock import patch

import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from psirt_ops.pipeline import compare, run, encoded, sha
from psirt_ops.reports import analyze, daily_markdown
from psirt_ops.adapters import dt_pages, paginate_jira, sf_query, Reader


def capture():
    cfg = json.loads((ROOT/'scripts/psirt_ops/scope_20261016.json').read_text())
    cfg['cutoff'] = '2026-10-16T12:00:00+08:00'
    sources = {n: {'status':'SUCCESS', 'complete':True, 'synthetic':True,
                  'scope':{'test':'only'}, 'source_version':'test/1', 'schema_version':'1',
                  'rule_version':'1', 'observed_at':cfg['cutoff'], 'pages':[], 'raw':[]}
               for n in ('kev','dt','salesforce','jira')}
    sources['kev']['raw'] = {'catalogVersion':'2026.10.16','dateReleased':cfg['cutoff'],
                             'title':'Synthetic test', 'count':1,'vulnerabilities':[{'cveID':'CVE-2026-99999','dateAdded':'2026-01-01'}]}
    return {'capture_schema':'psirt-ops/1', 'synthetic':True, 'config':cfg,
            'captured_at':cfg['cutoff'], 'sources':sources, 'weekly_template':{'status':'FAILED'},
            'background':{'rows':[]}}


def comparisons(c):
    return {n:compare(n,s) for n,s in c['sources'].items()}


def test_first_baseline_delta_then_no_repeat():
    old=capture()['sources']['jira']
    assert compare('jira',old)['counts'] is None
    new=copy.deepcopy(old);new['raw']=[{'id':'one','status':'new'}]
    assert compare('jira',new,old)['counts']=={'added':1,'changed':0,'removed':0}
    assert compare('jira',new,new)['counts']=={'added':0,'changed':0,'removed':0}


def test_incomplete_never_zero():
    for status in ('FAILED','PARTIAL'):
        check_incomplete(status)

def check_incomplete(status):
    c=capture();old=copy.deepcopy(c['sources']['jira'])
    c['sources']['jira'].update(status=status,complete=False,raw=None)
    result=compare('jira',c['sources']['jira'],old)
    assert result['counts'] is None and result['comparison']=='SOURCE_INCOMPLETE'
    text=daily_markdown(c,analyze(c,comparisons(c),{'reviews':{}}),comparisons(c),'snapshot-replay','test')
    assert 'created 新增：Unknown' in text


def test_scope_and_version_changes_are_not_diff():
    src=capture()['sources']['jira']
    for field,value in [('scope',{'other':1}),('source_version','2'),('rule_version','2')]:
        new=copy.deepcopy(src);new[field]=value
        assert compare('jira',new,src)['comparison']=='INCOMPATIBLE_BASELINE'
        assert compare('jira',new,src)['counts'] is None


def test_sf_new_reply_on_closed_case_explicit_jira_link():
    c=capture();s=c['sources'];date=c['config']['cutoff']
    s['salesforce']['raw']=[{'id':'c1','Id':'c1','CaseNumber':'Q-202610-12345',
                           'CreatedDate':date,'IsClosed':True,'Status':'Closed'}]
    s['salesforce']['emails']=[{'Id':'e1','ParentId':'c1','MessageDate':date}]
    s['jira']['raw']=[{'id':'DEMO-1','key':'DEMO-1','fields':{
        'summary':'Q-202610-12345','created':date,'updated':date,
        'status':{'name':'Done','statusCategory':{'key':'done'}}}}]
    result=analyze(c,comparisons(c),{'reviews':{}})
    assert result['sf_activity'][0]['jira_keys']==['DEMO-1']
    assert not result['sf_activity'][0]['candidate']
    assert len(result['new_issues'])==1 and not result['open_issues']
    old=copy.deepcopy(s['salesforce']);old['emails']=[]
    assert compare('salesforce',s['salesforce'],old)['email_counts']['added']==1
    assert compare('salesforce',s['salesforce'],s['salesforce'])['email_counts']['added']==0


def test_exact_cve_only_and_assignee_not_acceptance():
    c=capture();s=c['sources']
    # analyze accepts the rows; index validation is separately inherited from fetch_kev.
    s['kev']['raw']['vulnerabilities']=[{'cveID':'CVE-2026-1234','dateAdded':'2026-10-13'}]
    s['dt']['raw']=[{'id':'hit','vulnerability':{'vulnId':'CVE-2026-1234'}},
                    {'id':'no','vulnerability':{'vulnId':'CVE-2026-12345'}}]
    s['jira']['raw']=[{'id':'DEMO-202','key':'DEMO-202','fields':{
        'summary':'test','status':{'name':'In Progress'},'assignee':{'displayName':'A'}}}]
    comp={n:{'changes':None} for n in s}
    result=analyze(c,comp,{'reviews':{}})
    assert [m['finding']['id'] for m in result['kev_dt_matches']]==['hit']
    assert result['actions'][0]['accepted_by'] is None
    assert 'FIELD_UNVERIFIED_NEXT_ACTION' in result['actions'][0]['review_reasons']


def test_followup_case_references_existing_jira_and_filters_intake_hints():
    c=capture();s=c['sources'];date=c['config']['cutoff']
    s['jira']['raw']=[{'id':'DEMO-202','key':'DEMO-202','fields':{
        'summary':'Q-202609-54706', 'status':{'name':'In Progress'}}}]
    s['salesforce']['raw']=[{'id':str(i),'Id':str(i),'CaseNumber':'Q-202610-6000'+str(i),
        'CreatedDate':date,'Subject':title} for i,title in enumerate([
            '[PSIRT] Follow-up','Microsoft 365 security: You have messages in quarantine',
            'Security Report - credentials','Promotion'])]
    s['salesforce']['emails']=[{'Id':'e1','ParentId':'0','Incoming':True,
                                'TextBody':'Following up Q-202609-54706','MessageDate':date}]
    rows=analyze(c,comparisons(c),{'reviews':{}})['sf_activity']
    assert rows[0]['jira_keys']==['DEMO-202'] and not rows[0]['candidate']
    assert rows[0]['link_evidence'][0]['email_id']=='e1'
    assert [r['candidate'] for r in rows]==[False,False,True,False]


class FakeReader:
    def __init__(self,pages):self.pages=iter(pages);self.urls=[]
    def get(self,url,headers=None):self.urls.append(url);return next(self.pages)


def test_dt_pages_requires_total_and_complete_count():
    reader=FakeReader([([{'uuid':'a'}],{'X-Total-Count':'2'}),([{'uuid':'b'}],{'X-Total-Count':'2'})])
    rows,pages,ok=dt_pages(reader,'https://example.test/api',{})
    assert ok and len(rows)==2 and len(pages)==2
    assert 'pageNumber=2' in reader.urls[1]
    assert not dt_pages(FakeReader([([], {})]),'https://example.test',{})[2]
    assert not dt_pages(FakeReader([([{}],{'X-Total-Count':'2'}),([] ,{'X-Total-Count':'2'})]),'https://example.test',{})[2]


def test_jira_repeated_page_is_partial():
    def get(path,params):return {'issues':[{'key':'one'}],'startAt':0,'total':2}
    assert not paginate_jira(get,'search',{},'issues')[2]


def test_sf_pagination_duplicate_id_and_external_next_url_rejected():
    pages=[({'records':[{'Id':'1'}],'done':False,'totalSize':2,'nextRecordsUrl':'/services/data/v58.0/query/next'},{}),
           ({'records':[{'Id':'1'}],'done':True,'totalSize':2},{})]
    assert not sf_query(FakeReader(pages),'https://example.test','unused','SELECT')[2]
    pages=[({'records':[],'done':False,'totalSize':1,'nextRecordsUrl':'https://evil.test'}, {})]
    assert not sf_query(FakeReader(pages),'https://example.test','unused','SELECT')[2]


def test_transport_rejects_business_writes():
    with unittest.TestCase().assertRaises(PermissionError):Reader().transport('POST','https://example.test',{},b'{}')


def test_runs_preserve_review_baseline_and_integrity(tmp_path):
    c=capture();snap=tmp_path/'input.json';snap.write_bytes(encoded(c));out=tmp_path/'out'
    # Avoid permanently changing pytest's audit hooks; guard itself has Gate 1 coverage.
    with patch('psirt_daily.offline.install_offline_guard'):
        first=run(out,'snapshot-replay',snapshot=snap)
        review=out/'human_review.json'
        original=b'{"schema":"psirt-human-review/1","reviews":{"DEMO-199":{"note":"preserve this"}}}\n'
        review.write_bytes(original)
        second=run(out,'snapshot-replay',snapshot=snap)
        assert review.read_bytes()==original
        assert all(v['counts']=={'added':0,'changed':0,'removed':0} for v in second['comparisons'].values())
        before=json.loads((out/'state.json').read_text())['baselines']['jira']
        c['sources']['jira'].update(status='FAILED',complete=False,raw=None)
        snap.write_bytes(encoded(c));third=run(out,'snapshot-replay',snapshot=snap)
        assert third['exit_code']==1
        assert json.loads((out/'state.json').read_text())['baselines']['jira']==before
        saved=out/before['path'];saved.write_text('{}')
        with unittest.TestCase().assertRaisesRegex(ValueError,'BaselineHashMismatch'):run(out,'snapshot-replay',snapshot=snap)


def test_unmanaged_and_mixed_mode_outputs_refused(tmp_path):
    (tmp_path/'existing').write_text('keep')
    with unittest.TestCase().assertRaisesRegex(ValueError,'OutputMustBeEmpty'):run(tmp_path,'live',{})
    assert (tmp_path/'existing').read_text()=='keep'


class OpsTests(unittest.TestCase):
    pass


def wrap(fn):
    def method(self):
        if fn.__code__.co_argcount:
            with tempfile.TemporaryDirectory() as directory:
                fn(Path(directory))
        else:
            fn()
    return method


for name, fn in list(globals().items()):
    if name.startswith('test_') and callable(fn):
        setattr(OpsTests, name, wrap(fn))

if __name__ == '__main__':
    unittest.main()
