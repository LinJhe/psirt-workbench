"""Real loopback HTTP, isolated captures/stores only; no company APIs."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from psirt_casework.service import start,stop,ROOT
from psirt_casework.store import read_snapshot
from psirt_sf_fixtures import sample

class InboxHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.base=Path(cls.tmp.name);cls.root=cls.base/'output'
        cls.capture=sample();sf=cls.capture['sources']['salesforce'];sf['emails']=sf['emails'][:1]
        sf['scope']['instance']='synthetic://http-test'
        cls.run_capture();cls.entry=start(cls.root)
    @classmethod
    def tearDownClass(cls):
        stop(cls.root);cls.tmp.cleanup()
    @classmethod
    def run_capture(cls):
        path=cls.base/'input.json';path.write_text(json.dumps(cls.capture))
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),'--mode','snapshot-replay','--snapshot',str(path),'--output-dir',str(cls.root)],capture_output=True,text=True)
        if result.returncode not in (0,1):raise AssertionError(result.stdout+result.stderr)
        return json.loads(result.stdout)
    def request(self,path,body=None,token=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',int(self.entry['origin'].rsplit(':',1)[1]),timeout=30)
        h={'Origin':self.entry['origin'],'Content-Type':'application/json'}
        if token:h['X-PSIRT-Token']=token
        h.update(headers or {})
        conn.request('GET' if body is None else 'POST',path,body=json.dumps(body) if body is not None else None,headers=h)
        r=conn.getresponse();raw=r.read();result=json.loads(raw) if 'json' in (r.getheader('Content-Type') or '') else raw.decode();status=r.status;conn.close();return status,result
    def state(self):
        status,data=self.request('/api/sf-inbox');self.assertEqual(status,200,data);return data
    def test_01_ui_save_duplicate_conflict_and_restart(self):
        first=self.state();self.assertEqual(first['inbox']['counts']['unreviewed'],1)
        self.assertFalse((self.root/'casework/worklog.sqlite3').exists())
        status,html=self.request('/sf-triage.html');self.assertEqual(status,200);self.assertIn('data-editable="true"',html)
        row=first['inbox']['rows'][0];s=row['source']
        req={'kind':'sf_email','id':row['id'],'payload':{'instance':s['instance'],'email_id':s['email_id'],'source_digest':s['evidence_sha256'],'state':'following','next_action':'Synthetic follow up','reviewer':'DEMO reviewer','followup_at':'2026-10-23T09:00:00+08:00'},'expected_version':0,'operation_id':'http-inbox-save'}
        status,saved=self.request('/api/records',req,first['session']);self.assertEqual(status,200,saved);self.assertTrue(saved['committed_and_read_back'])
        self.assertEqual(self.request('/api/records',req,first['session'])[1]['record'],saved['record'])
        # Lost acknowledgement can be retried even after upstream evidence changed.
        self.capture['sources']['salesforce']['emails'][0]['TextBody']='Changed synthetic source'
        self.run_capture()
        self.assertTrue(self.state()['inbox']['rows'][0]['needs_recheck'])
        self.assertEqual(self.request('/api/records',req,first['session'])[1]['record'],saved['record'])
        stale=copy.deepcopy(req);stale['operation_id']='http-inbox-stale';stale['payload']['next_action']='must not overwrite'
        self.assertEqual(self.request('/api/records',stale,first['session'])[0],409)
        snapshot=read_snapshot(self.root/'casework',True);stop(self.root);type(self).entry=start(self.root)
        self.assertEqual(read_snapshot(self.root/'casework',True),snapshot)
        self.assertEqual(self.state()['inbox']['counts']['following'],1)
    def test_02_same_case_new_reply_is_unreviewed_and_outbound_excluded(self):
        sf=self.capture['sources']['salesforce'];new=copy.deepcopy(sf['emails'][0]);new.update(Id='email-new-reply',MessageDate='2026-10-19T20:00:00+08:00')
        sf['emails'].append(new);sf['emails'].append({**new,'Id':'email-outbound','Incoming':False})
        sf['observed_at']='2026-10-20T09:00:00+08:00';self.capture['config']['cutoff']=sf['observed_at']
        self.run_capture();state=self.state()['inbox']
        self.assertEqual(state['new_incoming'],1);self.assertEqual(state['counts']['following'],1);self.assertEqual(state['counts']['unreviewed'],1)
        self.run_capture();state=self.state()['inbox'];self.assertEqual(state['new_incoming'],0);self.assertEqual(state['known_total'],2)
    def test_03_failure_keeps_mail_and_status_unknown_not_zero(self):
        sf=self.capture['sources']['salesforce'];sf.update(status='FAILED',complete=False,raw=None,emails=[],observed_at='2026-10-21T09:00:00+08:00')
        self.run_capture();state=self.state()['inbox']
        self.assertIsNone(state['new_incoming']);self.assertEqual(state['coverage'],'UNKNOWN');self.assertEqual(state['known_total'],2)
        self.assertEqual(state['counts']['following'],1);self.assertTrue(all(not r['in_current_capture'] for r in state['rows']))
    def test_04_rebuild_html_json_consistency_and_immutable_history(self):
        old=Path(json.loads((self.root/'state.json').read_text())['latest_run']);hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in old.iterdir()}
        state=self.state();manual=read_snapshot(self.root/'casework',True)
        status,result=self.request('/api/rebuild',{},state['session']);self.assertEqual(status,200,result)
        new=Path(result['run_dir']);inbox=json.loads((new/'sf-inbox.json').read_text());triage=json.loads((new/'sf-triage.json').read_text())
        self.assertEqual(inbox,triage['inbox']);self.assertEqual(inbox['manual_sha256'],state['inbox']['manual_sha256'])
        self.assertEqual(inbox['source']['observed_at'],state['inbox']['source']['observed_at'])
        status,html=self.request('/runs/'+new.name+'/sf-triage.html');self.assertEqual(status,200);self.assertIn('data-editable="false"',html)
        self.assertEqual(hashes,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in old.iterdir()})
        self.assertEqual(read_snapshot(self.root/'casework',True),manual)
    def test_05_reject_unobserved_mail_and_cross_origin(self):
        state=self.state();row=state['inbox']['rows'][0];s=row['source']
        req={'kind':'sf_email','id':'unobserved-mail','payload':{'instance':s['instance'],'email_id':'invented','source_digest':s['evidence_sha256'],'state':'done','reviewer':'DEMO'},'expected_version':0,'operation_id':'http-inbox-invented'}
        self.assertEqual(self.request('/api/records',req,state['session'])[0],400)
        self.assertEqual(self.request('/api/records',req,state['session'],{'Origin':'https://invalid.example'})[0],403)
        req.update(id=row['id'],expected_version=row['record']['version'] if row['record'] else 0)
        req['payload'].update(email_id=s['email_id'],source_digest='0'*64,outcome='Synthetic completion')
        self.assertEqual(self.request('/api/records',req,state['session'])[0],409)

if __name__=='__main__':unittest.main()
