"""Real HTTP behavior with isolated stores; seed/rebuild subprocesses forbid network."""
import copy
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from psirt_casework.service import start, stop, inspect, ROOT
from psirt_casework.store import Store, read_snapshot
from test_psirt_casework import sample, case, work, date_item

class LocalServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.base=Path(cls.tmp.name);cls.root=cls.base/'output'
        cls.capture=cls.base/'capture.json';cls.capture.write_text(json.dumps(sample()))
        cls.seed()
        cls.entry=start(cls.root);cls.port=int(cls.entry['origin'].rsplit(':',1)[1]);cls.origin=cls.entry['origin']
    @classmethod
    def seed(cls):
        subprocess.run([sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),'--mode','snapshot-replay','--snapshot',str(cls.capture),'--output-dir',str(cls.root)],check=True,stdout=subprocess.DEVNULL)
    @classmethod
    def tearDownClass(cls):
        stop(cls.root);cls.tmp.cleanup()
    def request(self,path,body=None,headers=None,method=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=20)
        h={'Origin':self.origin,'Content-Type':'application/json'};h.update(headers or {})
        conn.request(method or ('POST' if body is not None else 'GET'),path,body=json.dumps(body) if body is not None else None,headers=h)
        r=conn.getresponse();raw=r.read();status=r.status;ctype=r.getheader('Content-Type');conn.close()
        return status,json.loads(raw) if 'application/json' in (ctype or '') else raw
    def state(self):
        status,x=self.request('/api/state');self.assertEqual(status,200);return x
    def post(self,path,body,token=None):return self.request(path,body,{'X-PSIRT-Token':token or self.state()['session']})
    def test_01_save_readback_idempotency_stale_reopen(self):
        state=self.state();oldrun=Path(json.loads((self.root/'state.json').read_text())['latest_run'])
        hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in oldrun.iterdir()}
        legacy=(self.root/'human_review.json').read_bytes()
        p=case();p.update(record_confirmation='confirmed',deliverable='Synthetic reviewed build manifest',next_action='Synthetic arrange verification',dates={'followup':date_item('2026-10-21T09:00:00+08:00')})
        req={'kind':'case','id':'DEMO-177','payload':p,'expected_version':0,'operation_id':'http-case-operation'}
        status,r=self.post('/api/records',req,state['session']);self.assertEqual(status,200);self.assertTrue(r['committed_and_read_back']);self.assertEqual(r['current']['version'],1)
        self.assertEqual(self.post('/api/records',req)[1]['record'],r['record'])
        bad=copy.deepcopy(req);bad['operation_id']='http-stale-operation';bad['payload']['deliverable']='must not win'
        self.assertEqual(self.post('/api/records',bad)[0],409)
        self.assertEqual(len(Store(self.root/'casework',True).history('case','DEMO-177')),1)
        before=Store(self.root/'casework',True).snapshot();stop(self.root);entry=start(self.root)
        type(self).port=int(entry['origin'].rsplit(':',1)[1]);type(self).origin=entry['origin']
        self.assertEqual(before,Store(self.root/'casework',True).snapshot())
        self.assertEqual(self.state()['projection']['cases'][0]['deliverable'],p['deliverable'])
        self.assertEqual(self.post('/api/records',req)[0],200)
        status,result=self.post('/api/rebuild',{});self.assertEqual(status,200,result)
        run=Path(result['run_dir']);self.assertNotEqual(run,oldrun)
        for name in ('Daily_PSIRT.md','Vance_Action_List.md','Weekly_PSIRT_Company_Format.md','casework.html'):
            self.assertIn(p['deliverable'],(run/name).read_text(),name)
            self.assertIn(p['next_action'],(run/name).read_text(),name)
            self.assertIn('2026-10-21T09:00:00+08:00',(run/name).read_text(),name)
        self.assertEqual(hashes,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in oldrun.iterdir()})
        self.assertEqual(legacy,(self.root/'human_review.json').read_bytes())
        self.assertEqual(before,Store(self.root/'casework',True).snapshot())
        self.assertTrue(start(self.root)['reused'])
    def test_02_security_fixed_paths_origin_host_token_fields(self):
        for origin in ('https://attacker.invalid','null'):
            self.assertEqual(self.request('/api/records',{}, {'Origin':origin,'X-PSIRT-Token':self.state()['session']})[0],403)
        self.assertEqual(self.request('/api/records',{})[0],403)
        self.assertEqual(self.request('/api/state',headers={'Host':'attacker.invalid'})[0],403)
        self.assertEqual(self.post('/api/records',{'unexpected':'field'})[0],400)
        for path in ('/.env','/../.env','/%2e%2e/.env','/casework/worklog.sqlite3','/.casework-service.json','/scripts/run_psirt_ops.py','/runs/../manifest.json'):
            self.assertEqual(self.request(path)[0],404,path)
        self.assertEqual(self.request('/health')[0],403)
        self.assertEqual(self.request('/api/state',headers={'Origin':'https://attacker.invalid'})[0],403)
    def test_03_shared_work_and_backup_restore(self):
        req={'kind':'worklog','id':'shared-http','payload':work(),'expected_version':0,'operation_id':'shared-http-operation'}
        self.assertEqual(self.post('/api/records',req)[0],200);self.assertEqual(self.post('/api/records',req)[0],200)
        self.assertEqual(self.state()['projection']['effort']['actual_minutes'],30)
        status,b=self.post('/api/backup',{});self.assertEqual(status,200)
        before=Store(self.root/'casework',True).snapshot();target=self.base/'restored';target.mkdir();(target/'worklog.sqlite3').write_bytes(Path(b['path']).read_bytes())
        self.assertEqual(before,read_snapshot(target,True))
    def test_04_failed_source_keeps_manual_and_history(self):
        before=Store(self.root/'casework',True).snapshot();capture=sample();capture['sources']['jira'].update(status='FAILED',complete=False,raw=None,observed_at='2026-10-19T18:00:00+08:00')
        self.capture.write_text(json.dumps(capture))
        p=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),'--mode','snapshot-replay','--snapshot',str(self.capture),'--output-dir',str(self.root)],stdout=subprocess.DEVNULL)
        self.assertEqual(p.returncode,1)
        state=self.state()['projection'];self.assertEqual(state['source']['status'],'FAILED');self.assertTrue(state['source']['historical']);self.assertEqual(state['source']['displayed_at'],'2026-10-19T10:00:00+08:00');self.assertIsNone(state['counts']['total'])
        self.assertEqual(state['cases'][0]['deliverable'],'Synthetic reviewed build manifest');self.assertEqual(before,Store(self.root/'casework',True).snapshot())
        req={'kind':'worklog','id':'offline-work','payload':{**work(),'minutes':10},'expected_version':0,'operation_id':'offline-operation'}
        self.assertEqual(self.post('/api/records',req)[0],200)
        status,result=self.post('/api/rebuild',{});self.assertEqual(status,200);self.assertEqual(result['exit_code'],1)
        self.assertEqual(self.state()['projection']['effort']['actual_minutes'],40)

    def test_05_stop_refused_during_mutation_and_token_expiry(self):
        import threading
        from urllib.error import HTTPError
        from psirt_casework.service import Server, local_request
        server=Server(self.root);thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
        try:
            token=server.token();server.tokens[token]=0
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            conn.request('POST','/api/backup',body='{}',headers={'Origin':server.origin,'Content-Type':'application/json','X-PSIRT-Token':token})
            reply=conn.getresponse();self.assertEqual(reply.status,403);reply.read();conn.close()
            server.mutation.acquire()
            try:
                with self.assertRaises(HTTPError) as error:local_request(server.receipt,'/control/stop','POST')
                self.assertEqual(error.exception.code,409);error.exception.close()
                self.assertTrue(thread.is_alive())
            finally:server.mutation.release()
            self.assertTrue(local_request(server.receipt,'/control/stop','POST')['stopping'])
            thread.join(3);self.assertFalse(thread.is_alive())
        finally:
            server.shutdown();server.server_close();thread.join(3)

if __name__=='__main__':unittest.main()
