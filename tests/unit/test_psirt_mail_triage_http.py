"""End-to-end local review transactions with isolated, synthetic snapshots."""
import copy
import hashlib
import http.client
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from psirt_casework.service import ROOT,start,stop
from psirt_casework.store import read_snapshot
from psirt_mail_triage_fixtures import sample,review_request,failed


class MailReviewHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.base=Path(cls.temp.name);cls.root=cls.base/'output'
        cls.capture=sample();cls.run_capture();cls.entry=start(cls.root)

    @classmethod
    def tearDownClass(cls):
        stop(cls.root);cls.temp.cleanup()

    @classmethod
    def run_capture(cls):
        path=cls.base/'input.json';path.write_text(json.dumps(cls.capture))
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),
            '--mode','snapshot-replay','--snapshot',str(path),'--output-dir',str(cls.root)],capture_output=True,text=True)
        if result.returncode not in (0,1):raise AssertionError(result.stdout+result.stderr)
        return json.loads(result.stdout)

    def request(self,path,body=None,token=None):
        conn=http.client.HTTPConnection('127.0.0.1',int(self.entry['origin'].rsplit(':',1)[1]),timeout=40)
        headers={'Origin':self.entry['origin'],'Content-Type':'application/json'}
        if token:headers['X-PSIRT-Token']=token
        conn.request('GET' if body is None else 'POST',path,json.dumps(body) if body is not None else None,headers)
        response=conn.getresponse();raw=response.read();status=response.status
        data=json.loads(raw) if 'json' in (response.getheader('Content-Type') or '') else raw.decode()
        conn.close();return status,data

    def state(self):
        status,data=self.request('/api/sf-inbox');self.assertEqual(status,200,data);return data

    def row(self,key):
        state=self.state();return state,next(r for r in state['inbox']['rows'] if r['source']['email_id']==key)

    def test_01_source_and_candidates_are_distinct_from_answer(self):
        state,row=self.row('mail-question')
        self.assertEqual(state['inbox']['known_total'],7)
        self.assertFalse(state['inbox']['can_retry_source'])
        self.assertEqual(set(row['triage']['reply_candidate_ids']),{'human-partial','draft-reply'})
        self.assertEqual(row['triage']['answer_assessment'],'unchecked')
        self.assertEqual(row['triage']['reply_fact']['state'],'candidates')
        status,body=self.request('/api/refresh',{'action':'retry_salesforce'},state['session'])
        self.assertEqual(status,400,body)
        self.assertFalse((self.root/'sf-auth-state.json').exists())

    def test_02_reject_unrelated_or_earlier_evidence_and_draft_answer(self):
        state,row=self.row('mail-question')
        for mid in ('mail-question','auto-reply','before-incoming','invented'):
            req=review_request(row,'reject-'+mid,reviewed_reply_fact='sent_human',reply_ids=mid,
                               reply_note='Synthetic manual confirmation',answer_assessment='answered',answer_note='Synthetic answer check')
            self.assertEqual(self.request('/api/records',req,state['session'])[0],400)
        req=review_request(row,'reject-draft',reviewed_reply_fact='draft_or_failed',reply_ids='draft-reply',
                           reply_note='Draft observed',answer_assessment='answered',answer_note='Not actually sent')
        self.assertEqual(self.request('/api/records',req,state['session'])[0],400)
        self.assertIsNone(self.row('mail-question')[1]['record'])

    def test_03_partial_manual_review_save_readback_and_restart(self):
        state,row=self.row('mail-question')
        req=review_request(row,'manual-partial',reviewed_reply_fact='sent_human',reply_ids='human-partial',
                           reply_note='SYNTHETIC sending proof reviewed',answer_assessment='partial',
                           answer_note='Bounty answered; reproduction question remains open.')
        status,result=self.request('/api/records',req,state['session']);self.assertEqual(status,200,result)
        self.assertTrue(result['committed_and_read_back']);type(self).saved_request=req
        self.assertEqual(self.request('/api/records',req,state['session'])[1]['record'],result['record'])
        row=self.row('mail-question')[1]
        self.assertEqual(row['triage']['answer_assessment'],'partial')
        self.assertEqual(row['triage']['reply_fact']['state'],'human_verified')
        manual=read_snapshot(self.root/'casework',True);stop(self.root);type(self).entry=start(self.root)
        self.assertEqual(read_snapshot(self.root/'casework',True),manual)
        self.assertTrue(self.row('mail-question')[1]['triage']['review_current'])

    def test_04_legacy_editor_cannot_erase_new_review(self):
        state,row=self.row('mail-question')
        req=review_request(row,'legacy-clear');req['payload']={k:v for k,v in req['payload'].items() if k in
            {'instance','email_id','source_digest','state','next_action','outcome','reviewer','correction_reason'}}
        self.assertEqual(self.request('/api/records',req,state['session'])[0],409)
        self.assertEqual(self.row('mail-question')[1]['record']['version'],1)

    def test_05_new_outgoing_stales_analysis_but_lost_ack_replay_succeeds(self):
        state,row=self.row('mail-question');old_digest=row['source']['evidence_sha256']
        stale=review_request(row,'stale-analysis')
        self.capture['sources']['salesforce']['emails'].append({'Id':'later-outgoing','ParentId':'case-question',
            'Incoming':False,'MessageDate':'2026-10-26T08:30:00+08:00','Subject':'DEMO follow-up',
            'TextBody':'Engineering evidence is now available.','Status':'3'})
        self.run_capture();state,current=self.row('mail-question')
        self.assertEqual(current['source']['evidence_sha256'],old_digest)
        self.assertTrue(current['triage']['needs_recheck']);self.assertEqual(current['triage']['answer_assessment'],'unchecked')
        self.assertEqual(current['record']['payload']['answer_assessment'],'partial')
        self.assertEqual(self.request('/api/records',stale,state['session'])[0],409)
        status,replay=self.request('/api/records',self.saved_request,state['session'])
        self.assertEqual(status,200,replay);self.assertEqual(replay['record']['version'],1)

    def test_06_not_required_done_leaves_attention_without_case_closure(self):
        state,row=self.row('mail-advert')
        req=review_request(row,'reference-complete',state='done',outcome='Synthetic reference message reviewed',
            reviewed_category='other',reviewed_attention='reference',answer_assessment='not_required',
            answer_note='Marketing only; no question requires reply.')
        status,data=self.request('/api/records',req,state['session']);self.assertEqual(status,200,data)
        row=self.row('mail-advert')[1];self.assertFalse(row['triage']['needs_attention'])
        self.assertFalse(next(c for c in self.capture['sources']['salesforce']['raw'] if c['Id']=='case-advert')['IsClosed'])
        self.run_capture();self.assertFalse(self.row('mail-advert')[1]['triage']['needs_recheck'])

    def test_07_auth_failure_preserves_reviews_and_unknown_new_count(self):
        manual=read_snapshot(self.root/'casework',True)
        type(self).capture=failed(self.capture);self.run_capture();state=self.state()
        self.assertEqual(state['inbox']['known_total'],7);self.assertIsNone(state['inbox']['new_incoming'])
        self.assertEqual(state['inbox']['source']['status'],'FAILED')
        self.assertTrue(state['inbox']['source']['auth_blocked'])
        self.assertEqual(read_snapshot(self.root/'casework',True),manual)
        self.assertFalse((self.root/'sf-auth-state.json').exists())

    def test_08_frozen_report_matches_review_json_and_preserves_history(self):
        state=self.state();old=Path(json.loads((self.root/'state.json').read_text())['latest_run'])
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in old.iterdir()}
        status,result=self.request('/api/rebuild',{},state['session']);self.assertEqual(status,200,result)
        new=Path(result['run_dir']);inbox=json.loads((new/'sf-inbox.json').read_text())
        self.assertEqual(inbox,json.loads((new/'sf-triage.json').read_text())['inbox'])
        self.assertEqual(inbox['manual_sha256'],state['inbox']['manual_sha256'])
        self.assertEqual(inbox['source'],state['inbox']['source'])
        html=(new/'sf-triage.html').read_text()
        self.assertIn('data-editable="false"',html)
        self.assertNotIn('<script>window.mailExecuted',html)
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in old.iterdir()})
        self.assertFalse((self.root/'sf-auth-state.json').exists())


if __name__=='__main__':unittest.main()
