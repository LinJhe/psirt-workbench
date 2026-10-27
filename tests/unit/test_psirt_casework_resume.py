import copy
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from psirt_casework.store import Store, validate, Invalid, Conflict
from psirt_casework.effective import resolve, digest
from psirt_casework.projection import build
from test_psirt_casework import sample, case, EMPTY, ASOF, date_item

class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'casework',True)
    def test_pending_without_fake_owner_or_evidence(self):
        p=case(entered=None);p.update(stage='unknown',stage_confirmation='pending',evidence='',reviewer='',deliverable='待找測試窗口',next_action='先整理版本',dates={'followup':{'at':'2026-10-21T09:00:00+08:00','confirmation':'pending'}})
        self.store.save('case','DEMO-177',p,0,'pending-operation')
        e=resolve(self.store.snapshot(),EMPTY)
        self.assertIsNone(e['review']['reviews']['DEMO-177']['source_next_action'])
        self.assertEqual(e['cases']['DEMO-177']['fields']['deliverable']['state'],'PENDING')
        self.assertEqual(self.store.get('case','DEMO-177')['payload']['deliverable'],'待找測試窗口')
    def test_conflict_blocks_only_affected_fields_until_explicit_resolution(self):
        old={'verification':'VERIFIED_BY_HUMAN','reviewer':'prior','evidence_ref':'fixture://prior','accepted_by':'Old','source_next_action':'Old action'}
        legacy={'schema':'psirt-human-review/1','reviews':{'DEMO-177':old}}
        p=case();p.update(accepted_by='DEMO New',owner_kind='person',acceptance='confirmed',accepted_at='2026-10-19T10:00:00+08:00',acceptance_evidence='fixture://accepted',record_confirmation='confirmed',next_action='New action',deliverable='Build manifest')
        self.store.save('case','DEMO-177',p,0,'conflict-operation')
        r=resolve(self.store.snapshot(),legacy)
        self.assertIsNone(r['review']['reviews']['DEMO-177']['accepted_by']);self.assertEqual(r['cases']['DEMO-177']['fields']['deliverable']['state'],'CONFIRMED')
        projected=build(sample(),self.store.snapshot(),legacy,ASOF)
        self.assertIsNone(projected['cases'][0]['accepted_by']);self.assertIsNone(projected['cases'][0]['next_action'])
        p.update(legacy_resolution='Keep new evidence',legacy_digest=digest(old),correction_reason='reviewed versions')
        self.store.save('case','DEMO-177',p,1,'resolve-operation')
        self.assertEqual(resolve(self.store.snapshot(),legacy)['review']['reviews']['DEMO-177']['accepted_by'],'DEMO New')
        old['accepted_by']='Changed prior'
        self.assertIsNone(resolve(self.store.snapshot(),legacy)['review']['reviews']['DEMO-177']['accepted_by'])
    def test_entered_at_correction_preserves_visit_identity_and_duration(self):
        p=case();self.store.save('case','DEMO-177',p,0,'first-operation')
        before=build(sample(),self.store.snapshot(),EMPTY,ASOF)
        p.update(entered_at='2026-10-19T09:30:00+08:00',correction_reason='correct actual event time')
        self.store.save('case','DEMO-177',p,1,'correct-operation')
        after=build(sample(),self.store.snapshot(),EMPTY,ASOF,previous=before)
        self.assertEqual(len(after['cases'][0]['stage_visits']),1)
        self.assertEqual(after['cases'][0]['stage_visits'][0]['revisions'],[1,2])
        self.assertEqual(after['cases'][0]['elapsed_minutes'],1410)
        self.assertEqual(after['weekly']['stage_change_count'],0)
        self.assertEqual(after['weekly']['new_stage_changes'],[])
    def test_explicit_same_stage_reentry_preserves_closed_interval_and_deduplicates(self):
        p=case();p.update(exited_at='2026-10-19T10:00:00+08:00',exit_evidence='fixture://left')
        first=self.store.save('case','DEMO-177',p,0,'closed-operation')
        prior=build(sample(),self.store.snapshot(),EMPTY,ASOF)
        p=case(entered='2026-10-19T11:00:00+08:00');p.update(stage_event='reenter',correction_reason='new evidence',stage_visit_id=first['payload']['stage_visit_id'])
        second=self.store.save('case','DEMO-177',p,1,'reentry-operation')
        self.assertEqual(second,self.store.save('case','DEMO-177',p,1,'reentry-operation'))
        after=build(sample(),self.store.snapshot(),EMPTY,ASOF,previous=prior)
        visits=after['cases'][0]['stage_visits']
        self.assertEqual(len(visits),2);self.assertEqual(visits[0]['duration_minutes'],60)
        self.assertEqual(visits[0]['entered_at'],'2026-10-19T09:00:00+08:00')
        self.assertEqual(visits[1]['entered_at'],'2026-10-19T11:00:00+08:00')
        self.assertNotEqual(visits[0]['id'],visits[1]['id'])
        self.assertEqual(after['weekly']['stage_change_count'],0)
        self.assertEqual(after['weekly']['reentry_count'],1)
        p={**second['payload'],'stage_event':'update','blocker':'extra detail','correction_reason':'detail correction'}
        self.store.save('case','DEMO-177',p,2,'detail-operation')
        current=build(sample(),self.store.snapshot(),EMPTY,ASOF,previous=after)
        self.assertEqual(len(current['cases'][0]['stage_visits']),2)
        self.assertEqual(current['weekly']['new_reentries'],[])
        self.assertEqual(current['cases'][0]['stage_visits'][1]['revisions'],[2,3])

    def test_same_stage_reentry_requires_intent_and_prior_exit(self):
        p=case();self.store.save('case','DEMO-177',p,0,'open-operation')
        new=case(entered='2026-10-19T11:00:00+08:00');new.update(stage_event='reenter',correction_reason='new evidence')
        with self.assertRaisesRegex(Invalid,'離開'):self.store.save('case','DEMO-177',new,1,'no-exit-operation')
        p.update(exited_at='2026-10-19T10:00:00+08:00',exit_evidence='fixture://left',correction_reason='record exit')
        self.store.save('case','DEMO-177',p,1,'exit-operation')
        new['stage_event']='update'
        with self.assertRaisesRegex(Invalid,'明確選擇'):self.store.save('case','DEMO-177',new,2,'implicit-operation')
        new['stage_event']='reenter';new['entered_at']='2026-10-19T09:30:00+08:00'
        with self.assertRaisesRegex(Invalid,'不得早於'):self.store.save('case','DEMO-177',new,2,'overlap-operation')
        self.assertEqual(len(self.store.history('case','DEMO-177')),2)

    def test_pending_reentry_not_counted_until_confirmed(self):
        p=case();p.update(exited_at='2026-10-19T10:00:00+08:00',exit_evidence='fixture://left')
        self.store.save('case','DEMO-177',p,0,'closed-operation')
        prior=build(sample(),self.store.snapshot(),EMPTY,ASOF)
        p=case(entered='2026-10-19T11:00:00+08:00');p.update(stage_event='reenter',stage_confirmation='pending',correction_reason='pending new evidence')
        saved=self.store.save('case','DEMO-177',p,1,'pending-reentry-operation')
        pending=build(sample(),self.store.snapshot(),EMPTY,ASOF,previous=prior)
        self.assertEqual(pending['weekly']['reentry_count'],0)
        p={**saved['payload'],'stage_event':'update','stage_confirmation':'confirmed','correction_reason':'confirm evidence'}
        self.store.save('case','DEMO-177',p,2,'confirmed-reentry-operation')
        confirmed=build(sample(),self.store.snapshot(),EMPTY,ASOF,previous=pending)
        self.assertEqual(confirmed['weekly']['reentry_count'],1)
        self.assertEqual(len(confirmed['weekly']['new_reentries']),1)
        self.assertEqual(confirmed['weekly']['stage_change_count'],0)

    def test_legacy_visit_keeps_identity_on_first_new_save(self):
        # Old revision payloads have no stable ID; a new correction must not split them.
        from psirt_casework.projection import stage_visits
        p=case();old={'id':'DEMO-177','version':1,'payload':p}
        corrected={**p,'entered_at':'2026-10-19T09:30:00+08:00','stage_visit_id':'DEMO-177:1','stage_event':'update'}
        visits=stage_visits([old,{'id':'DEMO-177','version':2,'payload':corrected}])
        self.assertEqual(len(visits),1);self.assertEqual(visits[0]['revisions'],[1,2])

    def test_pending_transition_confirmation_is_a_new_confirmed_event(self):
        self.store.save('case','DEMO-177',case(),0,'initial-operation')
        p=case(stage='development',entered='2026-10-19T11:00:00+08:00');p.update(stage_confirmation='pending',correction_reason='pending handoff')
        saved=self.store.save('case','DEMO-177',p,1,'pending-transition-operation')
        before=build(sample(),self.store.snapshot(),EMPTY,ASOF)
        p={**saved['payload'],'stage_confirmation':'confirmed','correction_reason':'confirm handoff'}
        self.store.save('case','DEMO-177',p,2,'confirm-transition-operation')
        after=build(sample(),self.store.snapshot(),EMPTY,ASOF,previous=before)
        self.assertEqual(after['weekly']['stage_change_count'],1);self.assertEqual(len(after['weekly']['new_stage_changes']),1)

    def test_sf_pending_evidence_not_promoted_and_resolved_next_step_consistent(self):
        from psirt_sf_fixtures import sample as sf_sample
        from test_psirt_sf_triage import make
        prior={'verification':'PENDING','reviewer':'prior','evidence_ref':'fixture://case-0','accepted_by':'Old','source_next_action':'Old action'}
        legacy={'schema':'psirt-human-review/1','reviews':{'DEMO-177':prior}}
        e=resolve(self.store.snapshot(),legacy)
        row=next(r for r in make(sf_sample(),review=e['sf_review'])['rows'] if r['id']=='case-0')
        self.assertFalse(row['human_reviews'][0]['verified']);self.assertIsNone(row['fields']['accepted_by']['value'])
        p=case();p.update(record_confirmation='confirmed',next_action='NEW reviewed build',correction_reason='choose new evidence',legacy_resolution='use Store',legacy_digest=digest(prior))
        self.store.save('case','DEMO-177',p,0,'sf-resolution-operation')
        e=resolve(self.store.snapshot(),legacy)
        row=next(r for r in make(sf_sample(),review=e['sf_review'])['rows'] if r['id']=='case-0')
        self.assertEqual(row['human_reviews'][0]['source_next_action'],e['review']['reviews']['DEMO-177']['source_next_action'])
        self.assertEqual(row['human_reviews'][0]['evidence_ref'],'fixture://case-0')
        self.assertFalse(row['human_reviews'][0]['verified'])

    def test_equivalent_offset_does_not_create_false_conflict(self):
        p=case();p['dates']['followup']=date_item('2026-10-20T01:00:00Z')
        self.store.save('case','DEMO-177',p,0,'timezone-operation')
        legacy={'schema':'psirt-human-review/1','reviews':{'DEMO-177':{'next_follow_up_at':'2026-10-20T09:00:00+08:00'}}}
        self.assertEqual(resolve(self.store.snapshot(),legacy)['cases']['DEMO-177']['conflict']['state'],'NONE')
    def test_legacy_only_remains_visible_without_promoting_formal_deadline(self):
        old={'verification':'VERIFIED_BY_HUMAN','reviewer':'prior','evidence_ref':'fixture://prior','accepted_by':'Old','source_next_action':'Old action','remediation_due_at':'2026-10-20T01:00:00Z'}
        legacy={'schema':'psirt-human-review/1','reviews':{'DEMO-177':old}}
        r=resolve(self.store.snapshot(),legacy)
        self.assertEqual(r['review']['reviews']['DEMO-177']['accepted_by'],'Old');self.assertIsNone(r['review']['reviews']['DEMO-177']['remediation_due_at'])
        p=build(sample(),self.store.snapshot(),legacy,ASOF);self.assertEqual(p['cases'][0]['accepted_by'],'Old')

if __name__=='__main__':unittest.main()
