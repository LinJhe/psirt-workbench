"""Behavioral acceptance of personal timing, evidence and persistence."""
import copy
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from psirt_casework.store import Store, Invalid, Conflict, read_snapshot, validate
from psirt_casework.projection import build, digest
from psirt_dt_fixtures import capture

ASOF='2026-10-20T09:00:00+08:00'
EMPTY={'schema':'psirt-human-review/1','reviews':{}}


def sample():
    c=capture();c['sources']['jira']['observed_at']='2026-10-19T10:00:00+08:00'
    c['sources']['jira']['raw']=[{'key':k,'id':k,'fields':{'summary':'Synthetic '+k,'status':{'name':'In Progress','statusCategory':{'key':'indeterminate'}},'assignee':{'displayName':'DEMO RD'},'created':'2020-01-01T00:00:00+08:00','updated':ASOF}} for k in ('DEMO-177','DEMO-179')]
    return c


def case(key='DEMO-177',stage='analysis',entered='2026-10-19T09:00:00+08:00'):
    return {'case_id':key,'stage':stage,'stage_confirmation':'confirmed','entered_at':entered,
            'entry_evidence':'synthetic entry event' if entered else '', 'evidence':'synthetic review',
            'owner_kind':'unknown','acceptance':'pending','reviewer':'DEMO reviewer','dates':{}}


def work():
    return {'case_ids':['DEMO-177','DEMO-179'],'task':'Synthetic shared verification','work_date':'2026-10-19',
            'minutes':30,'category':'verification','measurement':'measured','recording_mode':'backfill',
            'outcome':'Synthetic scope list','evidence':'fixture://scope'}


def date_item(at,**extra):
    return {'at':at,'confirmation':'confirmed','evidence':'fixture://agreement','confirmed_by':'DEMO reviewer',**extra}


class CaseworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.store=Store(self.root/'casework',synthetic=True)
        self.n=0
    def save(self,kind,id,p,version=0):
        self.n+=1
        return self.store.save(kind,id,p,version,'operation-'+str(self.n))
    def project(self,c=None,previous=None,legacy=None,fallback=None):
        return build(c or sample(),self.store.snapshot(),legacy or EMPTY,ASOF,previous,fallback)

    def test_assignee_status_and_jira_times_do_not_invent_stage_or_acceptance(self):
        p=self.project();r=p['cases'][0]
        self.assertEqual(r['jira_status'],'In Progress');self.assertEqual(r['stage'],'unknown')
        for field in ('elapsed_minutes','accepted_by','actual_minutes','waiting_minutes'):self.assertIsNone(r[field])
        self.assertEqual(r['dates']['remediation']['state'],'UNKNOWN')
        self.assertIsNone(p['weekly']['received_count']);self.assertIsNone(p['weekly']['stage_change_count'])

    def test_stage_wait_work_are_distinct_and_shared_work_counted_once(self):
        self.save('case','DEMO-177',case())
        self.save('worklog','shared',work())
        self.save('wait','wait1',{'case_id':'DEMO-177','start':'2026-10-19T09:00:00+08:00','end':'2026-10-19T11:00:00+08:00','waiting_for':'DEMO RD','deliverable':'build','reason':'await build','evidence':'fixture://request','resolution_evidence':'fixture://received'})
        p=self.project();r=p['cases'][0]
        self.assertEqual(r['elapsed_minutes'],1440);self.assertEqual(r['waiting_minutes'],120)
        self.assertEqual(p['effort']['actual_minutes'],30)
        self.assertEqual([r['actual_minutes'] for r in p['cases']],[30,30])
        self.assertEqual(p['effort']['shared_record_ids'],['shared'])

    def test_overlapping_waits_are_union_and_do_not_pause_dates(self):
        for i,(a,b) in enumerate([('09:00','11:00'),('10:00','12:00')]):
            self.save('wait','wait'+str(i),{'case_id':'DEMO-177','start':'2026-10-19T'+a+':00+08:00','end':'2026-10-19T'+b+':00+08:00','waiting_for':'DEMO RD','deliverable':'build','reason':'wait','evidence':'fixture://wait','resolution_evidence':'fixture://end'})
        d=case();d['dates']['commitment']=date_item('2026-10-19T12:00:00+08:00');self.save('case','DEMO-177',d)
        p=self.project();self.assertEqual(p['effort']['waiting_union_minutes'],180)
        self.assertEqual(p['counts']['commitment_overdue'],1)

    def test_followup_due_is_not_sla_and_completion_requires_evidence(self):
        d=case();d['dates']={'followup':date_item('2026-10-19T12:00:00+08:00')};self.save('case','DEMO-177',d)
        p=self.project();self.assertEqual(p['counts']['followup_due'],1)
        self.assertEqual(p['counts']['commitment_overdue'],0);self.assertEqual(p['counts']['deadline_unknown'],2)
        self.assertEqual(p['cases'][0]['dates']['remediation']['state'],'UNKNOWN')
        d['dates']['commitment']=date_item('2026-10-19T12:00:00+08:00',completed_at='2026-10-19T11:00:00+08:00')
        with self.assertRaises(Invalid):validate('case',d)

    def test_confirmed_deadline_basis_and_late_completion_are_separate(self):
        d=case();d['dates']['remediation']=date_item('2026-10-19T12:00:00+08:00')
        with self.assertRaises(Invalid):validate('case',d)
        d['dates']['remediation'].update(basis_version='DEMO policy',trigger_event='fixture trigger',scope='DEMO only')
        d['dates']['commitment']=date_item('2026-10-19T12:00:00+08:00',completed_at='2026-10-19T13:00:00+08:00',completion_evidence='fixture://delivery')
        self.save('case','DEMO-177',d);p=self.project()
        self.assertEqual(p['counts']['remediation_exceeded'],1)
        self.assertEqual(p['cases'][0]['dates']['commitment']['state'],'COMPLETED_LATE')
        self.assertEqual(p['counts']['commitment_overdue'],0)

    def test_return_to_verification_preserves_visits_and_corrections(self):
        d=case(stage='verification');d.update(exited_at='2026-10-19T10:00:00+08:00',exit_evidence='fixture failed test')
        self.save('case','DEMO-177',d)
        d=case(stage='development',entered='2026-10-19T10:00:00+08:00');d.update(correction_reason='failed test requires fix',exited_at='2026-10-19T12:00:00+08:00',exit_evidence='fixture build')
        self.save('case','DEMO-177',d,1)
        d=case(stage='verification',entered='2026-10-19T12:00:00+08:00');d['correction_reason']='return with new build';self.save('case','DEMO-177',d,2)
        d.update(blocker='await test',correction_reason='add blocker');self.save('case','DEMO-177',d,3)
        r=self.project()['cases'][0]
        self.assertEqual([v['stage'] for v in r['stage_visits']],['verification','development','verification'])
        self.assertEqual([v['duration_minutes'] for v in r['stage_visits']],[60,120,None])
        self.assertEqual(r['elapsed_minutes'],1260);self.assertEqual(len(r['revisions']),4)
        self.assertEqual(r['stage_visits'][-1]['revisions'],[3,4])

    def test_same_operation_and_stale_revision_do_not_duplicate_or_overwrite(self):
        w=work();a=self.store.save('worklog','one',w,0,'repeat-operation')
        self.assertEqual(a,self.store.save('worklog','one',w,0,'repeat-operation'))
        self.assertEqual(self.project()['effort']['actual_minutes'],30)
        changed={**w,'minutes':40,'correction_reason':'fix minutes'}
        with self.assertRaises(Conflict):self.store.save('worklog','one',changed,0,'new-operation')
        with self.assertRaises(Conflict):self.store.save('worklog','one',changed,1,'repeat-operation')
        self.assertEqual(self.store.get('worklog','one')['payload']['minutes'],30)

    def test_reopen_snapshot_backup_and_storage_failure(self):
        self.save('case','DEMO-177',case());self.save('worklog','one',work())
        before=self.store.snapshot();backup=self.store.backup()
        reopened=Store(self.root/'casework',synthetic=True);self.assertEqual(before,reopened.snapshot())
        with patch.object(self.store,'connect',side_effect=sqlite3.OperationalError('readonly')):
            with self.assertRaises(sqlite3.OperationalError):self.save('worklog','two',work())
        self.assertEqual(before,reopened.snapshot());self.assertTrue(backup.exists())
        isolated=self.root/'restored';isolated.mkdir();(isolated/'worklog.sqlite3').write_bytes(backup.read_bytes())
        self.assertEqual(before,read_snapshot(isolated,True))

    def test_unbound_work_estimates_and_invalid_overlaps(self):
        w=work();w.update(case_ids=[],task='General review');self.save('worklog','general',w)
        w.update(measurement='estimated',minutes=20);self.save('worklog','estimate',w)
        p=self.project();self.assertEqual(p['effort']['actual_minutes'],30);self.assertEqual(p['effort']['estimated_minutes'],20)
        w=work();w.update(start='2026-10-19T09:00:00+08:00',end='2026-10-19T09:30:00+08:00');self.save('worklog','timed1',w)
        with self.assertRaises(Conflict):self.save('worklog','timed2',w)
        with self.assertRaises(Invalid):self.save('worklog','negative',{**w,'minutes':-5})

    def test_partial_failed_source_preserves_old_time_and_manual_records(self):
        self.save('case','DEMO-177',case());self.save('worklog','one',work())
        before=self.store.snapshot();c=sample();last=copy.deepcopy(c['sources']['jira'])
        c['sources']['jira'].update(status='FAILED',complete=False,raw=None,observed_at=ASOF)
        p=self.project(c,fallback=last)
        self.assertIsNone(p['counts']['total']);self.assertIsNone(p['counts']['commitment_overdue'])
        self.assertTrue(p['source']['historical']);self.assertEqual(p['cases'][0]['source_observed_at'],last['observed_at'])
        self.assertEqual(p['effort']['actual_minutes'],30);self.assertEqual(before,self.store.snapshot())
        c['sources']['jira'].update(status='PARTIAL',raw=last['raw'][:1])
        self.assertIsNone(self.project(c)['counts']['total'])

    def test_weekly_baseline_scope_and_unique_delivery(self):
        prior=self.project()
        d={'case_ids':['DEMO-177','DEMO-179'],'title':'Shared test report','received_at':'2026-10-19T10:00:00+08:00', 'acceptance':'pending','outcome':'report received, not approved','evidence':'fixture://report','reviewer':'DEMO reviewer'}
        self.save('delivery','shared-report',d)
        p=self.project(previous=prior)
        self.assertEqual(p['weekly']['received_count'],1);self.assertEqual(p['weekly']['accepted_count'],0)
        self.assertEqual(self.project(previous=p)['weekly']['received_count'],1)
        c=sample();c['sources']['jira']['scope']={'other':'scope'}
        self.assertIsNone(self.project(c,previous=p)['weekly']['received_count'])

    def test_legacy_conflict_explicit_resolution_and_no_mutation(self):
        legacy={'schema':'psirt-human-review/1','reviews':{'DEMO-177':{'accepted_by':'old person','source_next_action':'old action'}}}
        original=copy.deepcopy(legacy);d=case();self.save('case','DEMO-177',d)
        p=self.project(legacy=legacy);self.assertEqual(p['counts']['conflicts'],1)
        d.update(legacy_digest=digest(legacy['reviews']['DEMO-177']),legacy_resolution='Keep store; old acceptance not verified',correction_reason='reviewed old record')
        self.save('case','DEMO-177',d,1)
        self.assertEqual(self.project(legacy=legacy)['cases'][0]['legacy_review']['state'],'RESOLVED_EXPLICITLY')
        legacy['reviews']['DEMO-177']['accepted_by']='changed legacy'
        self.assertEqual(self.project(legacy=legacy)['counts']['conflicts'],1)
        self.assertEqual(original['reviews']['DEMO-177']['accepted_by'],'old person')

    def test_absent_database_read_is_readonly_and_modes_do_not_mix(self):
        missing=self.root/'missing';self.assertFalse(read_snapshot(missing,True)['available']);self.assertFalse(missing.exists())
        with self.assertRaises(Invalid):Store(self.root/'casework',synthetic=False)
        real=Store(self.root/'real',synthetic=False)
        with self.assertRaises(Invalid):real.save('worklog','demo',work(),0,'demo-operation')

    def test_confirmed_stage_without_entry_still_has_unknown_elapsed_and_closed_is_not_fixed(self):
        d=case(stage='closure',entered=None);self.save('case','DEMO-177',d)
        p=self.project();self.assertEqual(p['cases'][0]['stage'],'closure');self.assertIsNone(p['cases'][0]['elapsed_minutes'])
        self.assertEqual(p['cases'][0]['jira_status'],'In Progress')
        self.assertNotIn('fixed_count',p['counts'])

if __name__=='__main__':unittest.main()
