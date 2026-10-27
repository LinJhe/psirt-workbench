import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from html import unescape
import re

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from psirt_ops.sf_triage import build,render,taiwan
from psirt_ops.pipeline import compare,run
from psirt_sf_fixtures import sample,failure,hostile

REVIEW={'schema':'psirt-human-review/1','reviews':{}}
def make(c,previous=None,review=None):
    comps={k:compare(k,v,(previous or {}).get('sources',{}).get(k)) for k,v in c['sources'].items()}
    return build(c,comps,review or REVIEW,'fixture-run','snapshot-replay','2026-10-19T09:00:00+08:00')


class SFTriageTests(unittest.TestCase):
    def test_case_and_email_increment_are_independent_and_idempotent(self):
        c=sample();self.assertEqual(make(c)['increments'],{'cases':None,'emails':None})
        self.assertEqual(make(c,c)['increments'],{'cases':0,'emails':0})
        new=copy.deepcopy(c);e=copy.deepcopy(new['sources']['salesforce']['emails'][0]);e['Id']='new-email';new['sources']['salesforce']['emails'].append(e)
        self.assertEqual(make(new,c)['increments'],{'cases':0,'emails':1})
        new['sources']['salesforce']['scope']={'different':True};self.assertIsNone(make(new,c)['increments']['cases'])

    def test_no_keyword_old_index_and_source_severity_survive(self):
        d=make(sample());r=d['rows'][0];by={r['id']:r for r in d['rows']}
        self.assertIn('unclassified',by['case-0']['tags']);self.assertIn('incoming',by['case-0']['tags'])
        self.assertEqual(by['case-0']['fields']['reporter_severity']['value'],'Medium')
        self.assertIsNone(by['case-0']['fields']['company_decision']['value'])
        self.assertIn('case-2',by);self.assertNotIn('new_case',by['case-2']['tags'])
        self.assertEqual(by['case-1']['fields']['product']['value'],'Example SDK')
        self.assertEqual(by['case-1']['fields']['version']['value'],'v1.00')
        self.assertIsNone(by['case-1']['fields']['reporter_severity']['value'])

    def test_field_absent_empty_and_reported_are_distinct(self):
        by={r['id']:r for r in make(sample())['rows']}
        self.assertEqual(by['case-0']['fields']['product_field']['state'],'NOT_FETCHED')
        self.assertEqual(by['case-2']['fields']['product_field']['state'],'EXPLICIT_EMPTY')
        self.assertEqual(by['case-3']['fields']['product']['state'],'REPORTED_UNVERIFIED')
        self.assertEqual(by['case-0']['fields']['product']['state'],'NOT_STATED')
        for r in by.values():
            for f in r['fields'].values():
                if f['value'] is not None:self.assertTrue(f['evidence_refs'])

    def test_jira_failed_partial_and_limited_no_match_are_distinct(self):
        for status in ('FAILED','PARTIAL'):
            c=failure();c['sources']['jira']['status']=status
            for r in make(c)['rows']:
                self.assertEqual(r['jira']['status'],'UNDETERMINED');self.assertEqual(r['jira']['current_status'],'UNKNOWN_SOURCE_INCOMPLETE')
                self.assertNotIn('未開單',r['next_action'])
        self.assertTrue(all(r['jira']['status']=='NOT_FOUND_IN_SCOPE' for r in make(sample())['rows']))

    def test_reference_is_candidate_not_formal_link_even_when_jira_fails(self):
        c=failure();c['sources']['salesforce']['emails'][0]['TextBody']+=' DEMO-177'
        r=next(r for r in make(c)['rows'] if r['id']=='case-0')
        self.assertEqual(r['jira']['status'],'CANDIDATE');self.assertEqual(r['jira']['formal_link'],'UNKNOWN')
        self.assertEqual(r['jira']['current_status'],'UNKNOWN_SOURCE_INCOMPLETE')
        self.assertEqual(r['jira']['evidence'][0]['key'],'DEMO-177')

    def test_verified_human_evidence_retained_without_inventing_formal_relation(self):
        review={'schema':'psirt-human-review/1','reviews':{'DEMO-1':{'verification':'VERIFIED_BY_HUMAN','reviewer':'Fixture reviewer','evidence_ref':'capture.json#/sources/salesforce/raw/0/Id (case-0)','accepted_by':'Fixture receiver','note':'Source says closed, technical validation still pending','reviewed_at':'2026-10-10T00:00:00+08:00'}}}
        r=next(r for r in make(failure(),review=review)['rows'] if r['id']=='case-0')
        self.assertEqual(r['jira']['status'],'VERIFIED_REVIEW_EVIDENCE');self.assertEqual(r['jira']['current_status'],'UNKNOWN_SOURCE_INCOMPLETE')
        self.assertEqual(r['fields']['accepted_by']['value'],'Fixture receiver');self.assertEqual(r['jira']['verified_review_evidence'][0]['review_date'],'2026-10-10T00:00:00+08:00')
        self.assertTrue(r['review_conflict_notice']);self.assertEqual(r['jira']['formal_link'],'UNKNOWN')
        review['reviews']['DEMO-1']['evidence_ref']='capture.json#/sources/salesforce/raw/0/Id (case-01)'
        self.assertFalse(any(x['human_reviews'] for x in make(sample(),review=review)['rows']))  # Never attach case-01 evidence to case-0.
        review['schema']='unsupported/2';d=make(sample(),review=review)
        self.assertEqual(d['review_schema_status'],'UNKNOWN_SCHEMA_NOT_INTERPRETED');self.assertFalse(any(r['human_reviews'] for r in d['rows']))

    def test_duplicate_preserves_both_cases_and_emails_without_merging(self):
        d=make(sample());rs=[r for r in d['rows'] if 'duplicate' in r['tags']]
        self.assertEqual(len(rs),2);self.assertEqual(len(d['rows']),5)
        self.assertEqual(rs[0]['duplicate_candidates'][0]['case_ids'],['case-3','case-4'])
        self.assertEqual(rs[0]['duplicate_candidates'][0]['email_ids'],['email-3','email-4'])

    def test_outbound_does_not_mean_human_acceptance(self):
        c=sample();c['sources']['salesforce']['emails'][0]['Incoming']=False
        r=next(r for r in make(c)['rows'] if r['id']=='case-0')
        self.assertEqual(r['messages'][0]['reply_nature'],'回信性質待確認');self.assertIsNone(r['fields']['accepted_by']['value']);self.assertIsNone(r['fields']['reporter_severity']['value'])

    def test_source_failure_counts_unknown_complete_empty_zero_orphan_kept(self):
        c=sample();c['sources']['salesforce'].update(status='PARTIAL',complete=False)
        d=make(c);self.assertIsNone(d['index_count']);self.assertTrue(all(v is None for v in d['counts'].values()));self.assertEqual(len(d['rows']),5)
        c['sources']['salesforce']['raw']=[];self.assertEqual(len(make(c)['rows']),4)
        c['sources']['salesforce'].update(status='SUCCESS',complete=True,emails=[])
        d=make(c);self.assertEqual(d['index_count'],0);self.assertTrue(all(v==0 for v in d['counts'].values()))

    def test_html_is_inert_minimized_and_matches_json(self):
        d=make(hostile());shell="<html><head><title>PSIRT 工作台</title><meta content=\"default-src 'none';\"></head><body><nav><a href=\"sf-triage.html\">SF</a></nav><main>DO_NOT_COPY_MAIL</main></body></html>"
        p=render(shell,d)
        self.assertNotIn('DO_NOT_COPY_MAIL',p);self.assertNotIn('<img src="https://evil.invalid',p);self.assertNotIn('HIDDEN_SECRET',p);self.assertNotIn('HIDDEN_CIPHERTEXT',p);self.assertNotIn('someone@example.invalid',p)
        self.assertEqual(p.count('<script>'),1)
        payload=json.loads(unescape(re.search(r'<pre id="sf-data" hidden>(.*?)</pre>',p,re.S).group(1)));self.assertEqual(payload,d)
        self.assertEqual(taiwan('2026-10-17T05:52:04.000+0000'),'2026-10-17T13:52:04+08:00')
        self.assertIsNone(taiwan('invalid'))

    def test_pipeline_preserves_review_history_and_manifest(self):
        c=sample()
        with tempfile.TemporaryDirectory() as td,patch('psirt_daily.offline.install_offline_guard'):
            root=Path(td);snap=root/'input.json';snap.write_text(json.dumps(c));out=root/'out'
            first=run(out,'snapshot-replay',snapshot=snap);p=Path(first['run_dir']);before={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.iterdir()}
            review=out/'human_review.json';review.write_text(json.dumps({'schema':'psirt-human-review/1','reviews':{'DEMO-1':{'note':'keep manually entered text'}}}));saved=review.read_bytes()
            second=run(out,'snapshot-replay',snapshot=snap);n=Path(second['run_dir']);d=json.loads((n/'sf-triage.json').read_text())
            self.assertEqual(d['increments'],{'cases':0,'emails':0});self.assertEqual(review.read_bytes(),saved);self.assertEqual(json.loads((n/'human_review_used.json').read_text()),json.loads(saved))
            for f,h in before.items():self.assertEqual(hashlib.sha256((p/f).read_bytes()).hexdigest(),h)
            m=json.loads((n/'manifest.json').read_text());self.assertEqual(d['run_id'],m['run_id']);self.assertEqual(d['generated_at'],m['started_at'])
            for f,h in m['artifacts_sha256'].items():self.assertEqual(hashlib.sha256((n/f).read_bytes()).hexdigest(),h)
            page=(n/'index.html').read_text();self.assertIn('href="sf-triage.html"',page);self.assertIn('id="salesforce"',page)
            self.assertTrue((n/'Weekly_PSIRT_Company_Format.md').is_file())  # Different baseline labels legitimately change Weekly text.

if __name__=='__main__':unittest.main()
