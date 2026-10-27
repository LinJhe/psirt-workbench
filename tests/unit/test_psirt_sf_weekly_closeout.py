import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from html.parser import HTMLParser
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from psirt_sf_fixtures import sample,failure
from test_psirt_sf_triage import make
from psirt_ops.pipeline import compare
from psirt_ops.reports import analyze
from psirt_ops.weekly_presentation import build,html,markdown,load_presentation

class Structure(HTMLParser):
    def __init__(self):super().__init__();self.headings=[];self.headers=[];self.heading=None;self.th=None;self.tables=0;self.after_other=False;self.other_text=[]
    def handle_starttag(self,t,a):
        if t in ('h2','h3'):self.heading=[t,'']
        if t=='table':self.tables+=1;self.headers.append([])
        if t=='th':self.th=''
    def handle_data(self,s):
        if self.heading is not None:self.heading[1]+=s
        elif self.after_other and s.strip():self.other_text.append(s.strip())
        if self.th is not None:self.th+=s
    def handle_endtag(self,t):
        if t in ('h2','h3') and self.heading:
            self.headings.append(tuple(self.heading));self.after_other=self.after_other or 'Other Topics' in self.heading[1];self.heading=None
        if t=='th':self.headers[-1].append(self.th);self.th=None

def config():
    return {'schema':'psirt-weekly-presentation/1','meetings':{'2026-10-19':{'time':'13:15–13:45','host':'Fixture Host','recorder':'Fixture Recorder'}},'overrides':[{'case_number':'Q-202610-90000','report_date':'2026-10-19','exclude':True,'decision_source':'Synthetic user decision'}]}
def model(c=None,day='2026-10-19'):
    c=c or sample();comp={k:compare(k,v) for k,v in c['sources'].items()};a=analyze(c,comp,{'reviews':{}})
    return build(c,a,make(c),config(),day)

class CloseoutTests(unittest.TestCase):
    def test_all_reference_directions_and_fields_keep_candidate_provenance(self):
        for incoming,where,failed in [(False,'Subject',False),(False,'TextBody',False),(True,'TextBody',False),(False,'TextBody',True)]:
            with self.subTest(incoming=incoming,where=where,failed=failed):
                c=failure() if failed else sample();e=c['sources']['salesforce']['emails'][0];e.update(Incoming=incoming,Subject='Ordinary reply',TextBody='Severity: High')
                e[where]+=' DEMO-177'
                r=next(r for r in make(c)['rows'] if r['id']=='case-0');ev=r['jira']['evidence'][0]
                self.assertEqual(ev['key'],'DEMO-177');self.assertEqual(r['jira']['formal_link'],'UNKNOWN')
                self.assertEqual(ev['evidence_refs'][0]['source_id'],e['Id']);self.assertEqual(ev['evidence_refs'][0]['field'],where)
                self.assertEqual(ev['evidence_refs'][0]['incoming'],incoming);self.assertEqual(ev['evidence_refs'][0]['message_date'],e['MessageDate'])
                if not incoming:self.assertIsNone(r['fields']['reporter_severity']['value'])
                if failed:self.assertEqual(r['jira']['current_status'],'UNKNOWN_SOURCE_INCOMPLETE')

    def test_reference_after_signature_not_lost_and_case_content_checked(self):
        c=failure();c['sources']['salesforce']['emails'][0].update(Incoming=False,TextBody='Regards,\nReference DEMO-177')
        c['sources']['salesforce']['raw'][0]['Description']='DEMO-202'
        r=next(r for r in make(c)['rows'] if r['id']=='case-0')
        self.assertEqual({x['key'] for x in r['jira']['evidence']},{'DEMO-177','DEMO-202'})

    def test_keyword_never_proves_technical_evidence(self):
        for body in ['No PoC is available.','Steps to Reproduce\n','Encrypted attachment contains PoC','Reproduction logs attached separately','Steps to Reproduce\n1. click the link']:
            c=sample();c['sources']['salesforce']['emails'][0]['TextBody']=body
            r=next(r for r in make(c)['rows'] if r['id']=='case-0')
            self.assertIn('重現證據',r['gaps']);self.assertIsNone(r['fields']['reproduction_verification']['value'])
            self.assertIn('重現證據待人工核實',r['next_action'])

    def test_override_is_period_scoped_and_source_is_immutable(self):
        c=sample();before=copy.deepcopy(c);m=model(c)
        self.assertNotIn('Q-202610-90000',html(m));self.assertIn('Q-202610-90000',html(model(c,'2026-10-20')))
        self.assertEqual(c,before);self.assertEqual(m['audit']['excluded_sf_rows'][0]['case_id'],'case-0')
        self.assertEqual(m['audit']['applied_overrides'][0]['decision_source'],'Synthetic user decision')
        self.assertEqual(html(m),html(model(c)))

    def test_excluding_sf_does_not_remove_jira_tracking(self):
        c=sample()
        for n in (202,203,204):
            c['sources']['jira']['raw'].append({'id':'DEMO-'+str(n),'key':'DEMO-'+str(n),'fields':{'summary':'Q-202610-90000 related issue','status':{'name':'In Progress','statusCategory':{'key':'indeterminate'}},'priority':{'name':'P2'}}})
        m=model(c);reported=next(b for b in m['blocks'] if b.get('key')=='reported')
        for n in (202,203,204):self.assertTrue(any(row[0]=='DEMO-'+str(n) for row in reported['rows']))
        self.assertFalse(any(row[0].startswith('指定範圍') and row[1]=='Q-202610-90000' for row in reported['rows']))

    def test_six_tables_headers_blank_other_and_no_technical_notes(self):
        m=model();p=Structure();p.feed(html(m));self.assertEqual(p.tables,6)
        self.assertEqual(p.headers,[['項目','內容'],['角色','職責'],['工單','SF Case','摘要','狀態','負責人','最後異動'],['判定','件數','說明'],['cveID','vendorProject','product','vulnerabilityName','dateAdded','dueDate','DT 命中專案候選（非受影響判定）'],['工單','摘要','優先級','狀態','負責人','最後異動']])
        self.assertEqual(len(p.headings),12);self.assertEqual(p.other_text,[])
        md=markdown(m);self.assertNotIn('本週訊息數',md);self.assertNotIn('來源健康',md);self.assertNotIn('capture.json',md)
        self.assertIn('| 主席 (Host) | Fixture Host |',md);self.assertIn('13:15–13:45',md)
        self.assertNotIn('Fixture Host',markdown(model(day='2026-10-20')))

    def test_failure_unknown_no_historical_numbers(self):
        m=model(failure());text=html(m);self.assertIn('Unknown · FAILED',text)
        self.assertIn('1. 未結案（Unknown）',text);self.assertNotIn('現行 18',text)
        sbom=next(b for b in m['blocks'] if b.get('key')=='sbom');self.assertTrue(all(r[1]=='Unknown' for r in sbom['rows']))

    def test_setting_validation_and_unknown_schema_fail_before_use(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'presentation.json';x=config();p.write_text(json.dumps(x));self.assertEqual(load_presentation(p),x)
            x['overrides'][0]['case_number']='90000';p.write_text(json.dumps(x))
            with self.assertRaises(ValueError):load_presentation(p)
            p.write_text('{"schema":"unknown"}')
            with self.assertRaises(ValueError):load_presentation(p)

if __name__=='__main__':unittest.main()
