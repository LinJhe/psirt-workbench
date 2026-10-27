import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from psirt_ops.pipeline import run
from psirt_casework.store import Store
from test_psirt_casework import sample,work,case

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.source=self.root/'capture.json';self.out=self.root/'output'
        self.source.write_text(json.dumps(sample()))
    def run_report(self):return Path(run(self.out,'snapshot-replay',snapshot=self.source)['run_dir'])
    def test_new_runs_preserve_records_and_old_reports_and_existing_outputs(self):
        a=self.run_report();old={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in a.iterdir()}
        legacy=self.out/'human_review.json';before=legacy.read_bytes()
        store=Store(self.out/'casework',True)
        store.save('case','DEMO-177',case(),0,'case-operation')
        store.save('worklog','shared',work(),0,'work-operation')
        snapshot=store.snapshot();b=self.run_report()
        self.assertEqual(snapshot,Store(self.out/'casework',True).snapshot());self.assertEqual(before,legacy.read_bytes())
        p=json.loads((b/'casework.json').read_text());self.assertEqual(p['effort']['actual_minutes'],30)
        self.assertEqual(old,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in a.iterdir()})
        for name in ['capture.json','sf-triage.json','dt-statistics.json']:
            x=json.loads((a/name).read_text()) if name.endswith('.json') else (a/name).read_text()
            y=json.loads((b/name).read_text()) if name.endswith('.json') else (b/name).read_text()
            if isinstance(x,dict):
                for key in ['run_id','generated_at','comparison','increments']:x.pop(key,None);y.pop(key,None)
                if name=='sf-triage.json':
                    # Inbox captures per-run baseline and manual-version metadata.
                    # The unchanged SF evidence and personal mail states must match.
                    left=x.pop('inbox');right=y.pop('inbox')
                    for key in ('rows','source','window','counts','known_total'):
                        self.assertEqual(left[key],right[key],key)
            self.assertEqual(x,y,name)
        self.assertIn('階段：分析與影響判定（已確認）',(b/'Weekly_PSIRT_Company_Format.md').read_text())
        self.assertIn('階段：分析與影響判定（已確認）',(b/'Daily_PSIRT.md').read_text())
        self.assertIn('階段：分析與影響判定（已確認）',(b/'Vance_Action_List.md').read_text())
        page=(b/'casework.html').read_text();self.assertIn('data-editable="false"',page);self.assertIn('<fieldset disabled>',page)
        self.assertIn('casework.html',(b/'index.html').read_text());self.assertIn('casework.html',(b/'sf-triage.html').read_text())
    def test_failed_source_new_run_is_not_old_success(self):
        a=self.run_report();store=Store(self.out/'casework',True);store.save('worklog','shared',work(),0,'work-operation')
        c=sample();c['sources']['jira'].update(status='FAILED',complete=False,raw=None,observed_at='2026-10-19T12:00:00+08:00');self.source.write_text(json.dumps(c))
        b=self.run_report();p=json.loads((b/'casework.json').read_text())
        self.assertEqual(p['source']['status'],'FAILED');self.assertTrue(p['source']['historical']);self.assertIsNone(p['counts']['total'])
        self.assertEqual(p['source']['displayed_at'],'2026-10-19T10:00:00+08:00');self.assertEqual(p['effort']['actual_minutes'],30)
        self.assertIn(a.name,p['cases'][0]['source_ref']);self.assertIn('FAILED',(b/'casework.html').read_text())
    def test_tampered_previous_projection_rejected_not_overwritten(self):
        a=self.run_report();p=a/'casework.json';p.write_text('{}')
        with self.assertRaisesRegex(ValueError,'CaseworkBaselineHashMismatch'):self.run_report()
        self.assertEqual(json.loads((self.out/'state.json').read_text())['latest_run'],str(a))

if __name__=='__main__':unittest.main()
