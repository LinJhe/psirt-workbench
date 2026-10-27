import copy
import fcntl
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from psirt_ops.html_report import render
from psirt_ops.pipeline import run, prepare
from psirt_ops.reports import analyze
from test_psirt_ops import capture, comparisons


class Parsed(HTMLParser):
    def __init__(self,text):
        super().__init__();self.metrics={};self.overview={};self.overview_current=None;self.sections=[];self.scripts=[];self.details=[];self.current=None
        self.feed(text)
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='section':self.sections.append(a.get('id'))
        if tag=='strong' and 'data-metric' in a:self.current=a['data-metric']
        if tag=='strong':self.overview_current=a.get('data-overview')
        if tag=='script':self.scripts.append(a)
        if tag=='details':self.details.append(a)
    def handle_endtag(self,tag):
        if tag=='strong':self.current=None;self.overview_current=None
    def handle_data(self,text):
        if self.current:self.metrics[self.current]=self.metrics.get(self.current,'')+text
        if self.overview_current:self.overview[self.overview_current]=self.overview.get(self.overview_current,'')+text


class HtmlTests(unittest.TestCase):
    def test_learning_links_and_source_failure_keep_evidence_boundaries(self):
        from psirt_ops.kev_learning import render as learning
        c=capture();comp=comparisons(c)
        text=render(c,analyze(c,comp,{'reviews':{}}),comp,'snapshot-replay','learning')
        class Links(HTMLParser):
            def __init__(self):
                super().__init__();self.ids=[];self.targets=[]
            def handle_starttag(self,tag,attrs):
                a=dict(attrs)
                if 'id' in a:self.ids.append(a['id'])
                if a.get('href','').startswith('#'):self.targets.append(a['href'][1:])
        links=Links();links.feed(text)
        self.assertEqual(len(links.ids),len(set(links.ids)))
        self.assertFalse(set(links.targets)-set(links.ids))
        for status in ('FAILED','PARTIAL'):
            c['sources']['kev'].update(status=status,complete=False)
            # A stale comparison cannot make a failed current fetch look like zero.
            comp['kev']['counts']={'added':0}
            c['sources']['dt']['scope']='<img src=x onerror=alert(1)>'
            module=learning(c,comp)
            self.assertIn('相較可用基準新增：Unknown',module)
            self.assertIn('&lt;img',module)
            self.assertNotIn('<img',module)
            self.assertIn('教材日期不代表重新取數',module)

    def test_report_sections_and_guide_keep_week_and_delta_distinct(self):
        c=capture();s=c['sources'];date=c['config']['cutoff']
        s['jira']['raw']=[{'id':'DEMO-202','key':'DEMO-202','fields':{
            'summary':'test','status':{'name':'In Progress','statusCategory':{'key':'indeterminate'}},'created':date,'updated':date}}]
        comp={n:__import__('psirt_ops.pipeline',fromlist=['compare']).compare(n,v,v) for n,v in s.items()}
        data=analyze(c,comp,{'reviews':{}})
        text=render(c,data,comp,'snapshot-replay','example');p=Parsed(text)
        self.assertEqual(p.sections,['kev-dt','salesforce','jira','decision-guide','kev-learning'])
        self.assertEqual(p.metrics['jira_week_new'],'1')
        self.assertEqual(p.metrics['jira_added'],'0')
        self.assertEqual(p.overview['kev-dt'],'0')
        self.assertEqual(p.overview['jira'],p.metrics['jira_open'])
        self.assertEqual(p.overview['salesforce'],str(sum(r['candidate'] for r in data['sf_activity'])))
        self.assertIn('data-theme="japanese-garden"',text)
        self.assertIn('GARDEN NEXUS / 10 · 本機草稿',text)
        self.assertEqual(p.scripts,[])
        self.assertTrue(p.details)
        self.assertTrue(all('open' not in a for a in p.details))
        self.assertIn('合成測試資料',text)
        self.assertIn('歷史 snapshot-replay',text)
        self.assertIn('aria-label="左側導覽"',text)
        self.assertIn('data-framework="tailwind-2.2.19"',text)
        self.assertNotIn('<link rel="stylesheet" href="https:',text)
        self.assertIn('@media(max-width:850px)',text)

    def test_untrusted_source_is_text_not_active_html(self):
        c=capture();attack='<script>alert(1)</script><img src="https://evil.test/">'
        c['sources']['salesforce']['raw']=[{'Id':'one','id':'one','CaseNumber':'Q-202610-99999',
            'CreatedDate':c['config']['cutoff'],'Subject':attack,'Status':'New'}]
        comp=comparisons(c);data=analyze(c,comp,{'reviews':{}})
        text=render(c,data,comp,'live','test')
        self.assertNotIn(attack,text)
        self.assertIn('&lt;script&gt;',text)
        self.assertEqual(Parsed(text).scripts,[])

    def test_partial_and_failed_metrics_are_unknown(self):
        for status in ('FAILED','PARTIAL'):
            c=capture()
            for s in c['sources'].values():s.update(status=status,complete=False)
            comp=comparisons(c);text=render(c,analyze(c,comp,{'reviews':{}}),comp,'live','failure')
            self.assertTrue(all(v=='待確認／Unknown' for v in Parsed(text).metrics.values()))
            self.assertEqual(Parsed(text).overview,dict.fromkeys(('kev-dt','salesforce','jira'),'Unknown'))
            self.assertIn('本輪來源 FAILED／PARTIAL',text)

    def test_source_failure_generates_new_hashed_html_not_old_success(self):
        c=capture();c['synthetic']=False
        for s in c['sources'].values():s['synthetic']=False
        with tempfile.TemporaryDirectory() as td, patch('psirt_ops.adapters.collect',return_value=c):
            first=run(td,'live',c['config'])
            old=Path(first['html_path']);oldhash=hashlib.sha256(old.read_bytes()).hexdigest()
            c['sources']['jira'].update(status='FAILED',complete=False,raw=None)
            second=run(td,'live',c['config'])
            self.assertEqual(second['exit_code'],1)
            self.assertNotEqual(first['html_path'],second['html_path'])
            self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(),oldhash)
            report=Path(second['html_path']);manifest=json.loads((report.parent/'manifest.json').read_text())
            self.assertEqual(manifest['artifacts_sha256']['index.html'],hashlib.sha256(report.read_bytes()).hexdigest())
            self.assertEqual(Parsed(report.read_text()).metrics['jira_week_new'],'待確認／Unknown')

    def test_real_process_lock_returns_75_without_new_run(self):
        with tempfile.TemporaryDirectory() as td:
            out=prepare(Path(td)/'managed','snapshot-replay');receipt=Path(td)/'receipt.json'
            with (out/'.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                process=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),
                    '--mode','snapshot-replay','--snapshot',str(Path(td)/'not-needed.json'),
                    '--output-dir',str(out),'--result-file',str(receipt)],capture_output=True,text=True)
            self.assertEqual(process.returncode,75,process.stderr)
            self.assertEqual(json.loads(receipt.read_text())['error_type'],'AlreadyRunning')
            self.assertFalse((out/'runs').exists())

    def test_fatal_receipt_has_no_old_report(self):
        with tempfile.TemporaryDirectory() as td:
            receipt=Path(td)/'receipt.json'
            args=[sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),'--mode','snapshot-replay',
                  '--snapshot',str(Path(td)/'missing.json'),'--output-dir',str(Path(td)/'output'),
                  '--result-file',str(receipt)]
            p=subprocess.run(args,capture_output=True,text=True)
            self.assertEqual(p.returncode,2)
            saved=receipt.read_bytes();result=json.loads(saved)
            self.assertNotIn('html_path',result)
            again=subprocess.run(args,capture_output=True,text=True)
            self.assertNotEqual(again.returncode,0)
            self.assertEqual(receipt.read_bytes(),saved)


if __name__=='__main__':unittest.main()
