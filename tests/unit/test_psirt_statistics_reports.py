import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from psirt_ops.pipeline import compare, run
from psirt_ops.reports import analyze, daily_markdown
from psirt_ops.html_report import render
from psirt_ops.weekly_presentation import build as weekly
from test_psirt_ops import capture
from test_psirt_html import Parsed


def fixture():
    c = capture()
    c['config']['cutoff'] = c['captured_at'] = '2026-10-26T22:00:00+08:00'
    for s in c['sources'].values():
        s['observed_at'] = c['captured_at']
    c['sources']['salesforce']['emails'] = []
    c['sources']['kev']['raw'].update(count=2, vulnerabilities=[
        {'cveID':'CVE-2026-11111', 'dateAdded':'2026-10-23'},
        {'cveID':'CVE-2026-22222', 'dateAdded':'2026-10-13'},
    ])
    c['sources']['dt']['scope'] = {'instance':'https://dt.example.invalid', 'project_uuids':['p1','p2']}
    c['sources']['dt']['raw'] = [
        {'id':'f'+p, 'project':{'uuid':p,'name':p}, 'component':{'uuid':'component','name':'lib'},
         'vulnerability':{'uuid':'vuln','vulnId':'CVE-2026-11111'}} for p in ('p1','p2')]
    c['sources']['jira']['raw'] = [
        {'id':str(n),'key':'DEMO-'+str(n), 'fields':{'summary':'Synthetic',
         'created':'2026-10-20T12:00:00+08:00','updated':'2026-10-26T13:00:00+08:00',
         'status':{'name':name,'statusCategory':{'key':category}}}}
        for n, name, category in ((101,'In Progress','indeterminate'),(105,'Done','done'))]
    return c


def inputs(c):
    comp = {n:compare(n,s,s) for n,s in c['sources'].items()}
    return comp, analyze(c,comp,{'reviews':{}})


class StatisticsReportTests(unittest.TestCase):
    def test_utc_cutoff_and_cve_alias_are_consistent_in_daily_and_weekly(self):
        c = fixture(); c['config']['cutoff'] = '2026-10-25T16:30:00Z'
        c['sources']['kev']['raw']['vulnerabilities'][0]['dateAdded'] = '2026-10-26'
        for finding in c['sources']['dt']['raw']:
            finding['vulnerability'].update(vulnId='GHSA-example',aliases=[{'cveId':'CVE-2026-11111'}])
        comp, data = inputs(c)
        self.assertEqual(data['statistics']['kev']['counts']['week'],1)
        self.assertIn('CVE-2026-11111',[r['cveID'] for r in data['kev_window']])
        w = weekly(c,data,{'rows':[]},{'meetings':{},'overrides':[]},'2026-10-26')
        row = next(r for b in w['blocks'] if b.get('key')=='kev' for r in b['rows'] if r[0]=='CVE-2026-11111')
        self.assertIn('p1',row[-1]); self.assertIn('p2',row[-1])
        self.assertNotIn('未命中',row[-1])

    def test_catalog_count_mismatch_displays_unknown_with_reason(self):
        c = fixture(); comp, _ = inputs(c)
        c['sources']['kev']['raw']['count'] = 100
        data = analyze(c,comp,{'reviews':{}})
        page = render(c,data,comp,'snapshot-replay','truncated')
        self.assertEqual(Parsed(page).metrics['kev_catalog'],'待確認／Unknown')
        self.assertIn('統計欄位或識別資料仍有缺口',page)
        self.assertIn('declared_rows',page)
        self.assertNotIn('四來源完整取得',page)

    def test_repeated_catalog_keeps_existing_matches_and_distinguishes_calendar_week(self):
        c = fixture(); comp, data = inputs(c)
        page = render(c,data,comp,'snapshot-replay','synthetic-repeat')
        metrics = Parsed(page).metrics
        self.assertEqual({k:metrics[k] for k in ('kev_catalog','kev_window','kev_week','kev_added')},
                         {'kev_catalog':'2','kev_window':'2','kev_week':'0','kev_added':'0'})
        self.assertEqual([metrics[k] for k in ('dt_cves','dt_matches','dt_projects')], ['1','2','2'])
        self.assertEqual([metrics[k] for k in ('jira_open','jira_total','jira_done')], ['1','2','1'])
        self.assertEqual([metrics[k] for k in ('jira_window_new','jira_week_new')], ['2','0'])
        self.assertEqual(Parsed(page).overview['kev-dt'], '2')
        self.assertIn('2026-10-26T00:00:00+08:00',page)
        self.assertIn('專案（非產品）',page)
        md = daily_markdown(c,data,comp,'snapshot-replay','synthetic-repeat')
        self.assertIn('非 Done 工單：1',md)
        self.assertIn('finding 2、專案 2',md)
        self.assertIn('相較上次完整基準新增：0',md)

    def test_unknown_category_is_not_reported_as_open_or_lost_from_actions_weekly(self):
        c = fixture(); del c['sources']['jira']['raw'][0]['fields']['status']['statusCategory']
        comp, data = inputs(c)
        self.assertEqual(data['open_issues'],[])
        self.assertEqual([r['key'] for r in data['unknown_issues']],['DEMO-101'])
        self.assertIn('DEMO-101',[r['key'] for r in data['actions']])
        self.assertEqual(Parsed(render(c,data,comp,'snapshot-replay','unknown')).metrics['jira_open'],'待確認／Unknown')
        w = weekly(c,data,{'rows':[]},{'meetings':{},'overrides':[]},'2026-10-26')
        block = next(b for b in w['blocks'] if b.get('key')=='jira_open')
        self.assertTrue(any(r[0]=='DEMO-101' and '分類待確認' in r[3] for r in block['rows']))
        self.assertIn('Unknown',next(b for b in w['blocks'] if b.get('key')=='jira_count')['text'])

    def test_incomplete_flag_overrides_success_and_retains_observed_evidence(self):
        c = fixture(); c['sources']['dt']['complete'] = False
        comp, data = inputs(c)
        page = render(c,data,comp,'snapshot-replay','partial')
        self.assertFalse(data['kev_dt_complete'])
        self.assertEqual(Parsed(page).metrics['dt_matches'],'待確認／Unknown')
        self.assertEqual(data['statistics']['kev_dt']['observed_counts']['findings'],2)
        self.assertIn('capture.json#/sources/dt/raw/0',page)
        self.assertIn('完整命中總數 Unknown',page)

    def test_isolated_pipeline_repeat_preserves_old_report_and_recomputes_same_totals(self):
        from hashlib import sha256
        c = fixture(); before = copy.deepcopy(c)
        with tempfile.TemporaryDirectory() as td:
            snap = Path(td)/'source.json'; snap.write_text(json.dumps(c))
            first = run(Path(td)/'out','snapshot-replay',snapshot=snap,report_date='2026-10-26')
            old = Path(first['html_path']); digest = sha256(old.read_bytes()).hexdigest()
            second = run(Path(td)/'out','report-rebuild',report_date='2026-10-26')
            self.assertEqual(sha256(old.read_bytes()).hexdigest(),digest)
            self.assertNotEqual(first['html_path'],second['html_path'])
            data = json.loads((Path(second['run_dir'])/'report.json').read_text())['analysis']
            self.assertEqual(data['statistics']['kev']['counts']['added'],0)
            self.assertEqual(data['statistics']['kev_dt']['counts'],{'cves':1,'findings':2,'projects':2})
            self.assertEqual(Parsed(Path(second['html_path']).read_text()).metrics['dt_matches'],'2')
            self.assertEqual(json.loads(snap.read_text()),before)


if __name__ == '__main__':
    unittest.main()
