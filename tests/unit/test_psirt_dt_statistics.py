import copy
import hashlib
import json
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from psirt_ops.dt_statistics import build, render
from psirt_ops.pipeline import run
from psirt_dt_fixtures import capture, sample, unrated_sample


class StatisticsTests(unittest.TestCase):
    def test_unrated_retains_raw_value_and_is_never_known_zero(self):
        for severity in ('UNASSIGNED',None,'UNKNOWN','unfamiliar'):
            with self.subTest(severity=severity):
                c=sample()
                for f in c['sources']['dt']['raw']:f['vulnerability']['severity']=severity
                d=build(c,'r','snapshot-replay')
                self.assertIsNone(d['counts']['critical'])
                self.assertEqual(d['severity_summary'],{'known_critical_findings':0,'unrated_findings':2})
                for v in d['vulnerabilities']:
                    self.assertEqual(v['source_severity'],severity)
                    self.assertEqual(v['severity'],'UNKNOWN')
                    self.assertFalse(v['severity_rated'])
                self.assertEqual(d['status'],'SUCCESS')  # Fetch complete, rating unknown.

    def test_mixed_ratings_and_genuinely_rated_zero(self):
        d=build(unrated_sample(),'r','snapshot-replay')
        self.assertEqual(d['severity_summary'],{'known_critical_findings':1,'unrated_findings':3})
        self.assertIsNone(d['counts']['critical'])
        c=sample()
        for f in c['sources']['dt']['raw']:f['vulnerability']['severity']='HIGH'
        self.assertEqual(build(c,'r','snapshot-replay')['counts']['critical'],0)

    def test_same_cve_two_projects_not_two_products(self):
        c=sample(); c['sources']['dt']['projects'][0]['metrics']={'findingsTotal':200}
        d=build(c,'r','snapshot-replay')
        self.assertEqual(d['counts'],{'components':2,'cves':1,'findings':2,'projects':2,'kev':2,'critical':2})
        self.assertNotIn('products',d['counts'])
        self.assertTrue(all(p['vendor'] is None for p in d['projects']))

    def test_inventory_includes_components_without_findings(self):
        c=sample(); c['sources']['dt']['components'][0]['records'].append({'uuid':'clean','name':'empty','version':'1'})
        self.assertEqual(build(c,'r','snapshot-replay')['counts']['components'],3)

    def test_failure_and_incomplete_pagination_are_not_zero(self):
        for status in ('FAILED','PARTIAL'):
            c=sample(); c['sources']['dt'].update(status=status,complete=False)
            d=build(c,'r','snapshot-replay')
            self.assertTrue(all(v is None for v in d['counts'].values()))
            self.assertEqual(d['status'],status)
        c=sample(); c['sources']['dt']['pages']=[{'endpoint':'findings','complete':False}]
        d=build(c,'r','snapshot-replay'); self.assertEqual(d['status'],'PARTIAL')
        self.assertIsNone(d['counts']['findings'])

    def test_complete_empty_is_zero_and_kev_failure_is_unknown(self):
        c=sample(); dt=c['sources']['dt']; dt.update(projects=[],components=[],raw=[])
        dt['scope']['project_uuids']=[]
        self.assertTrue(all(v==0 for v in build(c,'r','snapshot-replay')['counts'].values()))
        c=sample();c['sources']['kev'].update(status='FAILED',complete=False,raw=None)
        d=build(c,'r','snapshot-replay');self.assertIsNone(d['counts']['kev'])
        self.assertEqual(d['counts']['findings'],2)

    def test_duplicates_missing_inventory_and_severity_do_not_claim_complete(self):
        c=sample();c['sources']['dt']['raw'].append(copy.deepcopy(c['sources']['dt']['raw'][0]))
        d=build(c,'r','snapshot-replay');self.assertEqual(d['observed_counts']['findings'],2)
        self.assertIsNone(d['counts']['findings'])
        c=sample();c['sources']['dt']['components']=[]
        self.assertEqual(build(c,'r','snapshot-replay')['status'],'PARTIAL')
        c=sample()
        for f in c['sources']['dt']['raw']:f['vulnerability']['severity']=None
        self.assertIsNone(build(c,'r','snapshot-replay')['counts']['critical'])

    def test_explicit_alias_only_and_no_invented_cve(self):
        c=sample()
        for f in c['sources']['dt']['raw']:
            f['vulnerability'].update(vulnId='INTEL-SA-TEST',description='mentions CVE-2026-11111',aliases=[{'cveId':'CVE-2026-99999'}])
        d=build(c,'r','snapshot-replay');self.assertEqual(d['counts']['cves'],1);self.assertEqual(d['counts']['kev'],2)
        for f in c['sources']['dt']['raw']:f['vulnerability']['aliases']=[]
        d=build(c,'r','snapshot-replay');self.assertEqual(d['counts']['cves'],0);self.assertIsNone(d['counts']['kev'])

    def test_render_payload_safe_and_csp_matches_only_trusted_script(self):
        c=sample();attack='</pre><script>window.pwned=1</script>'
        c['sources']['dt']['components'][0]['records'][0]['name']=attack
        d=build(c,'r','snapshot-replay')
        shell='<html><head><meta content="default-src \'none\';"></head><body><aside><a href="#jira">Jira</a></aside><main>SECRET_SF_BODY</main></body></html>'
        page=render(shell,d)
        self.assertNotIn(attack,page);self.assertNotIn('SECRET_SF_BODY',page)
        self.assertIn('href="index.html#jira"',page)
        self.assertEqual(page.count('<script>'),1)
        import base64
        js=(ROOT/'scripts/psirt_ops/assets/dt-statistics-v1.js').read_bytes()
        digest=base64.b64encode(hashlib.sha256(js).digest()).decode()
        self.assertIn("script-src 'sha256-"+digest+"'",page)

    def test_pipeline_preserves_reviews_previous_reports_and_run_consistency(self):
        c=sample();c['synthetic']=False
        for s in c['sources'].values():s['synthetic']=False
        with tempfile.TemporaryDirectory() as td, patch('psirt_ops.adapters.collect',return_value=c):
            first=run(td,'live',c['config']);p=Path(first['run_dir'])
            hashes={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in p.iterdir()}
            review=Path(td)/'human_review.json'
            review.write_text(json.dumps({'schema':'psirt-human-review/1','reviews':{'DEMO-1':{'reviewer':'fixture','evidence_ref':'fixture:e1','accepted_by':'fixture owner'}}}))
            saved=review.read_bytes()
            c['sources']['dt'].update(status='PARTIAL',complete=False)
            second=run(td,'live',c['config']);new=Path(second['run_dir'])
            self.assertEqual(review.read_bytes(),saved)
            self.assertEqual(json.loads((new/'human_review_used.json').read_text()),json.loads(saved))
            for name,h in hashes.items():self.assertEqual(hashlib.sha256((p/name).read_bytes()).hexdigest(),h)
            m=json.loads((new/'manifest.json').read_text());d=json.loads((new/'dt-statistics.json').read_text())
            self.assertEqual(d['run_id'],m['run_id']);self.assertEqual(d['status'],'PARTIAL')
            html=(new/'dt-statistics.html').read_text()
            self.assertIn('總數 Unknown',html)
            self.assertIn('data-dt-metric="findings">待確認／Unknown',html)
            for name,h in m['artifacts_sha256'].items():self.assertEqual(hashlib.sha256((new/name).read_bytes()).hexdigest(),h)
            for name in ('Daily_PSIRT.md','Weekly_PSIRT_Company_Format.md','Vance_Action_List.md'):
                self.assertTrue((new/name).is_file())
            self.assertIn('href="dt-statistics.html"',(new/'index.html').read_text())


if __name__=='__main__':unittest.main()
