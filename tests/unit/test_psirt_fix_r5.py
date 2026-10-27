"""Report downloads stay pinned while current local records change."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from psirt_casework.report_version import describe, digest, pin_downloads, section
from psirt_casework.store import Invalid


class ReportVersionFix(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.run = Path(temporary.name) / '20261026T100000+0800-demo'; self.run.mkdir()
        self.manual = {'records': [{'id': 'DEMO-1', 'version': 1, 'payload': {'note': 'original'}}]}
        self.legacy = {'reviews': {}}
        self.manifest = {'started_at': '2026-10-26T10:00:00+08:00', 'artifacts_sha256': {}}
        for name, value in [('casework_manual_used.json', self.manual), ('human_review_used.json', self.legacy)]:
            raw = json.dumps(value).encode(); (self.run / name).write_bytes(raw)
            self.manifest['artifacts_sha256'][name] = hashlib.sha256(raw).hexdigest()

    def test_payload_change_with_same_version_sum_is_detected_without_mutating_report(self):
        before = {p.name: p.read_bytes() for p in self.run.iterdir()}
        self.assertEqual(describe(self.run, self.manifest, self.manual, self.legacy)['matches_report'], 'MATCH')
        current = copy.deepcopy(self.manual); current['records'][0]['payload']['note'] = 'new'
        value = describe(self.run, self.manifest, current, self.legacy)
        self.assertEqual(value['matches_report'], 'CHANGED')
        self.assertEqual(value['current_manual_sha256'], digest(current))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.run.iterdir()})
        self.assertEqual(describe(self.run, self.manifest, self.manual, {'reviews': {'new': {}}})['matches_report'], 'CHANGED')

    def test_legacy_missing_version_is_unknown_and_tampered_artifact_rejected(self):
        self.assertEqual(describe(self.run, {'artifacts_sha256': {}}, self.manual, self.legacy)['matches_report'], 'UNKNOWN')
        (self.run / 'casework_manual_used.json').write_text('{}')
        with self.assertRaises(Invalid):
            describe(self.run, self.manifest, self.manual, self.legacy)

    def test_downloads_pinned_without_changing_navigation_or_external_links(self):
        html = '<a href="casework.json">data</a><a href="manifest.json">manifest</a><a href="Weekly_PSIRT_Company_Format.html">weekly</a><a href="casework.html">work</a><a href="https://example.invalid/casework.json">external</a>'
        pinned = pin_downloads(html, self.run.name)
        self.assertIn('href="/runs/' + self.run.name + '/casework.json"', pinned)
        self.assertIn('href="casework.html"', pinned)
        self.assertIn('href="https://example.invalid/casework.json"', pinned)
        self.assertIn('data-report-artifact="Weekly_PSIRT_Company_Format.html"', pinned)
        self.assertIn('data-report-artifact="manifest.json"', pinned)
        self.assertNotIn('data-report-artifact="casework.html"', pinned)
        self.assertEqual(pin_downloads(pinned, 'another-run'), pinned)
        for bad in ('..', '../escape', '<script>', 'bad?run'):
            with self.subTest(bad=bad), self.assertRaises(Invalid): pin_downloads(html, bad)

    def test_report_panel_labels_static_and_working_versions(self):
        value = describe(self.run, self.manifest, {'records': []}, self.legacy)
        active = section({'report_version': value}, True, 'casework')
        self.assertIn('下載仍是最近已產生的固定報告', active)
        self.assertIn('/runs/' + self.run.name + '/casework.json', active)
        archive = section({'run_id': self.run.name, 'manual_sha256': 'hash'}, False, 'casework')
        self.assertIn('href="casework.json"', archive)
        self.assertIn('固定歷史報告', archive)


if __name__ == '__main__': unittest.main()
