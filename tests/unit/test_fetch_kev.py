"""Offline checks for daily KEV snapshots and failure preservation (stdlib only)."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import fetch_kev
from confluence_weekly.adapters import KevLiveSource


def catalog(*rows):
    return {"catalogVersion": "2026.10.06", "dateReleased": "2026-10-06T00:00:00Z",
            "count": len(rows), "vulnerabilities": list(rows), "extraMetadata": {"kept": True}}


def row(cve="CVE-2024-7490", **fields):
    return {"cveID": cve, "dateAdded": "2026-10-01", "product": "Example", **fields}


class DailyKevTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_catalog(self, raw):
        return fetch_kev.run(self.root, Mock(load_raw=Mock(return_value=raw)))

    def test_baseline_then_changed_added_removed(self):
        raw = catalog(row(notes="old"), row("CVE-2024-10001"))
        first = self.run_catalog(raw)
        self.assertEqual(first["status"], "BASELINE_CREATED")
        original = self.root / first["current_snapshot"]
        original_bytes = original.read_bytes()
        self.assertEqual(json.loads(original_bytes)["raw_catalog"], raw)
        second = self.run_catalog(catalog(row(notes="new"), row("CVE-2024-10002")))
        self.assertEqual(second["counts"], {"added": 1, "changed": 1, "removed": 1})
        self.assertEqual(second["changed"][0]["fields"]["notes"]["before"], "old")
        self.assertEqual(original.read_bytes(), original_bytes)
        self.assertEqual(len(list((self.root / "snapshots/kev").glob("*.json"))), 2)

    def test_order_only_is_not_changed(self):
        old = catalog(row(), row("CVE-2024-10001"))
        new = copy.deepcopy(old)
        new["vulnerabilities"].reverse()
        self.assertEqual(fetch_kev.diff_catalogs(old, new),
                         {"added": [], "changed": [], "removed": []})

    def test_removed_field_and_new_null_field_are_detected(self):
        changed = fetch_kev.diff_catalogs(catalog(row(notes=None)), catalog(row(newField=None)))
        fields = changed["changed"][0]["fields"]
        self.assertFalse(fields["notes"]["after_present"])
        self.assertFalse(fields["newField"]["before_present"])

    def test_http_failure_never_uses_mirror_or_zero(self):
        baseline = self.run_catalog(catalog(row()))
        path = self.root / baseline["current_snapshot"]
        before = path.read_bytes()
        source = KevLiveSource(transport=lambda *args: (503, b"bad"))
        result = fetch_kev.run(self.root, source)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error_category"], "CISA_HTTP_503")
        self.assertIsNone(result["counts"])
        self.assertIsNone(result["total_vulnerability_count"])
        self.assertEqual(result["last_success"]["total_vulnerability_count"], 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(list((self.root / "snapshots/kev").glob("*.json"))), 1)
        self.assertIn("Not evaluated", (self.root / "outputs/kev/latest_diff.md").read_text())

    def test_bad_json_and_invalid_catalogs_fail(self):
        source = KevLiveSource(transport=lambda *args: (200, b"not JSON"))
        self.assertEqual(fetch_kev.run(self.root, source)["error_category"], "JSONDecodeError")
        for raw in ({}, catalog(), {**catalog(row()), "count": 999}, catalog(row(), row())):
            self.assertEqual(self.run_catalog(raw)["status"], "FAILED")
        self.assertEqual(list((self.root / "snapshots/kev").glob("*.json")), [])

    def test_corrupt_previous_is_not_silently_replaced_by_baseline(self):
        directory = self.root / "snapshots/kev"
        directory.mkdir(parents=True)
        (directory / "20260101T000000.000000Z.json").write_text("broken")
        result = self.run_catalog(catalog(row()))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(len(list(directory.glob("*.json"))), 1)

    def test_legacy_collector_fallback_is_preserved(self):
        mirror = self.root / "mirror.json"
        mirror.write_text(json.dumps(catalog(row())))
        source = KevLiveSource(mirror_path=mirror, transport=lambda *args: (503, b"bad"))
        self.assertEqual(source.load()["source"], "mirror")
        source = KevLiveSource(transport=lambda *args: (200, json.dumps(catalog(row())).encode()))
        self.assertEqual(source.load()["source"], "live")


if __name__ == "__main__":
    unittest.main()
