"""Gate 1 acceptance checks; stdlib only, process-wide network tripwire enabled."""
import copy
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from psirt_daily.offline import install_offline_guard

install_offline_guard()
from psirt_daily import pipeline
import fetch_kev

FIXTURES = ROOT / "tests/fixtures/psirt_daily"


class DailyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "isolated"
        self.fixture = self.root / "fixture.json"
        self.first = json.loads((FIXTURES / "baseline.json").read_text())
        self.next = json.loads((FIXTURES / "changes.json").read_text())

    def run_payload(self, payload):
        self.fixture.write_text(json.dumps(payload))
        return pipeline.run(self.fixture, self.output)

    def state(self):
        return json.loads((self.output / "state.json").read_text())

    def test_first_baseline_changes_and_idempotent_rerun(self):
        first = self.run_payload(self.first)
        original = {p: p.read_bytes() for p in self.output.rglob("*") if p.is_file()
                    and p.name != "state.json"}
        for item in first["sources"].values():
            self.assertEqual(item["status"], "SUCCESS")
            self.assertTrue(item["baseline_created"])
            self.assertIsNone(item["counts"])
            self.assertIsNone(item["baseline_ref"])
            self.assertIsNotNone(item["last_successful_at"])
        second = self.run_payload(self.next)
        for item in second["sources"].values():
            self.assertEqual(item["counts"], {"added": 1, "changed": 1, "removed": 1})
            self.assertFalse(item["baseline_created"])
        third = self.run_payload(self.next)
        for item in third["sources"].values():
            self.assertEqual(item["comparison"], "unchanged")
            self.assertEqual(item["counts"], {"added": 0, "changed": 0, "removed": 0})
        self.assertEqual(len({r["run_id"] for r in (first, second, third)}), 3)
        for path, data in original.items():
            self.assertEqual(path.read_bytes(), data)

    def test_failure_partial_unconfigured_and_recovery_preserve_baseline(self):
        first = self.run_payload(self.first)
        refs = self.state()["baselines"]
        failed = json.loads((FIXTURES / "degraded.json").read_text())
        result = self.run_payload(failed)
        self.assertEqual(result["status"], "PARTIAL")
        for name, status in (("salesforce", "NOT_CONFIGURED"), ("dt", "FAILED"),
                             ("jira", "PARTIAL")):
            item = result["sources"][name]
            self.assertEqual(item["status"], status)
            self.assertIsNone(item["counts"])
            self.assertEqual(item["last_successful_at"], first["sources"][name]["last_successful_at"])
            self.assertEqual(self.state()["baselines"][name], refs[name])
        self.assertEqual(result["sources"]["jira"]["fetched_count"], 1)
        self.assertIsNone(result["sources"]["dt"]["fetched_count"])
        recovered = self.run_payload(self.next)
        for name in ("salesforce", "dt", "jira"):
            self.assertEqual(recovered["sources"][name]["counts"],
                             {"added": 1, "changed": 1, "removed": 1})

    def test_partial_first_cannot_create_complete_baseline(self):
        source = self.first["sources"]["jira"]
        source["status"] = "PARTIAL"
        source["completeness"]["complete"] = False
        self.run_payload(self.first)
        self.assertNotIn("jira", self.state()["baselines"])
        source["status"] = "SUCCESS"
        source["completeness"]["complete"] = True
        recovered = self.run_payload(self.first)["sources"]["jira"]
        self.assertTrue(recovered["baseline_created"])
        self.assertIsNone(recovered["counts"])

    def test_incomplete_pages_or_count_mismatch_downgrade_success(self):
        self.run_payload(self.first)
        original = self.state()["baselines"]["jira"]
        for metadata in ({"complete": False, "expected_count": 2},
                         {"complete": True, "expected_count": 10},
                         {"complete": True, "expected_count": 2, "pagination_exhausted": False}):
            with self.subTest(metadata=metadata):
                self.first["sources"]["jira"]["completeness"] = metadata
                result = self.run_payload(self.first)["sources"]["jira"]
                self.assertEqual(result["status"], "PARTIAL")
                self.assertIsNone(result["counts"])
                self.assertEqual(self.state()["baselines"]["jira"], original)

    def test_scope_version_schema_rule_changes_stop_comparison(self):
        self.run_payload(self.first)
        for key, value in (("scope", {"projects": ["DEMO-OTHER"]}),
                           ("source_version", "synthetic-dt-5.2.0"),
                           ("schema_version", "fixture-records/2"),
                           ("rule_version", "demo-filter/2")):
            with self.subTest(key=key):
                self.first["sources"]["dt"][key] = value
                result = self.run_payload(self.first)["sources"]["dt"]
                self.assertEqual(result["comparison"], "incompatible_baseline")
                self.assertEqual(result["incompatible_fields"], [key])
                self.assertTrue(result["baseline_created"])
                self.assertIsNone(result["counts"])
        with patch.object(pipeline, "RULE", "observation-diff/2"):
            result = self.run_payload(self.first)["sources"]["dt"]
            self.assertIn("pipeline_rule_version", result["incompatible_fields"])
            self.assertIsNone(result["counts"])

    def test_non_synthetic_and_unknown_source_refused_before_output(self):
        for payload in ({**self.first, "synthetic": False},
                        {**self.first, "sources": {"production": {}}},
                        {**self.first, "sources": {"kev": {"synthetic": False}}},
                        {**self.first, "sources": {"kev": {"synthetic": True, "mode": "live"}}}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.run_payload(payload)
        self.assertFalse(self.output.exists())

    def test_network_dns_and_subprocess_calls_are_blocked(self):
        for action in (lambda: socket.socket(), lambda: socket.getaddrinfo("example.invalid", 443),
                       lambda: subprocess.run([sys.executable, "-c", "pass"])):
            with self.assertRaises(PermissionError):
                action()
        # Deliberate integration regression: even a collector accidentally invoked
        # in validation cannot connect. It cannot silently report SUCCESS.
        with patch.object(fetch_kev, "index_catalog", side_effect=lambda raw: socket.socket()):
            with self.assertRaises(PermissionError):
                self.run_payload(self.first)
        self.assertFalse((self.output / "state.json").exists())

    def test_kev_functions_are_reused(self):
        with patch.object(fetch_kev, "index_catalog", wraps=fetch_kev.index_catalog) as validate:
            self.run_payload(self.first)
            self.assertTrue(validate.called)
        with patch.object(fetch_kev, "diff_catalogs", wraps=fetch_kev.diff_catalogs) as compare:
            self.run_payload(self.next)
            compare.assert_called_once()

    def test_raw_states_followups_dates_and_evidence_are_separate(self):
        report = self.run_payload(self.first)
        self.assertEqual(report["human_review"]["records_modified"], False)
        for name in pipeline.SOURCES:
            ref = report["sources"][name]["snapshot_ref"]
            data = (self.output / ref["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), ref["sha256"])
            self.assertEqual(json.loads(data)["observation"], self.first["sources"][name])
        for row in report["followups"]:
            self.assertTrue(row["review_required"])
            self.assertEqual(row["review_status"], "NOT_REVIEWED")
            self.assertEqual(set(row["dates"]), {"reply", "remediation", "verification", "release"})
            ref = row["evidence_ref"]
            data = json.loads((self.output / ref["path"]).read_text())
            for token in ref["json_pointer"].split("/")[1:]:
                data = data[int(token)] if isinstance(data, list) else data[token]
            self.assertEqual(data["id"], row["record_id"])
        text = Path(report["daily_markdown"]).read_text()
        self.assertIn("SYNTHETIC / NOT FOR PRODUCTION", text)
        self.assertIn("+08:00", report["completed_at_local"])
        self.assertIn("+00:00", report["completed_at_utc"])
        self.assertNotIn("approved_status", report)

    def test_invalid_timestamp_duplicate_ids_and_bad_kev_fail_without_zero(self):
        self.run_payload(self.first)
        for name, key, value in (
            ("jira", "observed_at", "2026-10-15T09:00:00"),
            ("jira", "raw", [{"id": "DUP"}, {"id": "DUP"}]),
            ("kev", "raw", {"count": 0, "vulnerabilities": []}),
            ("kev", "raw", {"count": 9, "vulnerabilities": [{"cveID": "CVE-2099-90001"}]}),
        ):
            with self.subTest(name=name, key=key):
                refs = self.state()["baselines"]
                payload = copy.deepcopy(self.first)
                payload["sources"][name][key] = value
                result = self.run_payload(payload)["sources"][name]
                self.assertEqual(result["status"], "FAILED")
                self.assertIsNone(result["counts"])
                self.assertEqual(self.state()["baselines"][name], refs[name])

    def test_out_of_order_observation_does_not_roll_back_baseline(self):
        self.run_payload(self.next)
        original = self.state()["baselines"]
        result = self.run_payload(self.first)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(self.state()["baselines"], original)

    def test_order_only_unchanged_and_missing_versus_null_detected(self):
        self.run_payload(self.first)
        for name, item in self.first["sources"].items():
            rows = item["raw"]["vulnerabilities"] if name == "kev" else item["raw"]
            rows.reverse()
        report = self.run_payload(self.first)
        for item in report["sources"].values():
            self.assertEqual(item["comparison"], "unchanged")
        self.first["sources"]["jira"]["raw"][0]["new_null"] = None
        report = self.run_payload(self.first)
        fields = report["sources"]["jira"]["changes"]["changed"][0]["fields"]
        self.assertFalse(fields["new_null"]["before_present"])
        self.assertTrue(fields["new_null"]["after_present"])

    def test_complete_empty_nonkev_is_valid_unconfigured_is_unknown(self):
        payload = copy.deepcopy(self.first)
        payload["followups"] = []
        payload["sources"] = {"jira": payload["sources"]["jira"]}
        payload["sources"]["jira"]["raw"] = []
        payload["sources"]["jira"]["completeness"]["expected_count"] = 0
        self.run_payload(payload)
        report = self.run_payload(payload)
        self.assertEqual(report["sources"]["jira"]["counts"]["added"], 0)
        for name in ("kev", "salesforce", "dt"):
            self.assertEqual(report["sources"][name]["status"], "NOT_CONFIGURED")
            self.assertIsNone(report["sources"][name]["counts"])
        empty = self.run_payload({"schema_version": pipeline.SCHEMA, "synthetic": True, "sources": {}})
        self.assertEqual(empty["status"], "NOT_CONFIGURED")

    def test_existing_output_and_human_review_files_untouched(self):
        self.output.mkdir()
        review = self.output / "human-review.json"
        review.write_text('{"approved_by":"synthetic-reviewer"}')
        before = review.read_bytes()
        with self.assertRaises(ValueError):
            self.run_payload(self.first)
        self.assertEqual(review.read_bytes(), before)
        self.assertEqual(list(self.output.iterdir()), [review])

    def test_symlink_output_and_internal_state_refused(self):
        actual = self.root / "actual"
        actual.mkdir()
        self.output.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.run_payload(self.first)
        self.assertEqual(list(actual.iterdir()), [])
        self.output.unlink()
        self.run_payload(self.first)
        (self.output / "state.json").unlink()
        sensitive = self.root / "review.json"
        sensitive.write_text("do not change")
        (self.output / "state.json").symlink_to(sensitive)
        with self.assertRaises(ValueError):
            self.run_payload(self.first)
        self.assertEqual(sensitive.read_text(), "do not change")

    def test_corrupt_or_missing_state_and_tampered_snapshot_fail_closed(self):
        self.run_payload(self.first)
        state_path = self.output / "state.json"
        original = state_path.read_bytes()
        ref = self.state()["baselines"]["kev"]
        state_path.write_text("broken")
        with self.assertRaises(ValueError):
            self.run_payload(self.next)
        state_path.unlink()
        with self.assertRaises(ValueError):
            self.run_payload(self.next)
        state_path.write_bytes(original)
        snapshot = self.output / ref["path"]
        snapshot.write_text("tampered")
        with self.assertRaises(ValueError):
            self.run_payload(self.next)
        self.assertEqual(state_path.read_bytes(), original)

    def test_report_write_failure_does_not_advance_state(self):
        self.run_payload(self.first)
        state = (self.output / "state.json").read_bytes()
        write = pipeline.write_new

        def fail_report(path, data):
            if path.name == "daily.md":
                raise OSError("synthetic disk failure")
            write(path, data)

        with patch.object(pipeline, "write_new", side_effect=fail_report):
            with self.assertRaises(OSError):
                self.run_payload(self.next)
        self.assertEqual((self.output / "state.json").read_bytes(), state)
        result = self.run_payload(self.next)
        self.assertEqual(result["sources"]["kev"]["counts"]["added"], 1)

    def test_duplicate_json_keys_rejected(self):
        self.fixture.write_text('{"synthetic": true, "synthetic": false}')
        with self.assertRaises(ValueError):
            pipeline.run(self.fixture, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
