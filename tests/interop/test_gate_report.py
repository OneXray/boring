"""No container or VCore checkout is needed to test final gate verdicts."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from gate_report import capture_inputs, finalize_run


class GateReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fork = Path(self.temporary.name)
        self.source = self.fork / "source.rs"
        self.lock = self.fork / "Cargo.lock"
        self.verifier = self.fork / "tests/interop/gate_report.py"
        self.verifier.parent.mkdir(parents=True)
        self.binary = self.fork / "probe"
        for path in (self.source, self.lock, self.verifier, self.binary):
            path.write_text("original")
        self.identity = Mock(return_value={"source_tree_sha256": "original"})
        self.lab = SimpleNamespace(run_id="owned-run")
        self.listing = Mock(return_value=[])
        self.record = dict(
            status="PASS",
            cases=[{"passed": True}],
            isolation={"peers": [{"joined": True}]},
            **capture_inputs(self.fork, [self.source], self.binary, self.identity),
        )

    def finalize(self):
        with contextlib.redirect_stdout(io.StringIO()):
            finalize_run(
                self.record,
                fork=self.fork,
                binary=self.binary,
                source_identity=self.identity,
                lab=self.lab,
                listing=self.listing,
                output=self.fork,
            )

    def saved(self):
        return json.loads((self.fork / "results.json").read_text())

    def assert_fails_and_saves(self):
        with self.assertRaisesRegex(RuntimeError, "cleanup or input identity"):
            self.finalize()
        self.assertEqual(self.saved()["status"], "FAIL")

    def test_stable_sources_and_cleaned_peers_pass(self):
        self.finalize()
        self.assertEqual(self.saved()["status"], "PASS")
        self.assertTrue(self.record["source_unchanged"])
        self.assertTrue(self.record["cleanup"])
        self.assertEqual(self.identity.call_count, 2)
        self.assertEqual(self.record["lab_source"], self.record["lab_source_after"])

    def test_lab_only_change_invalidates_gate(self):
        self.identity.return_value = {"source_tree_sha256": "changed"}
        self.assert_fails_and_saves()
        self.assertFalse(self.record["source_unchanged"])
        self.assertTrue(self.record["cleanup"])

    def test_fork_lock_probe_and_verifier_changes_invalidate_gate(self):
        for path in (self.source, self.lock, self.binary, self.verifier):
            with self.subTest(path=path.name):
                path.write_text("changed")
                self.assert_fails_and_saves()
                self.assertFalse(self.record["source_unchanged"])
                path.write_text("original")

    def test_removed_input_still_records_cleanup_and_failure(self):
        self.source.unlink()
        self.assert_fails_and_saves()
        self.assertEqual(self.record["identity_error"], "FileNotFoundError")
        self.assertTrue(self.record["cleanup"])

    def test_identity_error_still_records_cleanup_and_failure(self):
        self.identity.side_effect = ValueError("identity unavailable")
        self.assert_fails_and_saves()
        self.assertFalse(self.record["source_unchanged"])
        self.assertTrue(self.record["cleanup"])

    def test_leftover_owned_container_fails_but_unrelated_one_does_not(self):
        self.listing.return_value = [
            {"id": "peer", "configuration": {"labels": {"vcore-run": "other"}}}
        ]
        self.finalize()
        self.assertTrue(self.record["cleanup"])
        self.listing.return_value[0]["configuration"]["labels"]["vcore-run"] = (
            self.lab.run_id
        )
        self.assert_fails_and_saves()
        self.assertFalse(self.record["cleanup"])

    def test_unjoined_process_invalidates_gate(self):
        self.record["isolation"]["peers"][0]["joined"] = False
        self.assert_fails_and_saves()
        self.assertFalse(self.record["cleanup"])

    def test_cleanup_listing_error_is_fail_closed(self):
        self.listing.side_effect = RuntimeError("listing unavailable")
        self.assert_fails_and_saves()
        self.assertTrue(self.record["source_unchanged"])
        self.assertFalse(self.record["cleanup"])
        self.assertEqual(self.record["cleanup_error"], "RuntimeError")

    def test_missing_lab_is_not_a_cleanup_pass(self):
        self.lab = None
        self.assert_fails_and_saves()
        self.listing.assert_not_called()

    def test_original_protocol_failure_is_preserved(self):
        self.record.update(status="FAIL", failure="original protocol failure")
        self.finalize()
        self.assertEqual(self.saved()["status"], "FAIL")
        self.assertEqual(self.saved()["failure"], "original protocol failure")
        self.identity.return_value = {"source_tree_sha256": "changed"}
        self.assert_fails_and_saves()
        self.assertEqual(self.saved()["failure"], "original protocol failure")


if __name__ == "__main__":
    unittest.main()
