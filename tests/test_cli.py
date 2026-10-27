import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from teate.cli import main
from teate.model import TeateError, snapshot


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "config.json"
        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "state_dir": "state",
                    "assets": [
                        {
                            "id": "example",
                            "project": "example",
                            "environment": "test",
                            "kind": "source",
                            "path": "/not-available",
                        }
                    ],
                }
            )
        )

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args):
        capture = io.StringIO()
        with redirect_stdout(capture):
            code = main(["--config", str(self.config), *args])
        return code, capture.getvalue()

    def test_ingest_plan_report_and_resolution_end_to_end(self):
        finding = {
            "advisory_id": "CVE-2026-12345",
            "package": "example",
            "version": "1.0.0",
            "ecosystem": "npm",
            "severity": "HIGH",
            "fixed_versions": ["1.0.1"],
        }
        scan = snapshot(
            "example",
            "osv",
            "repository",
            {"type": "source", "revision": "abc"},
            [finding],
            observed_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        )
        receipt = self.root / "scan.json"
        receipt.write_text(json.dumps(scan))
        self.assertEqual(self.call("ingest", str(receipt))[0], 0)
        code, text = self.call("plan")
        self.assertEqual(json.loads(text)[0]["action"], "prepare_update_pr")
        self.assertEqual(code, 0)
        report = self.root / "nested" / "report.md"
        self.call("report", "--output", str(report))
        self.assertIn("CVE-2026-12345", report.read_text())
        scan.update(findings=[], observed_at=datetime.now(UTC).isoformat())
        receipt.write_text(json.dumps(scan))
        self.call("ingest", str(receipt))
        self.assertEqual(json.loads(self.call("status")[1])["resolved"], 1)

    def test_unavailable_source_is_not_reported_clean(self):
        code, text = self.call("run", "--scanner", "npm-audit")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["counts"]["unchecked_assets"], 1)
        self.assertTrue((self.root / "state" / "report.md").exists())

    @patch("teate.github.sync_issues", side_effect=TeateError("sync failed"))
    def test_report_survives_issue_sync_failure(self, sync):
        code, text = self.call("run", "--sync-issues", "owner/repo")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(text)["transport_errors"], ["sync failed"])
        self.assertIn("sync failed", (self.root / "state" / "report.md").read_text())

    def test_generated_launch_agent_is_not_installed_and_contains_no_token(self):
        target = self.root / "agent.plist"
        code, text = self.call("launch-agent", "--output", str(target))
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(text)["installed"])
        self.assertNotIn("GH_TOKEN", target.read_text())

    def test_init_refuses_overwriting_existing_inventory(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["init", "--output", str(self.config)]), 2)


if __name__ == "__main__":
    unittest.main()
