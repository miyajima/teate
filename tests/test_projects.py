import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from teate.agent import MAX_BRIEF_BYTES, brief, render
from teate.cli import main
from teate.model import snapshot
from teate.report import markdown, summary
from teate.projects import overview
from teate.store import Ledger


class ProjectActionsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.temp.name) / "ledger.sqlite3")
        self.asset = {"id": "app:dev", "project": "app", "environment": "development",
                      "kind": "source"}
        self.ledger.register([self.asset])

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def finding(self, location, package="rack", **kwargs):
        return {"advisory_id": "GHSA-" + package, "package": package, "version": "1.0.0",
                "ecosystem": "RubyGems", "severity": "HIGH", "fixed_versions": ["1.0.1"],
                "location": location, **kwargs}

    def ingest(self, findings, **kwargs):
        self.ledger.ingest(snapshot(self.asset["id"], "osv", "repository",
                                    {"type": "source", "revision": "abc"}, findings, **kwargs))

    def test_actions_group_by_file_without_hiding_copies_or_inventing_deployment(self):
        self.ingest([self.finding("Gemfile.lock"), self.finding("Gemfile.lock", "puma"),
                     self.finding(".worktrees/old/Gemfile.lock")])
        data = summary(self.ledger, {})
        project = data["projects"][0]
        self.assertEqual(project["open_count"], 3)
        self.assertEqual(len(project["tasks"]), 2)
        regular = next(t for t in project["tasks"] if t["file"] == "Gemfile.lock")
        copy = next(t for t in project["tasks"] if t["file"].startswith(".worktrees"))
        self.assertEqual(regular["finding_count"], 2)
        self.assertEqual(copy["scope_hint"], "review")
        self.assertIn("現用", copy["instruction"])
        self.assertIn("依存定義", regular["instruction"])
        self.assertEqual(project["runtime_status"], "unverified")
        self.assertEqual(len(data["findings"]), 3)
        text = markdown(data)
        self.assertLess(text.index("プロジェクトごとの次の作業"), text.index("## 対応候補"))
        self.assertIn("Gemfile.lock", text)
        self.assertIn("rack", text)
        rendered = render(brief(self.ledger, {}), projects=data["projects"])
        self.assertIn("プロジェクトごとの次の作業", rendered["text"])
        self.assertIn("Gemfile.lock", rendered["text"])

    def test_missing_dependency_inputs_are_unknown_with_a_specific_next_step(self):
        self.ingest([], status="unsupported", complete=False,
                    message="no supported dependency manifest found")
        row = summary(self.ledger, {})["projects"][0]
        self.assertIsNone(row["open_count"])
        self.assertEqual(row["next_action"], "check_dependency_inputs")
        self.assertIn("依存", row["next_step"])
        self.assertIn("対象外", row["next_step"])

    def test_parser_failure_reports_file_and_does_not_become_a_network_diagnosis(self):
        self.ingest([], status="error", complete=False,
                    message="OSV cannot parse dependency file: api/go.sum (exit 127)")
        row = summary(self.ledger, {})["projects"][0]
        self.assertEqual(row["next_action"], "fix_scanner_input")
        self.assertIn("go.mod", row["next_step"])
        self.assertIn("api/go.sum", " ".join(row["problems"]))
        self.assertIsNone(row["open_count"])

    def test_test_and_runtime_verification_states_remain_distinct(self):
        self.ingest([self.finding("Gemfile.lock")])
        finding = self.ledger.findings()[0]
        for state, action in [("testing", "complete_required_tests"),
                              ("awaiting_deployment", "verify_deployed_runtime")]:
            with self.subTest(state=state):
                self.ledger.mark(finding["id"], state, "fixture")
                row = summary(self.ledger, {})["projects"][0]
                self.assertEqual(row["next_action"], action)
                self.assertEqual(row["open_count"], 1)
                self.assertNotIn("配備済み", row["next_step"])

    def test_same_project_environments_do_not_share_counts_or_actions(self):
        self.ingest([self.finding("Gemfile.lock")])
        prod = {**self.asset, "id": "app:prod", "environment": "production"}
        self.ledger.register([prod])
        rows = summary(self.ledger, {})["projects"]
        self.assertEqual(len(rows), 2)
        self.assertIsNone(next(r for r in rows if r["environment"] == "production")["open_count"])

    def test_partial_scan_keeps_known_findings_without_claiming_a_complete_count(self):
        self.ingest([self.finding("Gemfile.lock")], complete=False, message="partial OSV errors")
        row = summary(self.ledger, {})["projects"][0]
        self.assertIsNone(row["open_count"])
        self.assertEqual(row["known_open_count"], 1)
        self.assertEqual(row["tasks"][0]["finding_count"], 1)

    def test_image_and_cloud_actions_do_not_instruct_editing_a_source_lockfile(self):
        self.ingest([self.finding("openssl")])
        data = summary(self.ledger, {})
        for kind in ["image", "cloud-run", "mac"]:
            with self.subTest(kind=kind):
                data["coverage"][0]["asset"]["kind"] = kind
                row = overview(data["coverage"], data["findings"], data["actions"])[0]
                self.assertNotIn("lock", row["next_step"])
                self.assertEqual(row["runtime_status"], "see_asset_evidence")

    def test_cli_render_includes_projects_beyond_the_bounded_agent_brief(self):
        self.ingest([self.finding("Gemfile.lock")])
        for i in range(7):
            self.ledger.register([{**self.asset, "id": f"source:{i}", "project": f"other-{i}"}])
        config = Path(self.temp.name) / "config.json"
        config.write_text(json.dumps({"schema_version": 1, "state_dir": self.temp.name,
                                      "assets": self.ledger.assets()}))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--config", str(config), "agent", "render"]), 0)
        for name in ["app", *[f"other-{i}" for i in range(7)]]:
            self.assertIn(name + " / development", output.getvalue())

    def test_brief_has_bounded_project_actions_and_no_absolute_asset_path(self):
        self.ingest([self.finding("Gemfile.lock")])
        for i in range(40):
            self.ledger.register([{**self.asset, "id": f"source:{i}",
                                   "project": "長い名前" * 50,
                                   "path": "/private/example/secret-project"}])
        packet = brief(self.ledger, {})
        self.assertTrue(packet["project_actions"])
        self.assertGreater(packet["omitted_projects"], 0)
        self.assertLessEqual(len(json.dumps(packet, ensure_ascii=False, indent=2).encode()) + 1,
                             MAX_BRIEF_BYTES)
        self.assertNotIn("/private/example", json.dumps(packet))


if __name__ == "__main__":
    unittest.main()
