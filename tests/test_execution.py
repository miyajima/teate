import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_repair

from teate.execution import cycle, execute, hook, hook_spec
from teate.jobs import Jobs
from teate.model import TeateError, digest
from teate.store import Ledger


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.f = test_repair.RepairTests()
        self.f.setUp()
        self.state = self.f.root / "state"
        self.runtime = self.f.root / "runtime"
        self.runtime.mkdir()
        self.f.policy["automation"].update(
            allowed_packages=["example"], minimum_release_age_hours=0
        )
        self.fake_hook = {
            "argv": ["/usr/bin/true"],
            "sha256": hashlib.sha256(Path("/usr/bin/true").read_bytes()).hexdigest(),
        }
        self.settings = {
            "enabled": True,
            "mode": "local",
            "runtime_assets": ["runtime"],
            **dict.fromkeys(("deploy", "observe", "health", "rollback"), self.fake_hook),
        }
        self.asset = {
            **self.f.asset,
            "remediation": self.settings,
            "verification": {"commands": [{"argv": ["python3", "test.py"]}]},
        }
        self.runtime_asset = {
            **self.f.asset,
            "id": "runtime",
            "path": str(self.runtime),
            "environment": "production",
        }
        self.f.ledger.register([self.asset, self.runtime_asset])
        self.record = self.f.execute()["results"][0]
        self.assertEqual(self.record["status"], "candidate_ready", self.record)
        self.jobs = Jobs(self.f.ledger)
        self.run = self.jobs.create("demo", self.record)
        self.calls = []
        self.bad_health = False
        self.rollback_done = False
        self.observation_unavailable = False

    def tearDown(self):
        self.f.tearDown()

    def receipt(self, run, **values):
        return {
            "run_id": run["id"],
            "candidate_id": digest(run["record"]["candidate_files"]),
            "release_id": "new",
            "previous_release_id": "old",
            **values,
        }

    def hook(self, spec, run, **kwargs):
        # Each invocation is independently identified by its configured argv.
        name = next(
            (k for k in ("deploy", "observe", "health", "rollback") if spec is self.settings[k]),
            None,
        )
        # Ledger serialization does not preserve object identity; tests register
        # separate marker args below and inspect those literal argv values.
        name = spec["argv"][-1]
        self.calls.append(name)
        if name == "deploy":
            for root in (self.f.repo, self.runtime):
                for file in ("package-lock.json", "package.json"):
                    shutil.copy2(Path(run["record"]["worktree"]) / file, root / file)
            return self.receipt(run, status="deployed")
        if name == "observe":
            if self.observation_unavailable:
                raise TeateError("observation_unavailable")
            return self.receipt(
                run,
                status="success",
                deployment="rolled_back" if self.rollback_done else "applied",
                release_id="old" if self.rollback_done else "new",
            )
        if name == "health":
            return self.receipt(
                run,
                healthy=not self.bad_health or self.rollback_done,
                release_id=kwargs.get("release_id", "new"),
            )
        if name == "rollback":
            self.rollback_done = True
            return self.receipt(run, status="rolled_back", release_id="old")
        raise AssertionError(name)

    def configure(self, **changes):
        settings = {**self.settings, **changes}
        for key in ("deploy", "observe", "health", "rollback"):
            if settings.get(key):
                settings[key] = {**self.fake_hook, "argv": ["/usr/bin/true", key]}
        self.settings = settings
        self.asset = {**self.asset, "remediation": settings}
        self.f.ledger.register([self.asset])
        self.record["asset_id_at_prepare"] = digest(self.asset)
        # Update the isolated test fixture before the first operation only.
        self.jobs.update(self.run["id"], "ready", record=self.record)

    def execute(self):
        with (
            patch("teate.execution.repair.registry", return_value=self.f.metadata),
            patch("teate.execution.verify", return_value={"status": "passed"}),
            patch("teate.execution.scan_source", side_effect=self.f.scan),
            patch("teate.execution.hook", side_effect=self.hook),
        ):
            return execute(self.f.ledger, self.f.policy, self.state, self.run["id"])

    def test_full_flow_with_git_and_plain_source_verifies_and_records_history(self):
        self.configure()
        result = self.execute()
        self.assertEqual(result["status"], "verified", result)
        self.assertEqual(self.f.ledger.findings()[0]["effective_status"], "resolved")
        self.assertEqual(self.calls.count("deploy"), 1)
        self.assertEqual(len(self.jobs.history(asset_id="demo")), 1)
        self.assertEqual(self.execute()["status"], "verified")
        self.assertEqual(self.calls.count("deploy"), 1)

    def test_absent_permissions_or_rollback_never_deploy(self):
        self.configure(rollback=None)
        self.assertEqual(self.execute()["status"], "awaiting_deployment")
        self.assertEqual(self.calls, [])

    def test_changed_source_or_policy_invalidates_before_any_write(self):
        self.configure()
        (self.f.repo / "package.json").write_text("{}")
        self.assertEqual(self.execute()["status"], "stale")
        self.assertEqual(self.calls, [])

    def test_unapproved_package_is_blocked(self):
        self.configure()
        self.f.policy["automation"]["allowed_packages"] = []
        self.assertEqual(self.execute()["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_incomplete_candidate_directs_to_cycle_without_retrying_operations(self):
        self.configure()
        self.jobs.update(
            self.run["id"],
            "ready",
            record={**self.record, "status": "review", "reason": "sandbox_not_permitted"},
        )
        with patch("teate.execution.repair.prepare") as prepare:
            for _ in range(2):
                result = self.execute()
                self.assertEqual(result["status"], "blocked")
                self.assertEqual(result["reason"], "sandbox_not_permitted")
                self.assertIn("次のagent cycle", result["next_action"])
                self.assertEqual(
                    self.jobs.get(self.run["id"])["next_action"], result["next_action"]
                )
            prepare.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.jobs.get(self.run["id"])["steps"], [])

    def test_failed_tests_prevent_all_external_writes(self):
        self.configure()
        with (
            patch("teate.execution.repair.registry", return_value=self.f.metadata),
            patch(
                "teate.execution.verify",
                return_value={"status": "failed", "reason": "project_test_failed"},
            ),
        ):
            result = execute(self.f.ledger, self.f.policy, self.state, self.run["id"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(self.calls, [])

    def test_network_loss_after_deployment_never_replays_mutation(self):
        self.configure()
        self.observation_unavailable = True
        self.assertEqual(self.execute()["status"], "verification_pending")
        self.observation_unavailable = False
        self.assertEqual(self.execute()["status"], "verified")
        self.assertEqual(self.calls.count("deploy"), 1)

    def test_crash_after_intent_is_reconciled_read_only(self):
        self.configure()
        self.jobs.intent(self.run["id"], "deploy")
        # Simulate actual execution completing before the worker crashed.
        self.hook(self.settings["deploy"], self.jobs.get(self.run["id"]))
        self.calls.clear()
        self.assertEqual(self.execute()["status"], "verified")
        self.assertNotIn("deploy", self.calls)

    def test_unknown_deployment_outcome_is_not_retried(self):
        self.configure()
        self.jobs.intent(self.run["id"], "deploy")

        def observe(spec, run, **kw):
            self.assertEqual(spec["argv"][-1], "observe")
            return self.receipt(run, status="success", deployment="unknown")

        with patch("teate.execution.hook", side_effect=observe):
            result = execute(self.f.ledger, self.f.policy, self.state, self.run["id"])
        self.assertEqual(result["status"], "verification_pending")
        self.assertNotEqual(self.f.ledger.findings()[0]["effective_status"], "resolved")

    def test_bad_health_rolls_back_once_and_never_marks_fixed(self):
        self.configure()
        self.bad_health = True
        self.assertEqual(self.execute()["status"], "uncertain")
        self.assertEqual(self.execute()["status"], "rolled_back")
        self.assertEqual(self.calls.count("deploy"), 1)
        self.assertEqual(self.calls.count("rollback"), 1)
        self.assertNotEqual(self.f.ledger.findings()[0]["effective_status"], "resolved")

    def test_wrong_runtime_never_closes(self):
        self.configure()
        original = self.hook

        def hook_(spec, run, **kw):
            value = original(spec, run, **kw)
            if spec["argv"][-1] == "observe":
                value["release_id"] = "wrong"
            return value

        self.hook = hook_
        result = self.execute()
        self.assertEqual(result["status"], "verification_pending")
        self.assertNotEqual(self.f.ledger.findings()[0]["effective_status"], "resolved")

    def test_plain_directory_executes_entire_flow(self):
        shutil.rmtree(self.f.repo / ".git")
        self.configure()
        self.record = self.f.execute()["results"][0]
        self.jobs.update(self.run["id"], "ready", record=self.record)
        self.assertEqual(self.execute()["status"], "verified")

    def test_runtime_scan_failure_never_closes(self):
        self.configure()
        original = self.f.scan

        def scan_(asset, **kw):
            values = original(asset, **kw)
            if asset["id"] == "runtime":
                values[0].update(status="error", complete=False, findings=[])
            return values

        self.f.scan = scan_
        self.assertEqual(self.execute()["status"], "verification_pending")
        self.assertNotEqual(self.f.ledger.findings()[0]["effective_status"], "resolved")

    def test_running_asset_gets_same_run(self):
        self.assertEqual(self.jobs.create("demo", self.record)["id"], self.run["id"])

    def test_hook_hash_changes_prevent_execution(self):
        with self.assertRaises(TeateError):
            hook_spec({**self.fake_hook, "sha256": "bad"})

    def test_hook_executes_registered_argv_and_rejects_foreign_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "hook"
            script.write_text('#!/bin/sh\nprintf \'{"run_id":"foreign"}\'\n')
            script.chmod(0o700)
            spec = {
                "argv": [str(script)],
                "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
            }
            with self.assertRaises(TeateError):
                hook(spec, self.run)

    def test_schema_migration_preserves_findings_and_backups(self):
        self.f.ledger.close()
        self.f.ledger = Ledger(self.f.root / "ledger.sqlite3")
        self.assertEqual(self.f.ledger.findings()[0]["id"], self.f.identifier)
        self.assertEqual(Jobs(self.f.ledger).get(self.run["id"])["asset_id"], "demo")

    def test_one_blocked_asset_does_not_abort_other_runs(self):
        workflow = {"decisions": []}
        with patch(
            "teate.execution.execute", return_value={"id": self.run["id"], "status": "blocked"}
        ) as execute_:
            results = cycle(self.f.ledger, self.f.policy, self.state, workflow)
        self.assertEqual(len(results), 1)
        self.assertEqual(execute_.call_count, 1)
