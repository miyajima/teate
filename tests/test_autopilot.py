import json
import unittest
from pathlib import Path
from unittest.mock import patch

import test_repair

from teate.autopilot import run
from teate.investigation import dispatch, packet, validate
from teate.model import TeateError, snapshot


class AutopilotTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_repair.RepairTests()
        self.fixture.setUp()
        self.f = self.fixture
        self.state = self.f.root/"state"
        self.upstream = {"source":"https://api.github.com/advisories/GHSA-example", "fixed_versions":["1.2.2"], "summary":"Official fix"}

    def tearDown(self):
        self.fixture.tearDown()
        self.fixture.doCleanups()

    def execute(self):
        with (patch("teate.autopilot.intel.advisory", return_value=self.upstream),
              patch("teate.repair.registry", return_value=self.f.metadata),
              patch("teate.repair.backend", side_effect=self.f.backend),
              patch("teate.repair.scan_source", side_effect=self.f.scan),
              patch("teate.autopilot.scan_source", side_effect=self.f.scan)):
            return run(self.f.ledger, self.f.policy, self.state, prepare=True)

    def test_supported_fix_and_missing_test_configuration_need_zero_llm_calls(self):
        result = self.execute()
        self.assertEqual(result["counts"]["candidate_findings"], 1)
        self.assertEqual(result["counts"]["tests_pending"], 1)
        self.assertEqual(result["counts"]["llm_needed"], 0)
        with patch("teate.codex.select") as model:
            dispatch(self.f.ledger, self.f.policy, self.state, result["decisions"], enabled=True)
            model.assert_not_called()
        self.assertEqual(self.f.ledger.findings()[0]["effective_status"], "proposed")

    def test_reuse_rechecks_candidate_without_preparing_or_testing_it_again(self):
        self.execute()
        with patch("teate.autopilot.repair.prepare", side_effect=AssertionError("must reuse")):
            result = self.execute()
        self.assertEqual(result["counts"]["reused_groups"], 1)
        self.assertFalse(result["changed"])

    def test_untracked_candidate_changes_invalidate_reuse(self):
        result = self.execute()
        candidate = Path(result["decisions"][0]["result"]["results"][0]["worktree"])
        (candidate/"new-test-input.js").write_text("changed input")
        self.assertEqual(self.execute()["counts"]["reused_groups"], 0)

    def test_equivalent_findings_share_one_upstream_lookup(self):
        for location in ("a/package-lock.json", "b/package-lock.json"):
            self.f.ledger.ingest(snapshot(self.f.asset["id"], "npm-audit", location, {"type":"source","revision":"test"},
                                          [{**self.f.finding,"location":location}]))
        with patch("teate.autopilot.intel.advisory", return_value=self.upstream) as upstream, patch("teate.repair.registry", return_value=self.f.metadata):
            result = run(self.f.ledger, self.f.policy, self.state)
        self.assertEqual(result["counts"]["groups"], 1)
        self.assertEqual(len(result["decisions"][0]["finding_ids"]), 3)
        self.assertEqual(upstream.call_count, 1)

    def unknown(self):
        return {"case_id":"example", "finding_ids":[self.f.identifier], "needs_llm":True,
                "package":"example", "version":"1.2.1", "advisory_id":"GHSA-example",
                "reason":"no_supported_patch_fix"}

    def test_same_evidence_gets_at_most_one_subscription_attempt(self):
        def respond(p, **kw):
            return {"response_text":json.dumps({"schema_version":1,"evidence_id":p["evidence_id"],
                    "assessment":"insufficient_evidence","explanation":"Review upstream compatibility", "edits":[]}),
                    "called":True, "reason":None}
        decision = self.unknown()
        with patch("teate.codex.select", side_effect=respond) as model:
            first = dispatch(self.f.ledger,self.f.policy,self.state,[decision],enabled=True)
            second = dispatch(self.f.ledger,self.f.policy,self.state,[decision],enabled=True)
        self.assertEqual(first["llm_calls"],1)
        self.assertEqual(second["llm_calls"],0)
        self.assertEqual(model.call_count,1)
        self.assertEqual(self.f.ledger.findings()[0]["effective_status"],"affected")

    def test_model_code_edits_are_validated_but_never_applied(self):
        code = self.f.repo/"example.py"
        code.write_text("value = 1\n")
        asset = {**self.f.asset,"verification":{"context_files":["example.py"]}}
        self.f.ledger.register([asset])
        p, files = packet(self.f.ledger,self.f.policy,self.unknown())
        self.assertLessEqual(len((json.dumps(p,ensure_ascii=False,indent=2)+'\n').encode()),6000)
        response = {"schema_version":1,"evidence_id":p["evidence_id"],"assessment":"code_change",
                    "explanation":"Adjust the known constant", "edits":[{"file_id":"source-0","before":"value = 1","after":"value = 2"}]}
        _, diff = validate(json.dumps(response),p,p,files)
        self.assertIn("+value = 2",diff)
        self.assertEqual(code.read_text(),"value = 1\n")
        for changes in ({"command":"execute"},{"facts":{"open":0}},{"evidence_id":"old"}):
            with self.subTest(changes=changes), self.assertRaises(TeateError):
                validate(json.dumps({**response,**changes}),p,p,files)
        code.write_text("changed since request\n")
        with self.assertRaises(TeateError):
            validate(json.dumps(response),p,p,files)

    def test_default_dispatch_only_writes_a_bounded_context(self):
        with patch("teate.codex.select") as model:
            result = dispatch(self.f.ledger,self.f.policy,self.state,[self.unknown()])
        model.assert_not_called()
        self.assertEqual(result["status"],"awaiting_opt_in")

    def test_private_key_context_is_never_submitted_to_a_model(self):
        code = self.f.repo/"example.py"
        code.write_text('credentials = {"refresh_token": "synthetic"}\n')
        self.f.ledger.register([{**self.f.asset,"verification":{"context_files":["example.py"]}}])
        with patch("teate.codex.select") as model:
            result = dispatch(self.f.ledger,self.f.policy,self.state,[self.unknown()],enabled=True)
        model.assert_not_called()
        self.assertEqual(result["status"],"context_requires_review")


if __name__ == "__main__":
    unittest.main()
