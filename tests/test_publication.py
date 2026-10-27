import base64
import unittest
from unittest.mock import patch

import test_repair

from teate.model import TeateError
from teate.publication import gate, reconcile


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.f = test_repair.RepairTests()
        self.f.setUp()
        record = self.f.execute()["results"][0]
        self.run = {"id": "a" * 32, "record": record}
        self.asset = {**self.f.asset, "remediation": {"repository": "owner/project"}}
        self.sha = "b" * 40
        self.base = record["original_subject"]["revision"]
        self.extra = False
        self.tamper = False

    def tearDown(self):
        self.f.tearDown()

    def api(self, endpoint, **kwargs):
        if "/git/ref/" in endpoint:
            return {"object": {"sha": self.sha}}
        if "/git/commits/" in endpoint:
            return {"parents": [{"sha": self.base}]}
        if "/compare/" in endpoint:
            return {
                "total_commits": 1,
                "files": [
                    {"filename": p}
                    for p in ["package-lock.json", *(["evil.js"] if self.extra else [])]
                ],
            }
        if "/contents/" in endpoint:
            from pathlib import Path

            raw = (Path(self.run["record"]["worktree"]) / "package-lock.json").read_bytes()
            return {"content": base64.b64encode(b"tampered" if self.tamper else raw).decode()}
        raise AssertionError(endpoint)

    def test_reconciliation_requires_exact_commit_diff_and_content(self):
        with (
            patch("teate.publication.api", side_effect=self.api),
            patch(
                "teate.publication.pages",
                return_value=[{"number": 1, "html_url": "https://github.com/owner/project/pull/1"}],
            ),
        ):
            self.assertEqual(reconcile(self.run, self.asset)["head_sha"], self.sha)
            self.extra = True
            with self.assertRaises(TeateError):
                reconcile(self.run, self.asset)
            self.extra = False
            self.tamper = True
            with self.assertRaises(TeateError):
                reconcile(self.run, self.asset)

    def test_changed_head_never_uses_old_ci(self):
        with (
            patch("teate.publication.api", return_value={"head": {"sha": "c" * 40}}),
            patch("teate.publication.inspect_patch_pr") as inspect,
        ):
            with self.assertRaises(TeateError):
                gate({"repository": "owner/project", "pr": 1, "head_sha": self.sha}, {})
            inspect.assert_not_called()

    def test_ci_and_merge_request_do_not_claim_deployment(self):
        with (
            patch(
                "teate.publication.api", return_value={"head": {"sha": self.sha}, "merged": False}
            ),
            patch(
                "teate.publication.inspect_patch_pr",
                return_value=(
                    {"head_sha": self.sha},
                    {"action": "review", "reasons": ["CI pending"]},
                ),
            ),
        ):
            result = gate({"repository": "owner/project", "pr": 1, "head_sha": self.sha}, {})
            self.assertFalse(result["merged"])
            self.assertEqual(result["decision"]["action"], "review")


class MergedCommitGateTests(unittest.TestCase):
    def test_manual_merge_does_not_bypass_commit_specific_checks(self):
        publication = {"repository": "owner/project", "pr": 1, "head_sha": "b" * 40}
        pr = {
            "head": {"sha": "b" * 40},
            "merged": True,
            "merge_commit_sha": "c" * 40,
            "user": {"login": "teate-bot"},
        }
        policy = {"automation": {"required_checks": ["test"], "trusted_bots": ["teate-bot"]}}

        def response(sha):
            return {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "test",
                        "head_sha": sha,
                        "conclusion": "success",
                        "app": {"slug": "github-actions"},
                    }
                ],
            }

        for sha, accepted in [("a" * 40, False), ("b" * 40, True)]:
            with patch("teate.publication.api", side_effect=[pr, response(sha)]):
                if accepted:
                    self.assertTrue(gate(publication, policy)["merged"])
                else:
                    with self.assertRaises(TeateError):
                        gate(publication, policy)
