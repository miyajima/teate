import copy
import unittest
from datetime import UTC, datetime, timedelta

from teate.mac import in_window
from teate.policy import is_patch_update, merge_decision, plan, priority


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "automation": {
                "enabled": True,
                "allowed_packages": ["example"],
                "required_checks": ["test", "security"],
                "minimum_release_age_hours": 48,
            }
        }
        self.update = {
            "author": "renovate[bot]",
            "packages": [{"name": "example", "from": "1.2.3", "to": "1.2.4"}],
            "sensitive_change": False,
            "head_sha": "abc",
            "checks": [
                {"name": "test", "head_sha": "abc", "conclusion": "success"},
                {"name": "security", "head_sha": "abc", "conclusion": "success"},
            ],
            "published_at": (datetime.now(UTC) - timedelta(days=5)).isoformat(),
        }

    def test_only_allowed_stable_patch_is_automatic(self):
        self.assertEqual(merge_decision(self.update, self.policy)["action"], "auto_merge")
        for target in ["1.3.0", "2.0.0", "1.2.5-rc.1", "1.2.2", "^1.2.4", "1.2", "01.2.4"]:
            with self.subTest(target=target):
                self.assertFalse(is_patch_update("1.2.3", target))

    def test_fail_closed_matrix(self):
        variants = [
            {"author": "someone"},
            {"sensitive_change": True},
            {"packages": []},
            {"packages": [{"name": "unapproved", "from": "1.2.3", "to": "1.2.4"}]},
            {"head_sha": "new-commit"},
            {"checks": []},
            {"published_at": None},
            {"published_at": datetime.now(UTC).isoformat()},
        ]
        for change in variants:
            with self.subTest(change=change):
                self.assertEqual(
                    merge_decision({**self.update, **change}, self.policy)["action"], "review"
                )

    def test_disabled_and_missing_required_checks_never_automerge(self):
        self.assertEqual(merge_decision(self.update, {})["action"], "review")
        policy = copy.deepcopy(self.policy)
        policy["automation"]["required_checks"] = []
        self.assertEqual(merge_decision(self.update, policy)["action"], "review")

    def test_emergency_cannot_bypass_checks(self):
        policy = copy.deepcopy(self.policy)
        policy["automation"]["allow_emergency_fast_track"] = True
        update = {**self.update, "emergency": True, "checks": []}
        self.assertEqual(merge_decision(update, policy)["action"], "review")

    def test_prepared_candidates_are_reported_as_review_without_inventing_a_fix(self):
        finding = {"id": "f", "asset_id": "a", "effective_status": "proposed",
                   "first_seen": datetime.now(UTC).isoformat(), "package": "example",
                   "version": "1.2.1", "advisory_id": "GHSA-test", "fixed_versions": []}
        asset = {"id": "a", "project": "example", "environment": "development"}
        action = plan([finding], [asset], {})[0]
        self.assertEqual(action["action"], "review_prepared_candidate")
        self.assertEqual(action["fixed_versions"], [])

    def test_kev_prioritizes_even_low_cvss(self):
        self.assertEqual(priority({"severity": "LOW", "kev": True}, {}), "urgent")
        self.assertEqual(priority({"severity": "CRITICAL"}, {"exposure": "public"}), "urgent")

    def test_maintenance_window_crosses_midnight(self):
        window = {"timezone": "Asia/Tokyo", "start": "23:00", "end": "02:00"}
        at = datetime(2026, 10, 25, 16, 0, tzinfo=UTC)  # 01:00 JST
        self.assertTrue(in_window(window, at))
        self.assertFalse(in_window(window, at + timedelta(hours=3)))
        self.assertFalse(in_window({}))


if __name__ == "__main__":
    unittest.main()
