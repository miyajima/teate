import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from teate.github import publish_receipt, require_private_repository, sync_issues
from teate.model import TeateError


class EvidencePrivacyTests(unittest.TestCase):
    def test_public_unknown_or_mismatched_destination_is_rejected_before_mutation(self):
        values = [
            {"full_name": "owner/repo", "private": False},
            {"full_name": "owner/repo"},
            {"full_name": "owner/repo", "private": "true"},
            {"full_name": "other/repo", "private": True},
            None,
        ]
        for info in values:
            for operation in (
                lambda: publish_receipt("owner/repo", {"synthetic": "receipt"}),
                lambda: sync_issues(Mock(), "owner/repo", apply=True),
            ):
                with self.subTest(info=info), patch("teate.github.api", return_value=info) as api:
                    with self.assertRaises(TeateError):
                        operation()
                    api.assert_called_once_with("repos/owner/repo")

    def test_visibility_lookup_failure_does_not_send_evidence(self):
        with patch("teate.github.api", side_effect=TeateError("unavailable")) as api:
            with self.assertRaises(TeateError):
                publish_receipt("owner/repo", {"synthetic": "receipt"})
            api.assert_called_once_with("repos/owner/repo")

    def test_explicitly_private_repository_still_accepts_a_receipt(self):
        calls = []

        def api(endpoint, **kw):
            calls.append((endpoint, kw))
            if endpoint == "repos/owner/repo":
                return {"private": True, "full_name": "owner/repo", "default_branch": "main"}
            if "/git/ref/" in endpoint:
                return {"object": {"sha": "a"*40}}
            if "/contents/" in endpoint:
                return None if not kw.get("method") else {"content": {"sha": "b"*40}}
            if endpoint.endswith("/dispatches"):
                return None
            raise AssertionError(endpoint)

        with patch("teate.github.api", side_effect=api):
            result = publish_receipt("owner/repo", {"synthetic": "receipt"})
        self.assertFalse(result["duplicate"])
        self.assertEqual(calls[0], ("repos/owner/repo", {}))
        self.assertEqual([kw["method"] for _, kw in calls if "method" in kw], ["PUT", "POST"])

    def test_private_repository_name_is_checked_case_insensitively(self):
        with patch("teate.github.api", return_value={"private": True, "full_name": "Owner/Repo"}):
            self.assertTrue(require_private_repository("owner/repo")["private"])

    def test_state_transport_rejects_public_repository_before_loading_local_data(self):
        path = Path(__file__).resolve().parents[1]/"scripts"/"ci_state.py"
        spec = importlib.util.spec_from_file_location("teate_ci_state_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for action in ("restore", "receipts", "save"):
            with (
                self.subTest(action=action),
                patch("sys.argv", [str(path), action, "--repository", "owner/repo"]),
                patch("teate.github.api", return_value={"private": False, "full_name": "owner/repo"}) as api,
                patch.object(module, "load_config") as config,
            ):
                with self.assertRaises(TeateError):
                    module.main()
                config.assert_not_called()
                api.assert_called_once_with("repos/owner/repo")


if __name__ == "__main__":
    unittest.main()
