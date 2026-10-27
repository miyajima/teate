import base64
import json
import unittest
from unittest.mock import patch

from teate.github import _manifest_sensitive, inspect_patch_pr, repository_name
from teate.model import TeateError


class GitHubGateTests(unittest.TestCase):
    def test_repository_validation_prevents_option_or_url_injection(self):
        for invalid in ["--flag", "https://github.com/a/b", "a/b/extra", "a/b?ref=x", "a/b\n"]:
            with self.subTest(invalid=invalid), self.assertRaises(TeateError):
                repository_name(invalid)

    def test_manifest_scripts_and_dependency_additions_require_review(self):
        base = {"dependencies": {"a": "1.0.0"}, "scripts": {"test": "test"}}
        self.assertFalse(_manifest_sensitive(base, {**base, "dependencies": {"a": "1.0.1"}}))
        self.assertTrue(_manifest_sensitive(base, {**base, "scripts": {"test": "echo passed"}}))
        self.assertTrue(
            _manifest_sensitive(base, {**base, "dependencies": {"a": "1.0.1", "b": "1.0.0"}})
        )

    def fixture(self, sensitive=False, manifest_extra=False):
        base, head = "a" * 40, "b" * 40
        old = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/example": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                    "integrity": "old",
                },
            },
        }
        new = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/example": {
                    "version": "1.0.1",
                    "resolved": "https://registry.npmjs.org/example/-/example-1.0.1.tgz",
                    "integrity": "new",
                },
            },
        }
        if sensitive:
            new["packages"]["node_modules/example"]["hasInstallScript"] = True
        files = [{"filename": "package-lock.json", "status": "modified"}]
        if manifest_extra:
            files.append({"filename": "package.json", "status": "modified"})

        def api(endpoint, **kwargs):
            if endpoint == "repos/owner/repo/pulls/1":
                return {
                    "state": "open",
                    "draft": False,
                    "changed_files": len(files),
                    "user": {"login": "renovate[bot]"},
                    "head": {"sha": head, "repo": {"full_name": "owner/repo"}},
                    "base": {"sha": base, "ref": "main", "repo": {"full_name": "owner/repo"}},
                }
            if "/files?" in endpoint:
                return files
            if "/contents/" in endpoint:
                value = old if "ref=" + base in endpoint else new
                if "/package.json?" in endpoint:
                    version = "1.0.0" if "ref=" + base in endpoint else "9.0.0"
                    value = {"dependencies": {"unapproved": version}}
                return {
                    "type": "file",
                    "encoding": "base64",
                    "content": base64.b64encode(json.dumps(value).encode()).decode(),
                }
            if "/check-runs?" in endpoint:
                return {
                    "total_count": 1,
                    "check_runs": [
                        {
                            "name": "test",
                            "head_sha": head,
                            "conclusion": "success",
                            "app": {"slug": "github-actions"},
                        }
                    ],
                }
            raise AssertionError(endpoint)

        return api

    @patch("teate.github._npm_publication_time", return_value="2026-01-01T00:00:00Z")
    def test_verified_patch_can_pass_and_does_not_execute_pr_code(self, publication):
        with patch("teate.github.api", side_effect=self.fixture()):
            _, decision = inspect_patch_pr(
                "owner/repo",
                1,
                {
                    "automation": {
                        "enabled": True,
                        "allowed_packages": ["example"],
                        "required_checks": ["test"],
                    }
                },
            )
        self.assertEqual(decision["action"], "auto_merge")

    @patch("teate.github._npm_publication_time", return_value="2026-01-01T00:00:00Z")
    def test_lifecycle_metadata_change_cannot_automerge(self, publication):
        with patch("teate.github.api", side_effect=self.fixture(sensitive=True)):
            _, decision = inspect_patch_pr(
                "owner/repo",
                1,
                {
                    "automation": {
                        "enabled": True,
                        "allowed_packages": ["example"],
                        "required_checks": ["test"],
                    }
                },
            )
        self.assertEqual(decision["action"], "review")

    @patch("teate.github._npm_publication_time", return_value="2026-01-01T00:00:00Z")
    def test_unapproved_manifest_update_cannot_hide_behind_allowed_lockfile_change(
        self, publication
    ):
        with patch("teate.github.api", side_effect=self.fixture(manifest_extra=True)):
            _, decision = inspect_patch_pr(
                "owner/repo",
                1,
                {
                    "automation": {
                        "enabled": True,
                        "allowed_packages": ["example"],
                        "required_checks": ["test"],
                    }
                },
            )
        self.assertEqual(decision["action"], "review")


if __name__ == "__main__":
    unittest.main()
