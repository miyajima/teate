import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from teate.model import TeateError
from teate.verification import relative, verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "test.py").write_text('print("ok")')
        self.record = {"worktree": str(self.root), "changed_files": ["package-lock.json"]}
        self.asset = {"verification": {"commands": [{"argv": ["python3", "test.py"]}]}}

    def tearDown(self):
        self.temp.cleanup()

    def test_no_configuration_never_executes(self):
        with patch("teate.verification.sandbox.execute") as execute:
            self.assertEqual(verify({}, self.record)["status"], "unconfigured")
            execute.assert_not_called()

    def test_tests_are_offline_and_dependency_preparation_is_separate(self):
        self.asset["verification"]["install_dependencies"] = True
        with patch(
            "teate.verification.sandbox.execute", return_value={"status": "passed"}
        ) as execute:
            self.assertEqual(verify(self.asset, self.record)["status"], "passed")
        self.assertEqual([c.kwargs["network"] for c in execute.call_args_list], ["npm", "offline"])
        self.assertIn("--ignore-scripts", execute.call_args_list[0].args[1])

    def test_missing_sandbox_never_retries_without_one(self):
        with patch(
            "teate.verification.sandbox.execute", return_value={"status": "blocked"}
        ) as execute:
            self.assertEqual(verify(self.asset, self.record)["status"], "blocked")
            self.assertEqual(execute.call_count, 1)

    def test_tests_cannot_change_manifest_or_candidate(self):
        def execute(*args, **kwargs):
            (self.root / "test.py").write_text("modified")
            return {"status": "passed"}

        with patch("teate.verification.sandbox.execute", side_effect=execute):
            self.assertEqual(verify(self.asset, self.record)["reason"], "tests_modified_candidate")
        for name in ("../file", "/tmp/file", ".git/config"):
            with self.assertRaises(TeateError):
                relative(self.root, name)

    def test_sandbox_profile_does_not_grant_host_home_or_credentials(self):
        from teate.sandbox import execute

        def start(command, **kwargs):
            profile = json.loads(Path(command[command.index("--settings") + 1]).read_text())
            self.assertEqual(profile["filesystem"]["denyRead"], ["/"])
            self.assertEqual(profile["network"]["allowedDomains"], [])
            self.assertNotIn("OPENAI_API_KEY", kwargs["env"])
            self.assertEqual(command[-2:], ["python3", "test.py"]) if command[
                -2
            ] == "python3" else None

            return {"raw": b"", "exit_code": 0, "timed_out": False, "output_limited": False}

        with (
            patch("teate.sandbox.shutil.which", side_effect=lambda v: "/usr/bin/" + v),
            patch("teate.sandbox.capture", side_effect=start),
        ):
            self.assertEqual(execute(self.root, ["python3", "test.py"])["status"], "passed")


class PrivateCandidateChangeTests(unittest.TestCase):
    def test_tests_cannot_hide_changes_in_npm_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def run(*args, **kwargs):
                (root / ".npmrc").write_text("omit=dev\n")
                return {"status": "passed"}

            with patch("teate.verification.sandbox.execute", side_effect=run):
                result = verify(
                    {"verification": {"commands": [{"argv": ["npm", "test"]}]}},
                    {"worktree": str(root)},
                )
            self.assertEqual(result["reason"], "tests_modified_candidate")
