import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from teate.model import TeateError
from teate.verification import _command, relative, verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.record = {"worktree":str(self.root)}
        self.asset = {"verification":{"commands":[{"name":"test","argv":["python3","test.py"]}]}}

    def tearDown(self):
        self.temp.cleanup()

    def test_no_configuration_does_not_execute_project_code(self):
        with patch("teate.verification.subprocess.Popen") as process:
            result = verify({}, self.record)
        self.assertEqual(result["status"], "unconfigured")
        process.assert_not_called()

    def test_linux_sandbox_has_no_network_or_host_authentication_mount(self):
        with patch("teate.verification.shutil.which", return_value="/usr/bin/bwrap"):
            command = _command(self.root,self.root,["python3","test.py"])
        self.assertIn("--unshare-all",command)
        self.assertIn("--clearenv",command)
        self.assertNotIn("--share-net",command)
        self.assertEqual(command.count("--bind"),1)
        self.assertEqual(command[command.index("--bind")+1],str(self.root))

    def test_no_sandbox_means_pending_review_and_never_an_unsandboxed_retry(self):
        with patch("teate.verification._git", return_value=""), patch("teate.verification._command",return_value=None), patch("teate.verification.subprocess.Popen") as process:
            result = verify(self.asset,self.record)
        self.assertEqual(result["status"],"blocked")
        process.assert_not_called()

    def test_explicit_command_success_is_local_evidence_not_a_github_check(self):
        def start(command, **kwargs):
            self.assertNotIn("GH_TOKEN",kwargs["env"])
            self.assertNotIn("OPENAI_API_KEY",kwargs["env"])
            kwargs["stdout"].write(b"synthetic local test passed")
            return SimpleNamespace(wait=lambda **kw:0)
        with patch("teate.verification._git",return_value=""), patch("teate.verification._command",return_value=["sandbox","test"]), patch("teate.verification.subprocess.Popen",side_effect=start):
            result = verify(self.asset,self.record)
        self.assertEqual(result["status"],"passed")
        self.assertIn("do not replace",result["note"])

    def test_sandbox_setup_failure_is_not_a_code_failure_or_success(self):
        def start(command,**kwargs):
            kwargs["stdout"].write(b"bwrap: namespace not permitted")
            return SimpleNamespace(wait=lambda **kw:1)
        with patch("teate.verification._git",return_value=""), patch("teate.verification._command",return_value=["sandbox","test"]), patch("teate.verification.subprocess.Popen",side_effect=start):
            result = verify(self.asset,self.record)
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["reason"],"test_sandbox_not_permitted")

    def test_output_cleanup_cannot_revert_the_patch_or_escape_the_worktree(self):
        for name in ("../file","/tmp/file",".git/config"):
            with self.subTest(name=name),self.assertRaises(TeateError):
                relative(self.root,name)
        (self.root/"package-lock.json").write_text("{}")
        asset = {"verification":{**self.asset["verification"],"discard_outputs":["package-lock.json"]}}
        with patch("teate.verification._git",return_value="package-lock.json"),self.assertRaises(TeateError):
            verify(asset,self.record)


if __name__ == "__main__":
    unittest.main()
