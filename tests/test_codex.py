import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from teate.codex import select, status


class CodexTests(unittest.TestCase):
    def setUp(self):
        self.packet = {
            "schema_version": 1, "brief_id": "current", "generated_at": "2026-10-26T00:00:00Z",
            "response_schema": {"type": "object"}, "items": [],
        }

    @patch("teate.codex.shutil.which", return_value="codex")
    @patch("teate.codex.subprocess.run")
    def test_api_auth_is_rejected_without_disclosing_diagnostics(self, run, which):
        run.return_value = subprocess.CompletedProcess([], 0, "Logged in using an API key: SECRET", "")
        result = status()
        self.assertFalse(result["ready"])
        self.assertNotIn("SECRET", json.dumps(result))

    @patch("teate.codex.status", return_value={"ready": False, "reason": "chatgpt_login_required"})
    @patch("teate.codex.subprocess.run")
    def test_no_model_call_without_subscription_auth(self, run, auth):
        self.assertIsNone(select(self.packet)["response_text"])
        run.assert_not_called()

    @patch("teate.codex.status", return_value={"ready": True})
    @patch("teate.codex._network_allowed", return_value=False)
    @patch("teate.codex.subprocess.run")
    def test_network_denial_does_not_trigger_a_call_or_retry(self, run, network, auth):
        self.assertEqual(select(self.packet)["reason"], "codex_network_not_allowed")
        run.assert_not_called()

    @patch.dict("os.environ", {"OPENAI_API_KEY": "SECRET", "CODEX_API_KEY": "SECRET",
                               "HTTPS_PROXY": "managed-proxy", "SSL_CERT_FILE": "managed-ca"})
    @patch("teate.codex.status", return_value={"ready": True})
    @patch("teate.codex._network_allowed", return_value=True)
    @patch("teate.codex.subprocess.run")
    def test_subscription_only_single_call_is_read_only_and_bounded(self, run, network, auth):
        def invoke(command, **kw):
            self.assertIn('forced_login_method="chatgpt"', command)
            self.assertIn('model_provider="openai"', command)
            self.assertIn("read-only", command)
            self.assertIn("features.shell_tool=false", command)
            self.assertIn("--ignore-user-config", command)
            self.assertIn("--ephemeral", command)
            self.assertNotIn("OPENAI_API_KEY", kw["env"])
            self.assertNotIn("CODEX_API_KEY", kw["env"])
            self.assertEqual(kw["env"]["HTTPS_PROXY"], "managed-proxy")
            self.assertEqual(kw["env"]["SSL_CERT_FILE"], "managed-ca")
            self.assertNotIn("SECRET", kw["input"])
            self.assertEqual(command[command.index("--model")+1], "selected-model")
            output = Path(command[command.index("--output-last-message")+1])
            output.write_text('{"schema_version":1,"brief_id":"current","focus_ids":[]}')
            return subprocess.CompletedProcess(command, 0)
        run.side_effect = invoke
        result = select(self.packet, model="selected-model", effort="max")
        self.assertEqual(json.loads(result["response_text"])["focus_ids"], [])
        self.assertEqual(run.call_count, 1)

    @patch("teate.codex.status", return_value={"ready": True})
    @patch("teate.codex._network_allowed", return_value=True)
    @patch("teate.codex.subprocess.run", side_effect=subprocess.TimeoutExpired("codex", 90))
    def test_timeout_has_no_retry_or_api_fallback(self, run, network, auth):
        self.assertEqual(select(self.packet)["reason"], "codex_call_unavailable")
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
