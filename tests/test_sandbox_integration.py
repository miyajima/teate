"""Real sandbox probes, optional on hosts that can provide an OS sandbox."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from teate.sandbox import execute


@unittest.skipUnless(
    os.environ.get("TEATE_SANDBOX_INTEGRATION") == "1", "opt-in real OS sandbox probes"
)
class SandboxIntegrationTests(unittest.TestCase):
    def test_real_boundary_hides_secrets_and_blocks_writes_and_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root / "candidate"
            candidate.mkdir()
            secret = root / "secret"
            secret.write_text("synthetic host secret")
            forbidden = root / "forbidden"
            script = candidate / "probe.py"
            script.write_text("""import json, pathlib, socket, sys
result = {}
try:
 pathlib.Path(sys.argv[1]).read_text()
 result['secret'] = 'readable'
except OSError: result['secret'] = 'denied'
try:
 pathlib.Path(sys.argv[2]).write_text('unexpected')
 result['write'] = 'allowed'
except OSError: result['write'] = 'denied'
try:
 socket.create_connection(('example.com',443),timeout=2)
 result['network'] = 'allowed'
except OSError: result['network'] = 'denied'
print(json.dumps(result))
""")
            import sys

            result = execute(
                candidate, [sys.executable, str(script), str(secret), str(forbidden)], timeout=15
            )
            if result["status"] == "blocked":
                self.skipTest(
                    "Host cannot start an OS sandbox: "
                    + result.get("reason", "namespace unavailable")
                )
            self.assertEqual(result["status"], "passed", result)
            evidence = json.loads(result["excerpt"].splitlines()[-1])
            self.assertEqual(evidence, {"secret": "denied", "write": "denied", "network": "denied"})
            self.assertFalse(forbidden.exists())
