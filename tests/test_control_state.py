import gzip
import json
import tempfile
import unittest
from pathlib import Path

from teate.control_state import export, restore
from teate.model import TeateError


class ControlStateTests(unittest.TestCase):
    def test_feed_and_attempt_receipts_survive_restart_without_source_or_auth_files(self):
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp)/"first", Path(temp)/"second"
            attempt = first/"autopilot/investigations"/('a'*64)/"attempt.json"
            attempt.parent.mkdir(parents=True)
            attempt.write_text('{"status":"already_attempted"}')
            (first/"auth.json").write_text('{"synthetic":"do not transfer"}')
            (attempt.parent/"packet.json").write_text('{"private_code":"do not transfer"}')
            restore(second,export(first))
            self.assertTrue((second/attempt.relative_to(first)).is_file())
            self.assertFalse((second/"auth.json").exists())
            self.assertFalse((second/attempt.parent.relative_to(first)/"packet.json").exists())

    def test_untrusted_control_manifest_cannot_write_outside_the_private_state(self):
        with tempfile.TemporaryDirectory() as temp:
            for name in ("../outside.json", "autopilot/../../outside.json", "config/local.json", "/tmp/other.json"):
                raw = gzip.compress(json.dumps({name:{}}).encode())
                with self.subTest(name=name),self.assertRaises(TeateError):
                    restore(Path(temp),raw)


if __name__ == "__main__":
    unittest.main()
