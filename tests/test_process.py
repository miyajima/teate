import sys
import tempfile
import unittest
from pathlib import Path

from teate.process import capture


class CaptureTests(unittest.TestCase):
    def test_output_limit_does_not_limit_artifact_size(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact"
            result = capture(
                [
                    sys.executable,
                    "-c",
                    'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"x"*20000); print("ok")',
                    str(artifact),
                ],
                limit=100,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(artifact.stat().st_size, 20000)
            self.assertEqual(result["raw"], b"ok\n")

    def test_excess_output_is_bounded_and_kills_the_command(self):
        result = capture([sys.executable, "-c", 'print("x"*20000)'], limit=100)
        self.assertTrue(result["output_limited"])
        self.assertEqual(len(result["raw"]), 101)

    def test_timeout_returns_an_uncertain_result(self):
        result = capture([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)
        self.assertTrue(result["timed_out"])
        self.assertNotEqual(result["exit_code"], 0)
