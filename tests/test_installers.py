import hashlib
import io
import os
import subprocess
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import install_dependencies as installer


class InstallerTests(unittest.TestCase):
    def test_platforms_and_windows_guidance(self):
        for system in ("Linux", "Darwin"):
            for arch in ("x86_64", "aarch64", "arm64"):
                self.assertIn(installer.target(system, arch)[1], ("x64", "arm64"))
        with self.assertRaisesRegex(ValueError, "WSL2"):
            installer.target("Windows", "AMD64")

    def test_checksum_exact_unique_and_valid(self):
        self.assertEqual(installer.checksum("a" * 64 + " ./tool", "tool"), "a" * 64)
        for value in ("bad tool", "a" * 64 + " other", "a" * 64 + " tool\n" + "a" * 64 + " tool"):
            with self.assertRaises(ValueError):
                installer.checksum(value, "tool")

    def test_bad_digest_is_rejected(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                installer, "download", side_effect=lambda url, path: path.write_bytes(b"changed")
            ),
        ):
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                installer.verified(
                    "https://example.org/tool",
                    Path(tmp) / "tool",
                    hashlib.sha256(b"original").hexdigest(),
                )

    def test_non_https_refused_before_request(self):
        with (
            patch.object(installer.urllib.request, "urlopen") as request,
            self.assertRaises(ValueError),
        ):
            installer.download("http://example.org/tool", Path("unused"))
        request.assert_not_called()

    def test_dry_run_has_no_side_effects(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(installer, "ROOT", Path(tmp)),
            patch.object(installer.platform, "system", return_value="Linux"),
            patch.object(installer.platform, "machine", return_value="x86_64"),
            patch.object(installer, "bootstrap") as bootstrap,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(installer.main(["--all", "--dry-run"]), 0)
            bootstrap.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_all_supported_artifacts_have_explicit_https_hashes(self):
        config = tomllib.loads((installer.ROOT / "tools/mise.toml").read_text())
        lock = tomllib.loads((installer.ROOT / "tools/mise.lock").read_text())
        for key, value in config["tools"].items():
            self.assertTrue(key.startswith("http:"))
            for platform in ("linux-x64", "linux-arm64", "macos-x64", "macos-arm64"):
                self.assertTrue(value["platforms"][platform]["url"].startswith("https://"))
                self.assertRegex(value["platforms"][platform]["checksum"], r"^sha256:[a-f0-9]{64}$")
            self.assertEqual(lock["tools"][key][0]["version"], value["version"])

    def test_mise_does_not_inherit_user_plugins_or_auto_update(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(
                os.environ, {"MISE_SELF_UPDATE_AUTO": "1", "MISE_TRUSTED_CONFIG_PATHS": "/"}
            ),
        ):
            env = installer.mise_environment(Path(tmp))
            self.assertEqual(env["MISE_SELF_UPDATE_AUTO"], "0")
            self.assertNotIn("MISE_TRUSTED_CONFIG_PATHS", env)
            self.assertTrue(env["MISE_DATA_DIR"].startswith(tmp))

    @unittest.skipUnless(os.name == "posix", "POSIX links")
    def test_different_unmanaged_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tool").write_text("binary")
            (root / "operator").write_text("operator")
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                installer.link(root / "tool", root / "operator")
            self.assertEqual((root / "operator").read_text(), "operator")

    @unittest.skipUnless(os.name == "posix", "bash")
    def test_shell_dry_run(self):
        result = subprocess.run(
            ["bash", str(installer.ROOT / "scripts/install.sh"), "--all", "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Dry run only", result.stdout)
