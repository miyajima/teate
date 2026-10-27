import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import install_dependencies as installer


class InstallerTests(unittest.TestCase):
    def test_platforms_and_windows_guidance(self):
        for system in ["Linux", "Darwin"]:
            for arch in ["x86_64", "aarch64", "arm64"]:
                self.assertIn(installer.target(system, arch)[1], ["amd64", "arm64"])
        for platform in [("Windows", "AMD64"), ("Linux", "i686")]:
            with self.assertRaisesRegex(ValueError, "WSL2"):
                installer.target(*platform)

    def test_manifest_requires_exact_unique_valid_entry(self):
        value = "a" * 64
        self.assertEqual(installer.checksum(f"{value}  *tool\n", "tool"), value)
        for manifest in [f"{value} tool.zip", f"{value} tool\n{value} tool", "bad tool"]:
            with self.assertRaises(ValueError):
                installer.checksum(manifest, "tool")

    def test_bad_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "download"
            with patch.object(installer, "download", side_effect=lambda url, path: path.write_bytes(b"changed")):
                with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                    installer.verified("https://example.org/tool", output, hashlib.sha256(b"original").hexdigest())

    def test_non_https_refused_before_request(self):
        with patch.object(installer.urllib.request, "urlopen") as request:
            with self.assertRaises(ValueError):
                installer.download("http://example.org/tool", Path("unused"))
            request.assert_not_called()

    def test_dry_run_does_not_write_download_or_execute(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (patch.object(installer, "ROOT", root),
                  patch.object(installer.platform, "system", return_value="Linux"),
                  patch.object(installer.platform, "machine", return_value="x86_64"),
                  patch.object(installer, "download") as download,
                  patch.object(installer.subprocess, "run") as run,
                  redirect_stdout(io.StringIO())):
                self.assertEqual(installer.main(["--all", "--dry-run"]), 0)
            self.assertEqual(list(root.iterdir()), [])
            download.assert_not_called()
            run.assert_not_called()

    def test_all_platform_plans_select_official_archives(self):
        for system in ["Linux", "Darwin"]:
            for arch in ["x86_64", "arm64"]:
                with tempfile.TemporaryDirectory() as temporary:
                    with (patch.object(installer, "ROOT", Path(temporary)),
                          patch.object(installer.platform, "system", return_value=system),
                          patch.object(installer.platform, "machine", return_value=arch),
                          patch.object(installer.shutil, "which", return_value="git"),
                          patch.object(installer, "install_tool") as install,
                          patch.object(installer, "link"),
                          patch.object(installer, "version_matches", return_value=True),
                          patch.dict(os.environ), redirect_stdout(io.StringIO())):
                        self.assertEqual(installer.main(["--all"]), 0)
                    calls = {call.args[0]: call for call in install.call_args_list}
                    self.assertEqual(set(calls), {"osv-scanner", "node", "trivy", "gh", "gcloud"})
                    suffix = ".zip" if system == "Darwin" else ".tar.gz"
                    self.assertTrue(calls["gh"].args[2].endswith(suffix))
                    self.assertEqual(calls["gcloud"].args[1], installer.GCLOUD_VERSION)
                    self.assertIn(installer.GCLOUD_VERSION, calls["gcloud"].args[2])
                    self.assertEqual(len(calls["gcloud"].kwargs["expected"]), 64)
                    self.assertTrue(all(call.args[2].startswith("https://") for call in calls.values()))

    def test_safe_zip_and_rejected_zip_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, name in enumerate(["bin/tool", "../escape", "/absolute", "bin\\escape"]):
                archive = root / f"{index}.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(name, b"tool")
                output = root / str(index)
                if index == 0:
                    installer.extract(archive, output)
                    self.assertEqual((output / name).read_bytes(), b"tool")
                else:
                    with self.assertRaises(ValueError):
                        installer.extract(archive, output)
                    self.assertFalse(output.exists())

    def test_tar_rejects_paths_nodes_and_writes_through_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, kind in enumerate(["escape", "absolute", "fifo", "link-write"]):
                archive = root / f"{index}.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    if kind == "link-write":
                        link = tarfile.TarInfo("link")
                        link.type, link.linkname = tarfile.SYMTYPE, "bin"
                        bundle.addfile(link)
                    member = tarfile.TarInfo({"escape": "../escape", "absolute": "/absolute",
                                              "fifo": "pipe", "link-write": "link/tool"}[kind])
                    if kind == "fifo":
                        member.type = tarfile.FIFOTYPE
                    bundle.addfile(member)
                with self.assertRaises(ValueError):
                    installer.extract(archive, root / str(index))
                self.assertFalse((root / str(index)).exists())

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support")
    def test_safe_relative_symlink_and_escape_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, target in enumerate(["../lib/tool", "../../escape"]):
                archive = root / f"{index}.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    file = tarfile.TarInfo("lib/tool")
                    file.size, file.mode = 4, 0o755
                    bundle.addfile(file, io.BytesIO(b"tool"))
                    link = tarfile.TarInfo("bin/tool")
                    link.type, link.linkname = tarfile.SYMTYPE, target
                    bundle.addfile(link)
                if index == 0:
                    installer.extract(archive, root / str(index))
                    self.assertEqual((root / str(index) / "bin/tool").read_bytes(), b"tool")
                else:
                    with self.assertRaisesRegex(ValueError, "escapes"):
                        installer.extract(archive, root / str(index))

    @unittest.skipUnless(os.name == "posix", "POSIX executable support")
    def test_raw_install_reuse_and_unmanaged_file_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bins, tools = root / "bin", root / "tools"
            bins.mkdir()
            tools.mkdir()
            args = ("tool", "1.0.0", "https://example.org/tool", None, "tool", bins, tools)
            with (patch.object(installer, "verified", side_effect=lambda url, path, expected: path.write_bytes(b"binary")) as download,
                  patch.object(installer, "version_matches", return_value=True), redirect_stdout(io.StringIO())):
                installer.install_tool(*args, expected="a" * 64, raw=True)
                installer.install_tool(*args, expected="a" * 64, raw=True)
                self.assertEqual(download.call_count, 1)
            (bins / "tool").unlink()
            (bins / "tool").write_text("operator file")
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                installer.link(tools / "tool-1.0.0/tool", bins / "tool")
            self.assertEqual((bins / "tool").read_text(), "operator file")
            (bins / "tool").write_bytes((tools / "tool-1.0.0/tool").read_bytes())
            installer.link(tools / "tool-1.0.0/tool", bins / "tool")
            self.assertTrue((bins / "tool").is_symlink())

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support")
    def test_archive_directory_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "sdk.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                file = tarfile.TarInfo("sdk/lib/tool")
                file.size = 4
                bundle.addfile(file, io.BytesIO(b"tool"))
                link = tarfile.TarInfo("sdk/lib64")
                link.type, link.linkname = tarfile.SYMTYPE, "lib"
                bundle.addfile(link)
            installer.extract(archive, root / "output")
            self.assertEqual((root / "output/sdk/lib64/tool").read_bytes(), b"tool")

    @unittest.skipUnless(os.name == "posix", "bash wrapper")
    def test_shell_dry_run_and_invalid_options(self):
        script = Path(__file__).resolve().parents[1] / "scripts/install.sh"
        result = subprocess.run(["bash", str(script), "--all", "--dry-run"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Dry run only", result.stdout)
        result = subprocess.run(["bash", str(script), "--typo"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
