import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import install_skill


class SkillInstallTests(unittest.TestCase):
    def test_copies_only_the_public_bundle_and_reuses_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            destination = root / ".agents/skills/teate"
            self.assertEqual(install_skill.install(install_skill.SOURCE, destination), "Installed")
            actual = {str(p.relative_to(destination)).replace(os.sep, "/")
                      for p in destination.rglob("*") if p.is_file()}
            self.assertEqual(actual, set(install_skill.FILES))
            self.assertEqual(install_skill.install(install_skill.SOURCE, destination), "Already installed")
            self.assertEqual(install_skill.install(destination, destination), "Already installed")

    def test_different_skill_and_unknown_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary).resolve() / "teate"
            install_skill.install(install_skill.SOURCE, destination)
            original = destination / "SKILL.md"
            original.write_text("my custom skill", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different contents"):
                install_skill.install(install_skill.SOURCE, destination)
            self.assertEqual(original.read_text(encoding="utf-8"), "my custom skill")
            original.write_bytes((install_skill.SOURCE / "SKILL.md").read_bytes())
            extra = destination / "private.txt"
            extra.write_text("operator data", encoding="utf-8")
            read = Path.read_bytes

            def refuse_unknown_read(path):
                if path == extra:
                    self.fail("Installer must not read unknown files")
                return read(path)

            with patch.object(Path, "read_bytes", refuse_unknown_read):
                with self.assertRaises(ValueError):
                    install_skill.install(install_skill.SOURCE, destination)
            self.assertEqual(extra.read_text(encoding="utf-8"), "operator data")

    def test_dry_run_does_not_create_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            destination = root / "not-created/.agents/skills/teate"
            self.assertEqual(install_skill.install(install_skill.SOURCE, destination, dry_run=True), "Would install")
            self.assertEqual(list(root.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support")
    def test_rejects_destination_symlinks_without_touching_the_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            actual = root / "actual"
            actual.mkdir()
            (root / ".agents").symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                install_skill.install(install_skill.SOURCE, root / ".agents/skills/teate")
            self.assertEqual(list(actual.iterdir()), [])

    def test_cli_installs_only_in_the_selected_project(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(install_skill.main(["--project", str(root)]), 0)
            self.assertTrue((root / ".agents/skills/teate/SKILL.md").is_file())
            with self.assertRaises(ValueError):
                install_skill.main(["--project", str(root / "missing")])


if __name__ == "__main__":
    unittest.main()
