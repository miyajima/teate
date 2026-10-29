import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from teate.model import TeateError, snapshot
from teate.repair import _lock, prepare, validate_lock
from teate.store import Ledger


class RepairTests(unittest.TestCase):
    def setUp(self):
        git_env = patch.dict(
            os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        )
        git_env.start()
        self.addCleanup(git_env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.old = {
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"devDependencies": {"example": "^1.2.1"}},
                "node_modules/example": {
                    "version": "1.2.1",
                    "license": "MIT",
                    "engines": {"node": ">=0.10"},
                    "resolved": "https://registry.npmjs.org/example/-/example-1.2.1.tgz",
                    "integrity": "sha512-old",
                },
            },
        }
        (self.repo / "package-lock.json").write_text(json.dumps(self.old, indent=2) + "\n")
        (self.repo / "package.json").write_text(
            json.dumps({"devDependencies": {"example": "^1.2.1"}})
        )
        self.git("init", "-q")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "Initial",
        )
        self.asset = {
            "id": "demo",
            "project": "demo",
            "kind": "source",
            "environment": "test",
            "path": str(self.repo),
        }
        self.ledger = Ledger(self.root / "ledger.sqlite3")
        self.ledger.register([self.asset])
        self.finding = {
            "advisory_id": "GHSA-example",
            "package": "example",
            "version": "1.2.1",
            "ecosystem": "npm",
            "severity": "HIGH",
            "location": "package-lock.json",
        }
        self.ledger.ingest(
            snapshot(
                "demo",
                "npm-audit",
                "package-lock.json",
                {"type": "source", "revision": "initial"},
                [self.finding],
            )
        )
        self.identifier = self.ledger.findings()[0]["id"]
        self.metadata = {
            "version": {
                "name": "example",
                "version": "1.2.2",
                "license": "MIT",
                "engines": {"node": ">=0.10"},
                "dist": {
                    "tarball": "https://registry.npmjs.org/example/-/example-1.2.2.tgz",
                    "integrity": "sha512-" + "A" * 86 + "==",
                },
            },
            "published_at": "2026-09-30T00:00:00Z",
        }
        self.policy = {
            "automation": {
                "enabled": True,
                "allowed_packages": [],
                "required_checks": ["test", "security"],
            }
        }

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()
        self.doCleanups()

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(self.repo), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def fixed(self):
        new = copy.deepcopy(self.old)
        new["packages"]["node_modules/example"].update(
            version="1.2.2",
            resolved=self.metadata["version"]["dist"]["tarball"],
            integrity=self.metadata["version"]["dist"]["integrity"],
        )
        return new

    def backend(self, root, location, selected, scanner):
        (root / location).write_text(json.dumps(self.fixed(), indent=2) + "\n")
        return {"status": "passed", "exit_code": 0}

    def scan(self, asset, **kwargs):
        data = json.loads((Path(asset["path"]) / "package-lock.json").read_text())
        vulnerable = data["packages"]["node_modules/example"]["version"] == "1.2.1"
        return [
            snapshot(
                asset["id"],
                kwargs.get("scanner", "npm-audit"),
                "package-lock.json",
                {"type": "source", "revision": "test"},
                [self.finding] if vulnerable else [],
            )
        ]

    def execute(self, scanner=None):
        with (
            patch("teate.repair.registry", return_value=self.metadata),
            patch("teate.repair.scan_source", side_effect=scanner or self.scan),
            patch("teate.repair.backend", side_effect=self.backend),
        ):
            return prepare(
                self.ledger, self.policy, self.root / "state", [self.identifier], "1.2.2"
            )

    def test_preparation_keeps_source_and_resolution_unchanged(self):
        before = (self.repo / "package-lock.json").read_bytes()
        record = self.execute()["results"][0]
        self.assertEqual(record["status"], "candidate_ready", record)
        self.assertEqual((self.repo / "package-lock.json").read_bytes(), before)
        self.assertEqual(self.ledger.findings()[0]["effective_status"], "proposed")
        self.assertFalse(record["live_applied"])
        self.assertFalse(record["resolved"])
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertFalse((Path(record["worktree"]) / ".git").exists())

    def test_plain_directory_does_not_require_git(self):
        import shutil

        shutil.rmtree(self.repo / ".git")
        with patch("teate.collect.shutil.which", return_value=None):
            self.assertEqual(self.execute()["results"][0]["status"], "candidate_ready")

    def test_candidate_presence_and_new_advisories_are_rejected(self):
        for advisory, reason in [
            ("GHSA-example", "did not remove"),
            ("GHSA-new", "additional findings"),
        ]:

            def scan(asset, **kw):
                scans = self.scan(asset, **kw)
                if asset["path"] != str(self.repo):
                    scans[0]["findings"] = [{**self.finding, "advisory_id": advisory}]
                return scans

            self.assertIn(reason, self.execute(scan)["results"][0]["reason"])

    def test_incomplete_scan_is_never_clean(self):
        def scan(asset, **kw):
            scans = self.scan(asset, **kw)
            if asset["path"] != str(self.repo):
                scans[0].update(status="error", complete=False, findings=[])
            return scans

        self.assertIn("could not be verified", self.execute(scan)["results"][0]["reason"])

    def test_source_change_and_dirty_checkout_are_rejected(self):
        (self.repo / "package.json").write_text("{}")
        self.assertIn("local changes", self.execute()["results"][0]["reason"])

    def test_graph_metadata_and_major_minor_changes_are_rejected(self):
        for mutation in ("graph", "minor", "unselected", "metadata", "integrity"):
            new = self.fixed()
            if mutation == "graph":
                new["packages"]["node_modules/new"] = {"version": "1.0.0"}
            if mutation == "minor":
                new["packages"]["node_modules/example"]["version"] = "1.3.0"
            if mutation == "unselected":
                new["packages"][""]["changed"] = True
            if mutation == "metadata":
                new["packages"]["node_modules/example"]["bin"] = {"run": "run.js"}
            if mutation == "integrity":
                new["packages"]["node_modules/example"]["integrity"] = "tampered"
            with self.subTest(mutation=mutation), self.assertRaises(TeateError):
                validate_lock(self.old, new, [self.finding], "1.2.2", {"example": self.metadata})

    def test_lifecycle_requires_review_even_when_ignored_by_installer(self):
        meta = copy.deepcopy(self.metadata)
        meta["version"]["scripts"] = {"install": "untrusted"}
        with self.assertRaises(TeateError):
            validate_lock(self.old, self.fixed(), [self.finding], "1.2.2", {"example": meta})

    def test_backend_has_no_fallback_and_never_runs_force_or_scripts(self):
        from teate.repair import backend

        for scanner, tool in [("npm-audit", "npm"), ("osv", "osv-scanner")]:
            with patch(
                "teate.repair.sandbox.execute", return_value={"status": "passed", "exit_code": 0}
            ) as execute:
                backend(self.repo, "package-lock.json", [self.finding], scanner)
                argv = execute.call_args.args[1]
                self.assertEqual(argv[0], tool)
                self.assertNotIn("--force", argv)
                self.assertNotIn("--non-interactive", argv)
        with (
            patch("teate.repair.sandbox.execute", return_value={"status": "blocked"}) as execute,
            self.assertRaises(TeateError),
        ):
            backend(self.repo, "package-lock.json", [self.finding], "osv")
        self.assertEqual(execute.call_count, 1)

    def test_ids_and_paths_are_bounded(self):
        for ids in ([], [self.identifier] * 2, ["unknown"], [str(n) for n in range(6)]):
            with self.assertRaises(TeateError):
                prepare(self.ledger, self.policy, self.root / "state", ids, "1.2.2")
        for path in (
            "../package-lock.json",
            "/tmp/package-lock.json",
            "node_modules/a/package-lock.json",
        ):
            with self.assertRaises(TeateError):
                _lock(self.repo, path)

    def test_secret_files_are_not_copied(self):
        (self.repo / ".env").write_text("TOKEN=synthetic")
        self.git("add", ".env")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "secret fixture",
        )
        record = self.execute()["results"][0]
        self.assertEqual(record["status"], "candidate_ready", record)
        self.assertFalse((Path(record["worktree"]) / ".env").exists())


class OSVScopeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RepairTests()
        self.fixture.setUp()
        self.__dict__.update(
            {k: v for k, v in self.fixture.__dict__.items() if k != "_testMethodName"}
        )
        self.scan = self.fixture.scan
        self.backend = self.fixture.backend

    def tearDown(self):
        self.fixture.tearDown()

    def test_repository_scan_scope_and_lockfile_locations_are_separate(self):
        ledger = self.ledger
        # Use a separate registered scanner identity, never close npm findings.
        ledger.ingest(
            snapshot(
                "demo",
                "osv",
                "repository",
                {"type": "source", "revision": "initial"},
                [self.finding],
            )
        )
        identifier = next(f["id"] for f in ledger.findings() if f["scanner"] == "osv")

        def scan(asset, **kwargs):
            values = self.scan(asset, **kwargs)
            values[0]["scope"] = "repository"
            return values

        with (
            patch("teate.repair.registry", return_value=self.metadata),
            patch("teate.repair.scan_source", side_effect=scan),
            patch("teate.repair.backend", side_effect=self.backend),
        ):
            result = prepare(
                ledger, self.policy, self.root / "state", [identifier], "1.2.2", scanner="osv"
            )
        self.assertEqual(result["results"][0]["status"], "candidate_ready", result)
        self.assertNotEqual(
            next(f for f in ledger.findings() if f["scanner"] == "npm-audit")["effective_status"],
            "resolved",
        )
