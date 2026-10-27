import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from teate.model import TeateError, snapshot
from teate.repair import _lock, _patch_lock, prepare
from teate.store import Ledger


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.old = {
            "lockfileVersion": 3,
            "packages": {"": {"devDependencies": {"example": "^1.2.1"}},
                         "node_modules/example": {
                             "version": "1.2.1", "resolved": "https://registry.npmjs.org/example/-/example-1.2.1.tgz",
                             "integrity": "old", "license": "MIT", "engines": {"node": ">=0.10"},
                         }},
        }
        (self.repo / "package-lock.json").write_text(json.dumps(self.old, indent=2)+'\n')
        self.git("init", "-q")
        self.git("add", "package-lock.json")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "initial")
        self.ledger = Ledger(self.root / "state" / "ledger.sqlite3")
        self.asset = {"id": "source:example", "project": "example", "environment": "test",
                      "kind": "source", "path": str(self.repo)}
        self.ledger.register([self.asset])
        self.finding = {"advisory_id": "GHSA-example", "ecosystem": "npm", "package": "example",
                        "version": "1.2.1", "severity": "HIGH", "location": "package-lock.json"}
        self.ledger.ingest(snapshot(self.asset["id"], "npm-audit", "package-lock.json",
                                    {"type": "source", "revision": "initial"}, [self.finding]))
        self.identifier = self.ledger.findings()[0]["id"]
        self.metadata = {"version": {"name": "example", "version": "1.2.2", "license": "MIT",
                                     "engines": {"node": ">=0.10"},
                                     "dist": {"tarball": "https://registry.npmjs.org/example/-/example-1.2.2.tgz",
                                              "integrity": "sha512-"+'A'*86+'=='}},
                         "published_at": "2026-09-30T00:00:00Z"}
        self.policy = {"automation": {"enabled": True, "allowed_packages": [],
                                      "required_checks": ["test", "security"]}}

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(self.repo), *args],
                              check=True, capture_output=True, text=True).stdout

    def scan(self, asset, **kw):
        data = json.loads((Path(asset["path"])/"package-lock.json").read_text())
        vulnerable = data["packages"]["node_modules/example"]["version"] == "1.2.1"
        return [snapshot(asset["id"], "npm-audit", "package-lock.json", {"type": "source", "revision": "test"},
                         [self.finding] if vulnerable else []),
                snapshot(asset["id"], "npm-audit", "Cargo.lock", {}, status="unsupported", complete=False)]

    def execute(self, scanner=None):
        with patch("teate.repair.registry", return_value=self.metadata), patch(
            "teate.repair.scan_source", side_effect=scanner or self.scan
        ):
            return prepare(self.ledger, self.policy, self.root/"state", [self.identifier], "1.2.2")

    def test_preparation_keeps_live_source_and_resolution_unchanged(self):
        before = (self.repo/"package-lock.json").read_bytes()
        result = self.execute()
        record = result["results"][0]
        self.assertEqual(record["status"], "candidate_ready", record)
        self.assertEqual((self.repo/"package-lock.json").read_bytes(), before)
        self.assertEqual(self.ledger.findings()[0]["effective_status"], "proposed")
        self.assertFalse(record["live_applied"])
        self.assertFalse(record["resolved"])
        self.assertEqual(record["merge_decision"]["action"], "review")
        self.assertIn("Cargo.lock", record["unverified_scopes"])
        self.assertTrue(Path(record["patch"]).is_file())
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_candidate_that_still_has_the_advisory_is_review_only(self):
        def scanner(asset, **kw):
            scans = self.scan(asset, **kw)
            scans[0]["findings"] = [self.finding]
            return scans
        record = self.execute(scanner)["results"][0]
        self.assertEqual(record["status"], "review")
        self.assertIn("did not remove", record["reason"])
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_a_new_advisory_blocks_the_candidate(self):
        def scanner(asset, **kw):
            scans = self.scan(asset, **kw)
            if asset["path"] != str(self.repo):
                scans[0]["findings"] = [{**self.finding, "advisory_id": "GHSA-new"}]
            return scans
        self.assertIn("additional findings", self.execute(scanner)["results"][0]["reason"])

    def test_candidate_scanner_failure_never_counts_as_success(self):
        def scanner(asset, **kw):
            scans = self.scan(asset, **kw)
            if asset["path"] != str(self.repo):
                scans[0].update(status="error", complete=False, findings=[])
            return scans
        result = self.execute(scanner)["results"][0]
        self.assertEqual(result["status"], "review")
        self.assertIn("could not be verified", result["reason"])
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_live_source_change_during_candidate_scan_blocks_the_candidate(self):
        def scanner(asset, **kw):
            scans = self.scan(asset, **kw)
            if asset["path"] != str(self.repo):
                (self.repo/"package-lock.json").write_text(json.dumps({**self.old, "changed": True}))
            return scans
        result = self.execute(scanner)["results"][0]
        self.assertEqual(result["status"], "review")
        self.assertIn("Source changed", result["reason"])

    def test_dirty_checkout_is_not_touched(self):
        (self.repo/"package-lock.json").write_text("changed")
        self.assertIn("local changes", self.execute()["results"][0]["reason"])

    def test_unverified_host_is_not_scanned(self):
        self.ledger.register([{**self.asset, "host_id": "unverified-other-host"}])
        with patch("teate.repair.scan_source") as scanner:
            result = self.execute()
            scanner.assert_not_called()
        self.assertIn("verified host", result["results"][0]["reason"])

    def test_ids_are_bounded_and_come_from_the_ledger(self):
        for ids in ([], [self.identifier]*2, ["unknown"], [str(n) for n in range(6)]):
            with self.subTest(ids=ids), self.assertRaises(TeateError):
                prepare(self.ledger, self.policy, self.root/"state", ids, "1.2.2")

    def test_pinned_constraints_graph_changes_and_major_updates_are_not_guessed(self):
        old = copy.deepcopy(self.old)
        old["packages"][""]["devDependencies"]["example"] = "1.2.1"
        variants = [(old, self.metadata)]
        for key in ("dependencies", "bin"):
            meta = copy.deepcopy(self.metadata)
            meta["version"][key] = {"untrusted": "value"}
            variants.append((self.old, meta))
        meta = copy.deepcopy(self.metadata)
        meta["version"]["scripts"] = {"install": "untrusted command"}
        variants.append((self.old, meta))
        meta = copy.deepcopy(self.metadata)
        meta["version"]["version"] = "1.3.0"
        variants.append((self.old, meta))
        for old, meta in variants:
            with self.subTest(meta=meta), self.assertRaises(TeateError):
                _patch_lock(old, "example", "1.2.1", meta)

    def test_non_install_package_scripts_are_not_executed_or_added_to_the_lock(self):
        metadata = copy.deepcopy(self.metadata)
        metadata["version"]["scripts"] = {"test": "node test.js", "build": "webpack"}
        result = _patch_lock(self.old, "example", "1.2.1", metadata)
        self.assertEqual(result["packages"]["node_modules/example"]["version"], "1.2.2")
        self.assertNotIn("scripts", result["packages"]["node_modules/example"])

    def test_traversal_and_symlink_paths_are_rejected(self):
        for path in ("../package-lock.json", "/tmp/package-lock.json", "node_modules/a/package-lock.json"):
            with self.subTest(path=path), self.assertRaises(TeateError):
                _lock(self.repo, path)
        (self.repo/"linked").symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(TeateError):
            _lock(self.repo, "linked/package-lock.json")


if __name__ == "__main__":
    unittest.main()
