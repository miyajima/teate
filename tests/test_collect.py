import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from teate.collect import (
    collect_cloud_run,
    lockfiles,
    npm_findings,
    osv_findings,
    scan_source,
    trivy_findings,
)
from teate.model import TeateError


def result(value, returncode=0):
    return subprocess.CompletedProcess([], returncode, json.dumps(value), "")


class AdapterTests(unittest.TestCase):
    @patch("teate.collect.shutil.which", return_value="osv-scanner")
    @patch("teate.collect.run")
    def test_go_module_is_scanned_instead_of_go_sum_and_both_are_fingerprinted(self, run, _):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "go.mod").write_text("module example.test/app\nrequire example.test/lib v1.0.0\n")
            (root / "go.sum").write_text("checksum fixture\n")
            run.side_effect = [subprocess.CompletedProcess([], 0, "abc", ""),
                               result({"results": []})]
            scan = scan_source({"id": "app", "path": str(root)})[0]
            self.assertTrue(scan["complete"])
            inputs = [a for a in run.call_args.args[0] if a.startswith("--lockfile=")]
            self.assertEqual(inputs, [f"--lockfile={root.resolve()}/go.mod"])
            self.assertEqual(set(scan["subject"]["lockfile_hashes"]), {"go.mod", "go.sum"})

    @patch("teate.collect.shutil.which", return_value="osv-scanner")
    @patch("teate.collect.run")
    def test_go_sum_without_a_module_is_a_specific_gap_not_a_clean_scan(self, run, _):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "go.sum").write_text("checksum fixture\n")
            run.return_value = subprocess.CompletedProcess([], 0, "abc", "")
            scan = scan_source({"id": "app", "path": str(root)})[0]
            self.assertFalse(scan["complete"])
            self.assertIn("go.mod", scan["message"])
            self.assertEqual(run.call_count, 1)

    @patch("teate.collect.shutil.which", return_value="osv-scanner")
    @patch("teate.collect.run")
    def test_parser_diagnostics_only_expose_the_known_input_not_raw_stderr(self, run, _):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Cargo.lock").write_text("")
            run.side_effect = [subprocess.CompletedProcess([], 0, "abc", ""),
                               subprocess.CompletedProcess([], 127, "",
                                   f'private-token-value\ncould not determine extractor suitable to this file: "{root.resolve()}/Cargo.lock"\n')]
            scan = scan_source({"id": "app", "path": str(root)})[0]
            self.assertFalse(scan["complete"])
            self.assertIn("Cargo.lock", scan["message"])
            self.assertNotIn("private-token-value", scan["message"])
            self.assertNotIn(str(root), scan["message"])

    def test_invalid_empty_outputs_are_not_clean_scans(self):
        for adapter in (osv_findings, trivy_findings):
            with self.assertRaises(TeateError):
                adapter({})
        with self.assertRaises(TeateError):
            npm_findings({}, "package-lock.json")

    def test_osv_aliases_and_fixes(self):
        raw = {
            "results": [
                {
                    "source": {"path": "Cargo.lock"},
                    "packages": [
                        {
                            "package": {
                                "name": "example",
                                "ecosystem": "crates.io",
                                "version": "1.0.0",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-test",
                                    "aliases": ["CVE-2026-12345"],
                                    "database_specific": {"severity": "MODERATE"},
                                    "affected": [
                                        {
                                            "ranges": [
                                                {
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "1.0.1"},
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        finding = osv_findings(raw)[0]
        self.assertEqual(finding["fixed_versions"], ["1.0.1"])
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["aliases"], ["CVE-2026-12345"])

    def test_trivy_maps_os_package_advisory(self):
        raw = {
            "SchemaVersion": 2,
            "ArtifactName": "app",
            "Results": [
                {
                    "Target": "alpine",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-test",
                            "PkgName": "openssl",
                            "InstalledVersion": "1",
                            "FixedVersion": "2, 3",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
        finding = trivy_findings(raw)[0]
        self.assertEqual(finding["fixed_versions"], ["2", "3"])

    def test_npm_does_not_treat_transitive_dependency_labels_as_advisories(self):
        raw = {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "example": {
                    "via": [
                        "transitive",
                        {
                            "source": 123,
                            "url": "https://github.com/advisories/GHSA-test",
                            "title": "example",
                            "severity": "moderate",
                            "range": "<1",
                        },
                    ],
                    "fixAvailable": True,
                }
            },
        }
        findings = npm_findings(raw, "package-lock.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["fixed_versions"], [])

    def test_lock_discovery_skips_installed_and_symlinked_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "package-lock.json").write_text("{}")
            (root / "Cargo.lock").write_text("")
            (root / "package-lock.json").symlink_to(root / "Cargo.lock")
            self.assertEqual(lockfiles(root), ["Cargo.lock"])

    def test_missing_source_directory_reports_error(self):
        scan = scan_source({"id": "missing", "path": "/missing-teate-project"})[0]
        self.assertEqual(scan["status"], "error")
        self.assertFalse(scan["complete"])

    @patch("teate.collect.run")
    def test_cloud_collector_includes_tagged_and_traffic_revisions(self, run):
        hashes = ["sha256:" + c * 64 for c in "ab"]
        service = {
            "status": {
                "traffic": [
                    {"revisionName": "new", "percent": 100},
                    {"revisionName": "old", "percent": 0, "tag": "preview"},
                ]
            }
        }
        run.side_effect = [
            result(service),
            *[
                result(
                    {
                        "status": {
                            "conditions": [{"type": "Ready", "status": "True"}],
                            "imageDigest": f"example/app@{d}",
                        }
                    }
                )
                for d in hashes
            ],
        ]
        observation = collect_cloud_run({"service": "app", "gcp_project": "p", "region": "r"})
        self.assertEqual(observation["images"], hashes)
        self.assertEqual(observation["revisions"], ["new", "old"])

    @patch("teate.collect.run")
    def test_cloud_collector_refuses_unresolved_image(self, run):
        run.side_effect = [
            result({"status": {"traffic": [{"revisionName": "new", "percent": 100}]}}),
            result({"status": {"conditions": [{"type": "Ready", "status": "True"}]}}),
        ]
        self.assertEqual(
            collect_cloud_run({"service": "app", "gcp_project": "p", "region": "r"})["status"],
            "error",
        )


if __name__ == "__main__":
    unittest.main()
