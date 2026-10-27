import copy
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from teate.model import TeateError, snapshot
from teate.store import Ledger


def moment(minutes=0):
    return (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat()


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.temp.name) / "ledger.db")
        self.asset = {
            "id": "project:mac",
            "project": "example",
            "environment": "mac",
            "kind": "source",
        }
        self.ledger.register([self.asset])
        self.finding = {
            "advisory_id": "GHSA-test",
            "aliases": ["CVE-2026-12345"],
            "package": "example",
            "ecosystem": "npm",
            "version": "1.0.0",
            "severity": "HIGH",
        }

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def scan(self, findings=None, minutes=0, **kwargs):
        return snapshot(
            "project:mac",
            "osv",
            "repository",
            {"type": "source", "revision": "abc"},
            [copy.deepcopy(self.finding)] if findings is None else findings,
            observed_at=moment(minutes),
            **kwargs,
        )

    def test_duplicate_import_is_idempotent(self):
        scan = self.scan()
        self.ledger.ingest(scan)
        self.assertTrue(self.ledger.ingest(copy.deepcopy(scan))["duplicate"])
        self.assertEqual(len(self.ledger.findings()), 1)

    def test_empty_error_does_not_resolve(self):
        self.ledger.ingest(self.scan(minutes=2))
        self.ledger.ingest(self.scan([], status="error", complete=False))
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")
        self.assertEqual(self.ledger.coverage()[0]["status"], "unknown")

    def test_partial_scan_does_not_resolve(self):
        self.ledger.ingest(self.scan(minutes=2))
        self.ledger.ingest(self.scan([], complete=False))
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_complete_matching_scan_resolves_and_recurrence_reopens(self):
        self.ledger.ingest(self.scan(minutes=3))
        self.assertEqual(self.ledger.ingest(self.scan([], minutes=2))["resolved"], 1)
        self.assertEqual(self.ledger.findings()[0]["effective_status"], "resolved")
        self.ledger.ingest(self.scan())
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_other_environment_cannot_close_local_finding(self):
        self.ledger.ingest(self.scan(minutes=2))
        self.ledger.register(
            [{**self.asset, "id": "project:production", "environment": "production"}]
        )
        scan = self.scan([])
        scan["asset_id"] = "project:production"
        self.ledger.ingest(scan)
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_old_clean_scan_does_not_close_new_finding(self):
        self.ledger.ingest(self.scan(minutes=1))
        result = self.ledger.ingest(self.scan([], minutes=2))
        self.assertTrue(result["out_of_order"])
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_timezone_offsets_order_by_instant(self):
        found = self.scan(minutes=5)
        local = datetime.fromisoformat(found["observed_at"]).astimezone(
            timezone(timedelta(hours=9))
        )
        found["observed_at"] = local.isoformat()
        self.ledger.ingest(found)
        self.ledger.ingest(self.scan([]))
        self.assertEqual(self.ledger.findings()[0]["status"], "resolved")

    def test_aliases_keep_one_finding_across_advisory_ids(self):
        self.ledger.ingest(self.scan(minutes=1))
        new = {**self.finding, "advisory_id": "CVE-2026-12345", "aliases": []}
        self.ledger.ingest(self.scan([new]))
        self.assertEqual(len(self.ledger.findings()), 1)

    def test_version_update_does_not_reset_first_seen_or_identity(self):
        self.ledger.ingest(self.scan(minutes=1))
        first = self.ledger.findings()[0]
        self.ledger.ingest(self.scan([{**self.finding, "version": "1.0.1"}]))
        current = self.ledger.findings()[0]
        self.assertEqual(first["id"], current["id"])
        self.assertEqual(first["first_seen"], current["first_seen"])

    def test_manual_resolution_is_forbidden(self):
        self.ledger.ingest(self.scan())
        with self.assertRaises(TeateError):
            self.ledger.mark(self.ledger.findings()[0]["id"], "resolved", "PR merged")

    def test_exception_requires_expiry_and_does_not_close(self):
        self.ledger.ingest(self.scan())
        item = self.ledger.findings()[0]
        with self.assertRaises(TeateError):
            self.ledger.exception(item["id"], moment(1), "expired")
        self.ledger.exception(item["id"], moment(-60), "mitigation in place")
        current = self.ledger.findings()[0]
        self.assertEqual(current["status"], "affected")
        self.assertEqual(current["effective_status"], "accepted_risk")

    def test_stale_and_never_scanned_assets_are_unknown(self):
        self.assertEqual(self.ledger.coverage()[0]["status"], "unknown")
        self.ledger.ingest(self.scan([], minutes=60 * 49))
        self.assertIn("stale", " ".join(self.ledger.coverage()[0]["problems"]))

    def test_snapshot_schema_validation_happens_before_mutation(self):
        invalid = self.scan()
        invalid["findings"][0]["kev"] = "false"
        with self.assertRaises(TeateError):
            self.ledger.ingest(invalid)
        self.assertEqual(self.ledger.db.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)

    def test_unpinned_image_cannot_be_marked_checked(self):
        asset = {
            "id": "image:test",
            "kind": "image",
            "project": "example",
            "environment": "test",
            "image": "test:latest",
        }
        self.ledger.register([asset])
        scan = snapshot(
            asset["id"], "trivy", "image", {"type": "image", "digest": "sha256:" + "a" * 64}
        )
        self.ledger.ingest(scan)
        image = next(c for c in self.ledger.coverage() if c["asset"]["id"] == asset["id"])
        self.assertEqual(image["status"], "unknown")

    def test_runtime_requires_all_routable_image_digests(self):
        asset = {
            "id": "cloud:prod",
            "kind": "cloud-run",
            "project": "example",
            "environment": "production",
        }
        self.ledger.register([asset])
        hashes = ["sha256:" + c * 64 for c in "ab"]
        self.ledger.observe(
            asset["id"], {"status": "success", "observed_at": moment(), "images": hashes}
        )
        found = snapshot(
            asset["id"],
            "trivy",
            "runtime",
            {"type": "runtime", "digests": hashes},
            [self.finding],
            observed_at=moment(1),
        )
        self.ledger.ingest(found)
        incomplete = snapshot(
            asset["id"], "trivy", "runtime", {"type": "runtime", "digests": hashes[:1]}
        )
        self.ledger.ingest(incomplete)
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")
        self.ledger.ingest(
            snapshot(asset["id"], "trivy", "runtime", {"type": "runtime", "digests": hashes})
        )
        self.assertEqual(self.ledger.findings()[0]["status"], "resolved")

    def test_stale_runtime_observation_cannot_close(self):
        asset = {
            "id": "cloud:prod",
            "kind": "cloud-run",
            "project": "example",
            "environment": "production",
        }
        self.ledger.register([asset])
        hashes = ["sha256:" + "a" * 64]
        self.ledger.observe(
            asset["id"], {"status": "success", "observed_at": moment(120), "images": hashes}
        )
        self.ledger.ingest(
            snapshot(
                asset["id"],
                "trivy",
                "runtime",
                {"digests": hashes},
                [self.finding],
                observed_at=moment(1),
            )
        )
        self.ledger.ingest(snapshot(asset["id"], "trivy", "runtime", {"digests": hashes}))
        self.assertEqual(self.ledger.findings()[0]["status"], "affected")

    def test_register_cannot_reassign_asset_identity(self):
        with self.assertRaises(TeateError):
            self.ledger.register([{**self.asset, "environment": "production"}])

    def test_scanner_metadata_cannot_override_identity_or_workflow_state(self):
        forged = {
            **self.finding,
            "id": "forged",
            "asset_id": "other:production",
            "status": "resolved",
            "first_seen": "2099-01-01T00:00:00Z",
            "effective_status": "resolved",
        }
        self.ledger.ingest(self.scan([forged]))
        current = self.ledger.findings()[0]
        self.assertEqual(current["asset_id"], self.asset["id"])
        self.assertNotEqual(current["id"], "forged")
        self.assertEqual(current["effective_status"], "affected")
        self.assertFalse(current["first_seen"].startswith("2099"))

    def test_missing_feed_does_not_erase_positive_kev_evidence(self):
        self.ledger.ingest(self.scan([{**self.finding, "kev": True}], minutes=1))
        self.ledger.ingest(self.scan())
        self.assertTrue(self.ledger.findings()[0]["kev"])

    def test_recovered_collection_does_not_leave_a_permanent_coverage_gap(self):
        failed = self.scan([], minutes=1, status="error", complete=False)
        failed["scope"] = "collection"
        self.ledger.ingest(failed)
        self.ledger.ingest(self.scan([]))
        self.assertEqual(self.ledger.coverage()[0]["status"], "checked")

    def test_transaction_rolls_back_invalid_ingest(self):
        malformed = self.scan()
        malformed["findings"].append({"advisory_id": "bad"})
        with self.assertRaises(TeateError):
            self.ledger.ingest(malformed)
        self.assertEqual(self.ledger.findings(), [])


if __name__ == "__main__":
    unittest.main()
