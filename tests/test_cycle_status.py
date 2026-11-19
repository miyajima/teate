import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from teate.agent import MAX_BRIEF_BYTES, brief, render
from teate.cycle_status import changes
from teate.model import snapshot
from teate.store import Ledger


class CycleChangesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.temp.name)/"ledger.sqlite3")
        self.asset = {"id": "example", "project": "example", "environment": "development", "kind": "source"}
        self.ledger.register([self.asset])
        self.scan(1)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def scan(self, count, *, failed=False):
        self.ledger.ingest(snapshot(
            "example", "osv", "repository", {"type": "source", "revision": "abc"},
            [{"advisory_id": f"GHSA-{i}", "package": "example", "ecosystem": "npm",
              "version": "1.0.0", "severity": "HIGH", "location": "package-lock.json"}
             for i in range(count)], status="error" if failed else "success", complete=not failed,
        ))

    def checkpoint(self):
        with self.ledger.db:
            self.ledger.db.execute("BEGIN IMMEDIATE")
            delta = changes(self.ledger)
            packet = brief(self.ledger, {}, cycle={"changes": delta})
            return delta, packet

    def test_first_or_corrupt_baseline_reports_unknown_instead_of_zero(self):
        for corrupt in (False, True):
            if corrupt:
                with self.ledger.db:
                    self.ledger.db.execute("UPDATE agent_cycle_baseline SET statuses='not json'")
            delta, packet = self.checkpoint()
            self.assertEqual(delta["status"], "baseline_unavailable")
            self.assertIsNone(delta["new"])
            self.assertIsNone(delta["resolved_new"])
            self.assertIn("未確認", render(packet)["text"])
        delta, _ = self.checkpoint()
        self.assertEqual(delta["continuing"], 1)

    def test_omitted_findings_and_failed_scans_never_become_resolutions(self):
        self.checkpoint()
        self.scan(30)
        delta, packet = self.checkpoint()
        self.assertEqual((delta["new"], delta["continuing"], delta["resolved_new"]), (29, 1, 0))
        self.assertEqual(packet["omitted"]["findings"], 25)
        self.assertLessEqual(len((json.dumps(packet, ensure_ascii=False, indent=2)+"\n").encode()), MAX_BRIEF_BYTES)
        self.scan(0, failed=True)
        delta, _ = self.checkpoint()
        self.assertEqual((delta["continuing"], delta["resolved_new"]), (30, 0))
        self.scan(0)
        delta, packet = self.checkpoint()
        self.assertEqual((delta["continuing"], delta["resolved_new"]), (0, 30))
        self.assertIn("実行履歴と対象環境の証跡", render(packet)["text"])

    def test_risk_acceptance_is_not_resolution_and_expiry_is_newly_open(self):
        self.checkpoint()
        identifier = self.ledger.findings()[0]["id"]
        self.ledger.exception(identifier, (datetime.now(UTC)+timedelta(days=1)).isoformat(), "reviewed")
        delta, _ = self.checkpoint()
        self.assertEqual((delta["new"], delta["continuing"], delta["resolved_new"]), (0, 0, 0))
        with self.ledger.db:
            self.ledger.db.execute("UPDATE findings SET exception_until=?", ((datetime.now(UTC)-timedelta(days=1)).isoformat(),))
        delta, _ = self.checkpoint()
        self.assertEqual((delta["new"], delta["resolved_new"]), (1, 0))

    def test_missing_ids_are_unknown_and_require_review(self):
        self.checkpoint()
        with self.ledger.db:
            row = self.ledger.db.execute("SELECT statuses FROM agent_cycle_baseline").fetchone()
            statuses = {**json.loads(row["statuses"]), "no-longer-present": "affected"}
            self.ledger.db.execute("UPDATE agent_cycle_baseline SET statuses=?", (json.dumps(statuses),))
        delta, packet = self.checkpoint()
        self.assertEqual((delta["missing"], delta["resolved_new"]), (1, 0))
        self.assertTrue(packet["facts"]["requires_review"])
        self.assertIn("解消には数えません", render(packet)["text"])

    def test_packet_persistence_failure_does_not_advance_baseline(self):
        self.checkpoint()
        self.scan(2)
        with self.assertRaises(OSError), self.ledger.db:
            self.ledger.db.execute("BEGIN IMMEDIATE")
            delta = changes(self.ledger)
            brief(self.ledger, {}, cycle={"changes": delta})
            raise OSError("packet persistence failed")
        delta, _ = self.checkpoint()
        self.assertEqual((delta["new"], delta["continuing"]), (1, 1))
