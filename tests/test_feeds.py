import copy
import unittest

from teate.feeds import enrich
from teate.model import snapshot


class FeedTests(unittest.TestCase):
    def test_kev_matches_alias_and_keeps_source_dates(self):
        scan = snapshot(
            "test",
            "osv",
            "repository",
            {},
            [{"advisory_id": "GHSA-test", "aliases": ["CVE-2026-1"]}],
        )
        feed = {
            "source": "official",
            "fetched_at": "2026-10-25T00:00:00Z",
            "data": {
                "dateReleased": "2026-10-23T00:00:00Z",
                "vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-10-22"}],
            },
        }
        enriched = enrich(copy.deepcopy(scan), feed)
        self.assertTrue(enriched["findings"][0]["kev"])
        self.assertEqual(enriched["findings"][0]["kev_added_at"], "2026-10-22")
        self.assertEqual(enriched["kev_feed"]["released_at"], "2026-10-23T00:00:00Z")

    def test_missing_feed_does_not_invent_an_exploitation_status(self):
        scan = snapshot("test", "osv", "repository", {}, [{"advisory_id": "GHSA-test"}])
        self.assertNotIn("kev", enrich(scan, None)["findings"][0])


if __name__ == "__main__":
    unittest.main()
