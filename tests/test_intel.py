import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from teate.intel import advisory, enrich, parse_feed, refresh
from teate.model import TeateError


class IntelTests(unittest.TestCase):
    def feed(self, title="Update", date=None):
        date = date or datetime.now(UTC).isoformat()
        return ('<rss><channel><item><title>'+title+'</title><link>https://vendor.example/advisory</link>'
                '<pubDate>'+date+'</pubDate><description>Primary source</description></item></channel></rss>').encode()

    def test_xml_entity_and_non_https_links_are_not_accepted(self):
        with self.assertRaises(TeateError):
            parse_feed(b'<!DOCTYPE x [<!ENTITY x "expand">]><rss/>')
        self.assertEqual(parse_feed(self.feed().replace(b'https:', b'http:')), [])

    def test_first_window_deltas_and_failures_do_not_advance_success(self):
        with tempfile.TemporaryDirectory() as temp, patch("teate.intel.FEEDS", {"vendor":"https://vendor.example/rss"}):
            state = Path(temp)
            with patch("teate.intel.fetch", return_value=(self.feed(date="2026-01-01T00:00:00Z"), {})):
                self.assertEqual(refresh(state)["new"], 0)
            with patch("teate.intel.fetch", return_value=(self.feed(), {})):
                self.assertEqual(refresh(state)["updated"], 1)
            cache = state/"intel/vendor.json"
            before = cache.read_bytes()
            with patch("teate.intel.fetch", side_effect=TeateError("network_not_allowed")):
                self.assertEqual(refresh(state)["unconfirmed"], 1)
            self.assertEqual(cache.read_bytes(), before)

    def test_reordered_or_unchanged_feed_has_no_new_model_work(self):
        raw = self.feed(date="2026-10-27T00:00:00Z")
        with tempfile.TemporaryDirectory() as temp, patch("teate.intel.FEEDS", {"vendor":"https://vendor.example/rss"}), patch("teate.intel.fetch", return_value=(raw, {})):
            refresh(Path(temp))
            result = refresh(Path(temp))
            self.assertEqual(result["events"], [])

    def test_fix_is_taken_only_from_matching_official_advisory_package(self):
        finding = {"advisory_id":"GHSA-aaaa-bbbb-cccc", "package":"example"}
        data = {"ghsa_id":finding["advisory_id"], "vulnerabilities":[
            {"package":{"ecosystem":"npm","name":"other"}, "first_patched_version":"9.9.9"},
            {"package":{"ecosystem":"npm","name":"example"}, "first_patched_version":"1.2.2"}]}
        with patch("teate.intel.fetch", return_value=(json.dumps(data).encode(), {})):
            self.assertEqual(advisory(finding)["fixed_versions"], ["1.2.2"])
        data["withdrawn_at"] = "2026-10-27T00:00:00Z"
        with patch("teate.intel.fetch", return_value=(json.dumps(data).encode(), {})), self.assertRaises(TeateError):
            advisory(finding)

    def test_structured_alias_and_fix_enrichment_is_shared_and_provenance_is_retained(self):
        finding = {"ecosystem":"npm","advisory_id":"GHSA-aaaa-bbbb-cccc","package":"example"}
        scans = [{"findings":[dict(finding),dict(finding)]}]
        value = {"aliases":["CVE-2026-12345"],"fixed_versions":["1.2.2"],
                 "source":"https://api.github.com/advisories/GHSA-aaaa-bbbb-cccc","updated_at":"2026-10-27T00:00:00Z"}
        with patch("teate.intel.advisory",return_value=value) as source:
            enrich(scans,{})
        self.assertEqual(source.call_count,1)
        for record in scans[0]["findings"]:
            self.assertEqual(record["aliases"],["CVE-2026-12345"])
            self.assertEqual(record["fixed_versions"],["1.2.2"])
            self.assertEqual(record["fix_evidence"]["source"],value["source"])


if __name__ == "__main__":
    unittest.main()
