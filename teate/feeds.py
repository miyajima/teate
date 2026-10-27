"""KEV enrichment is separate from package applicability detection."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .model import TeateError, utcnow

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


def fetch_kev() -> dict:
    try:
        request = urllib.request.Request(KEV_URL, headers={"User-Agent": "Teate/0.1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = json.load(response)
        if not isinstance(raw.get("vulnerabilities"), list) or not raw.get("dateReleased"):
            raise TeateError("Invalid official KEV feed")
        return {"fetched_at": utcnow(), "source": KEV_URL, "data": raw}
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise TeateError("Cannot fetch KEV; existing scan results are unchanged") from exc


def enrich(scan: dict, feed: dict | None) -> dict:
    if not feed:
        return scan
    known = {v["cveID"]: v for v in feed["data"]["vulnerabilities"]}
    for finding in scan["findings"]:
        matches = [
            known[a] for a in [finding["advisory_id"], *finding.get("aliases", [])] if a in known
        ]
        if matches:
            finding["kev"] = True
            finding["kev_added_at"] = min(m["dateAdded"] for m in matches)
    scan["kev_feed"] = {
        "source": feed["source"],
        "fetched_at": feed["fetched_at"],
        "released_at": feed["data"]["dateReleased"],
    }
    return scan
