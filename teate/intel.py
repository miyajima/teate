"""Bounded primary-source intake and stable content identities, without an LLM."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from .model import TeateError, digest, load_json, timestamp, utcnow, write_json

FEEDS = {
    "jpcert": "https://www.jpcert.or.jp/rss/jpcert.rdf",
    "jvn": "https://jvn.jp/rss/jvn.rdf",
    "nodejs": "https://nodejs.org/en/feed/blog.xml",
}
MAX_BODY = 2_000_000


def network_allowed(url: str) -> bool:
    path = Path("/etc/codex/network-policy.json")
    if not path.exists():
        return True
    try:
        data = load_json(path)
        policy = data["http_network_policy"]
        return data["version"] == 1 and (
            policy["type"] == "unrestricted" or urllib.parse.urlsplit(url).hostname in
            {r.get("host") for r in policy.get("egress_rules", [])}
        )
    except (TeateError, KeyError, TypeError):
        return False


def fetch(url: str, headers: dict | None = None) -> tuple[bytes, dict]:
    if not network_allowed(url):
        raise TeateError("network_not_allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "Teate/0.4", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if urllib.parse.urlsplit(response.geturl()).hostname != urllib.parse.urlsplit(url).hostname:
                raise TeateError("unexpected_source_redirect")
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise TeateError("source_response_too_large")
            return raw, {k: response.headers[k] for k in ("ETag", "Last-Modified") if k in response.headers}
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return b"", {"not_modified": True}
        raise TeateError("source_fetch_failed") from exc
    except OSError as exc:
        raise TeateError("source_fetch_failed") from exc


def _date(value: str) -> str | None:
    try:
        return timestamp(value).isoformat()
    except TeateError:
        try:
            result = parsedate_to_datetime(value)
            return result.astimezone(UTC).isoformat() if result.tzinfo else None
        except (ValueError, TypeError):
            return None


def parse_feed(raw: bytes) -> list[dict]:
    if b"\x00" in raw or re.search(br"<!DOCTYPE|<!ENTITY", raw, re.I):
        raise TeateError("feed_entities_not_supported")
    import feedparser
    parsed = feedparser.parse(raw)
    if parsed.bozo:
        raise TeateError("invalid_official_feed")
    items = []
    for entry in parsed.entries[:100]:
        values = dict(entry)
        values["description"] = entry.get("summary", "")
        values["pubDate"] = entry.get("published", "")
        link = values.get("link", "").strip()
        if urllib.parse.urlsplit(link).scheme != "https":
            continue
        if any(i["url"] == link for i in items):
            continue
        title = re.sub(r"\s+", " ", values.get("title", ""))[:200]
        excerpt = re.sub(r"<[^>]+>", " ", values.get("summary", values.get("description", "")))
        item = {"url": link, "title": title,
                "published_at": _date(values.get("published", values.get("pubDate", values.get("date", "")))),
                "updated_at": _date(values.get("updated", values.get("date", ""))),
                "excerpt": re.sub(r"\s+", " ", excerpt).strip()[:500]}
        item["content_id"] = digest(item)
        items.append(item)
        if len(items) >= 100:
            break
    return items


def refresh(state: Path) -> dict:
    root = state / "intel"
    records, events = [], []
    now = datetime.now(UTC)
    for name, url in FEEDS.items():
        path = root / (name + ".json")
        try:
            old = load_json(path) if path.exists() else {}
            if not isinstance(old, dict) or not isinstance(old.get("headers", {}), dict):
                old = {}
        except TeateError:
            old = {}
        try:
            start = timestamp(old["last_success"]) - timedelta(hours=48) if old.get("last_success") else now-timedelta(days=7)
        except (TeateError, TypeError):
            old, start = {}, now-timedelta(days=7)
        record = {"source": name, "url": url, "status": "success", "window_start": start.isoformat()}
        try:
            headers = {"If-None-Match": old["headers"]["ETag"]} if old.get("headers", {}).get("ETag") else {}
            raw, response_headers = fetch(url, headers)
            previous = {i["url"]: i for i in old.get("items", [])}
            items = old.get("items", []) if response_headers.get("not_modified") else parse_feed(raw)
            if not items and not response_headers.get("not_modified"):
                raise TeateError("empty_or_unsupported_official_feed")
            for item in items:
                before = previous.get(item["url"])
                dated = item.get("updated_at") or item.get("published_at")
                if before and before["content_id"] == item["content_id"]:
                    continue
                if not before and dated and timestamp(dated) < start:
                    continue
                events.append({**item, "source": name, "change": "updated" if before else "new"})
                event = events[-1]
                evidence_file = root/"events"/(digest(event)+".json")
                if not evidence_file.exists():
                    write_json(evidence_file, event)
            write_json(path, {"last_success": utcnow(), "headers": response_headers or old.get("headers", {}),
                              "items": list({i["url"]: i for i in [*old.get("items", []), *items]}.values())[-1000:]})
        except (TeateError, ValueError, KeyError, TypeError) as exc:
            record.update(status="unconfirmed", reason=str(exc) if isinstance(exc, TeateError) else "invalid_source_data")
        records.append(record)
    result = {"checked_at": utcnow(), "sources": records, "events": events,
              "new": sum(e["change"] == "new" for e in events),
              "updated": sum(e["change"] == "updated" for e in events),
              "unconfirmed": sum(r["status"] != "success" for r in records)}
    write_json(root / "summary.json", result)
    return result


def advisory(finding: dict) -> dict:
    identifier = finding["advisory_id"]
    if not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", identifier):
        raise TeateError("structured_fix_unavailable")
    url = "https://api.github.com/advisories/" + identifier
    raw, _ = fetch(url, {"Accept": "application/vnd.github+json"})
    try:
        data = json.loads(raw)
        if data["ghsa_id"] != identifier or data.get("withdrawn_at"):
            raise TeateError("advisory_identity_or_withdrawal")
        versions = [v["first_patched_version"] for v in data["vulnerabilities"]
                    if v["package"] == {"ecosystem": "npm", "name": finding["package"]}
                    and v.get("first_patched_version")]
        return {"source": url, "updated_at": data.get("updated_at"), "fixed_versions": versions,
                "aliases": [data["cve_id"]] if data.get("cve_id") else [],
                "summary": str(data.get("summary", ""))[:500]}
    except (ValueError, KeyError, TypeError) as exc:
        raise TeateError("invalid_structured_advisory") from exc


def resolve(finding: dict, catalog: dict) -> dict | None:
    key = (finding["package"], finding["advisory_id"])
    if key not in catalog:
        if len(catalog) >= 5:
            return None
        try:
            catalog[key] = advisory(finding)
        except (TeateError, OSError, ValueError, KeyError, TypeError):
            catalog[key] = None
    return catalog[key]


def enrich(scans: list[dict], catalog: dict):
    for scan in scans:
        for finding in scan["findings"]:
            if finding["ecosystem"] != "npm":
                continue
            data = resolve(finding, catalog)
            if data:
                finding["aliases"] = sorted(set(finding.get("aliases", [])) | {
                    v for v in data["aliases"] if isinstance(v,str) and re.fullmatch(r"CVE-\d{4}-\d{4,}",v)})
                finding["fixed_versions"] = sorted(set(finding.get("fixed_versions", [])) | {
                    v for v in data["fixed_versions"] if isinstance(v,str) and len(v)<80})
                finding["fix_evidence"] = {"source":data["source"], "updated_at":data["updated_at"]}
