"""Transactional evidence ledger. Missing/failed scans never imply remediation."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .model import (
    TeateError,
    canonical,
    digest,
    image_digest,
    timestamp,
    utcnow,
    validate_asset,
    validate_snapshot,
)

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS assets (
 id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id), scanner TEXT NOT NULL,
 scope TEXT NOT NULL, observed_at TEXT NOT NULL, status TEXT NOT NULL,
 complete INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS scans_scope ON scans(asset_id,scanner,scope,observed_at);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id), scanner TEXT NOT NULL,
 scope TEXT NOT NULL, package TEXT NOT NULL, ecosystem TEXT NOT NULL,
 location TEXT NOT NULL, data TEXT NOT NULL, status TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT,
 exception_until TEXT, exception_reason TEXT, issue_url TEXT);
CREATE TABLE IF NOT EXISTS aliases (
 finding_id TEXT NOT NULL REFERENCES findings(id), alias TEXT NOT NULL,
 PRIMARY KEY(finding_id,alias));
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, finding_id TEXT REFERENCES findings(id),
 at TEXT NOT NULL, action TEXT NOT NULL, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations (
 asset_id TEXT PRIMARY KEY REFERENCES assets(id), observed_at TEXT NOT NULL,
 data TEXT NOT NULL);
"""


class Ledger:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=30)
        self.db.row_factory = sqlite3.Row
        # Back up existing evidence before the additive v0.5 schema migration.
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE name='assets'").fetchone():
            backup_path = Path(str(path) + ".pre-v05")
            if not backup_path.exists() and not self.db.execute("SELECT 1 FROM sqlite_master WHERE name='repair_runs'").fetchone():
                with sqlite3.connect(str(backup_path)) as backup:
                    self.db.backup(backup)
        self.db.executescript(SCHEMA)
        from .jobs import Jobs
        Jobs(self)

    def close(self):
        self.db.close()

    def register(self, assets: list[dict]):
        ids = [validate_asset(a)["id"] for a in assets]
        if len(ids) != len(set(ids)):
            raise TeateError("Duplicate asset ids in inventory")
        with self.db:
            for asset in assets:
                old = self.db.execute(
                    "SELECT data FROM assets WHERE id=?", (asset["id"],)
                ).fetchone()
                if old:
                    previous = json.loads(old["data"])
                    if any(previous[k] != asset[k] for k in ("project", "environment", "kind")):
                        raise TeateError("Asset identity cannot be repurposed; use a new id")
                self.db.execute(
                    "INSERT INTO assets VALUES (?,?,?) ON CONFLICT(id) DO UPDATE "
                    "SET data=excluded.data,updated_at=excluded.updated_at",
                    (asset["id"], canonical(asset), utcnow()),
                )

    def assets(self) -> list[dict]:
        return [
            json.loads(r["data"]) for r in self.db.execute("SELECT data FROM assets ORDER BY id")
        ]

    def asset(self, asset_id: str) -> dict:
        row = self.db.execute("SELECT data FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not row:
            raise TeateError(f"Unknown asset: {asset_id}")
        return json.loads(row["data"])

    def observation(self, asset_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT data FROM observations WHERE asset_id=?", (asset_id,)
        ).fetchone()
        return json.loads(row["data"]) if row else None

    def observe(self, asset_id: str, observation: dict):
        self.asset(asset_id)
        observed = observation.get("observed_at", utcnow())
        observed_time = timestamp(observed)
        if (observed_time - datetime.now(UTC)).total_seconds() > 300:
            raise TeateError("Observation timestamp is in the future")
        observed = observed_time.isoformat(timespec="microseconds")
        old = self.observation(asset_id)
        if old and timestamp(old["observed_at"]) >= timestamp(observed):
            return
        observation = {**observation, "observed_at": observed}
        with self.db:
            self.db.execute(
                "INSERT INTO observations VALUES (?,?,?) ON CONFLICT(asset_id) "
                "DO UPDATE SET observed_at=excluded.observed_at,data=excluded.data",
                (asset_id, observed, canonical(observation)),
            )

    def _event(self, finding_id: str, action: str, evidence: str):
        self.db.execute(
            "INSERT INTO events(finding_id,at,action,evidence) VALUES (?,?,?,?)",
            (finding_id, utcnow(), action, evidence),
        )

    def _subject_valid(self, asset: dict, scan: dict) -> bool:
        subject = scan["subject"]
        if asset["kind"] == "source":
            host_matches = not asset.get("host_id") or subject.get("host_id") == asset["host_id"]
            return (
                host_matches and subject.get("type") == "source" and bool(subject.get("revision"))
            )
        if asset["kind"] == "image":
            expected = image_digest(asset.get("image", ""))
            return bool(expected) and image_digest(subject.get("digest", "")) == expected
        if asset["kind"] == "cloud-run":
            observation = self.observation(asset["id"])
            if not observation or observation.get("status") != "success":
                return False
            if (
                abs(
                    (
                        timestamp(scan["observed_at"]) - timestamp(observation["observed_at"])
                    ).total_seconds()
                )
                > 3600
            ):
                return False
            # All traffic-bearing revisions, and tagged routable revisions, must be checked.
            images = observation.get("images", [])
            return bool(images) and set(subject.get("digests", [])) == set(images)
        if asset["kind"] == "mac":
            return subject.get("type") == "host" and subject.get("host_id") == asset.get("host_id")
        return False

    def ingest(self, scan: dict) -> dict:
        validate_snapshot(scan)
        asset = self.asset(scan["asset_id"])
        scan_id = digest(scan)
        counts = {
            "scan_id": scan_id,
            "created": 0,
            "updated": 0,
            "resolved": 0,
            "duplicate": False,
            "out_of_order": False,
        }
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.db.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone():
                self.db.rollback()
                return {**counts, "duplicate": True}
            args = (scan["asset_id"], scan["scanner"], scan["scope"])
            latest = self.db.execute(
                "SELECT observed_at FROM scans WHERE asset_id=? AND scanner=? "
                "AND scope=? ORDER BY observed_at DESC LIMIT 1",
                args,
            ).fetchone()
            self.db.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)",
                (
                    scan_id,
                    *args,
                    scan["observed_at"],
                    scan["status"],
                    scan["complete"],
                    canonical(scan),
                ),
            )
            if latest and timestamp(latest["observed_at"]) >= timestamp(scan["observed_at"]):
                self.db.commit()
                return {**counts, "out_of_order": True}
            # Even partial scans can prove presence, but only trustworthy complete scans prove absence.
            seen = set()
            for finding in scan["findings"]:
                aliases = sorted({finding["advisory_id"], *finding.get("aliases", [])})
                location = finding.get("location", scan["scope"])
                candidates = self.db.execute(
                    "SELECT * FROM findings WHERE asset_id=? AND scanner=? AND scope=? "
                    "AND package=? AND ecosystem=? AND location=?",
                    (*args, finding["package"], finding["ecosystem"], location),
                ).fetchall()
                row = next(
                    (
                        r
                        for r in candidates
                        if set(aliases)
                        & {
                            a[0]
                            for a in self.db.execute(
                                "SELECT alias FROM aliases WHERE finding_id=?", (r["id"],)
                            )
                        }
                    ),
                    None,
                )
                finding_id = (
                    row["id"]
                    if row
                    else digest(
                        [*args, finding["ecosystem"], finding["package"], location, aliases[0]]
                    )[:24]
                )
                seen.add(finding_id)
                if row:
                    old = json.loads(row["data"])
                    finding = {**finding, "aliases": sorted(set(aliases + old.get("aliases", [])))}
                    if old.get("kev"):
                        finding["kev"] = True
                        finding.setdefault("kev_added_at", old.get("kev_added_at"))
                    status = row["status"] if row["status"] != "resolved" else "affected"
                    self.db.execute(
                        "UPDATE findings SET data=?,status=?,last_seen=?,resolved_at=NULL WHERE id=?",
                        (canonical(finding), status, scan["observed_at"], finding_id),
                    )
                    if row["status"] == "resolved":
                        self._event(finding_id, "reopened", scan_id)
                    counts["updated"] += 1
                else:
                    self.db.execute(
                        "INSERT INTO findings(id,asset_id,scanner,scope,package,ecosystem,location,"
                        "data,status,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            finding_id,
                            *args,
                            finding["package"],
                            finding["ecosystem"],
                            location,
                            canonical({**finding, "aliases": aliases}),
                            "affected",
                            scan["observed_at"],
                            scan["observed_at"],
                        ),
                    )
                    self._event(finding_id, "detected", scan_id)
                    counts["created"] += 1
                for alias in aliases:
                    self.db.execute(
                        "INSERT OR IGNORE INTO aliases VALUES (?,?)", (finding_id, alias)
                    )
            if (
                scan["status"] == "success"
                and scan["complete"]
                and self._subject_valid(asset, scan)
            ):
                for row in self.db.execute(
                    "SELECT id FROM findings WHERE asset_id=? AND scanner=? AND scope=? "
                    "AND status!='resolved'",
                    args,
                ).fetchall():
                    if row["id"] not in seen:
                        self.db.execute(
                            "UPDATE findings SET status='resolved',resolved_at=?,exception_until=NULL,"
                            "exception_reason=NULL WHERE id=?",
                            (scan["observed_at"], row["id"]),
                        )
                        self._event(row["id"], "verified_resolved", scan_id)
                        counts["resolved"] += 1
            self.db.commit()
            return counts
        except Exception:
            self.db.rollback()
            raise

    def findings(self) -> list[dict]:
        results = []
        for row in self.db.execute("SELECT * FROM findings ORDER BY first_seen,id"):
            # Scanner-controlled metadata cannot override ledger identity or workflow state.
            item = {**json.loads(row["data"]), **dict(row)}
            del item["data"]
            if item["exception_until"] and timestamp(item["exception_until"]) > datetime.now(UTC):
                item["effective_status"] = (
                    "accepted_risk" if item["status"] != "resolved" else "resolved"
                )
            else:
                item["effective_status"] = item["status"]
            results.append(item)
        return results

    def mark(self, finding_id: str, status: str, reason: str):
        if status not in {"affected", "proposed", "testing", "awaiting_deployment", "blocked"}:
            raise TeateError("Resolution requires a complete matching scan; invalid transition")
        with self.db:
            row = self.db.execute(
                "SELECT status FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
            if not row or row["status"] == "resolved":
                raise TeateError("Finding is missing or already resolved")
            self.db.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
            self._event(finding_id, status, reason)

    def exception(self, finding_id: str, until: str, reason: str):
        if not reason.strip() or timestamp(until) <= datetime.now(UTC):
            raise TeateError("An exception requires a reason and a future expiry")
        with self.db:
            if not self.db.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone():
                raise TeateError("Unknown finding")
            self.db.execute(
                "UPDATE findings SET exception_until=?,exception_reason=? WHERE id=?",
                (until, reason, finding_id),
            )
            self._event(finding_id, "exception", canonical({"until": until, "reason": reason}))

    def coverage(self, max_age_hours: int = 48) -> list[dict]:
        now = datetime.now(UTC)
        results = []
        for asset in self.assets():
            rows = self.db.execute(
                "SELECT data FROM scans WHERE asset_id=? ORDER BY observed_at DESC", (asset["id"],)
            ).fetchall()
            latest = {}
            for row in rows:
                scan = json.loads(row["data"])
                latest.setdefault((scan["scanner"], scan["scope"]), scan)
            # A later successful collection supersedes a transient collector-level
            # failure, while individual scanner gaps remain visible independently.
            recovered_at = max(
                (
                    timestamp(s["observed_at"])
                    for s in latest.values()
                    if s["scope"] != "collection" and s["status"] == "success"
                ),
                default=None,
            )
            latest = {
                key: scan
                for key, scan in latest.items()
                if not (
                    scan["scope"] == "collection"
                    and recovered_at is not None
                    and timestamp(scan["observed_at"]) < recovered_at
                )
            }
            expected = {tuple(x) for x in asset.get("expected_scans", [])}
            missing = expected - set(latest)
            problems = [f"{scanner}:{scope}: never scanned" for scanner, scope in sorted(missing)]
            if not latest:
                problems.append("never scanned")
            for (scanner, scope), scan in latest.items():
                prefix = f"{scanner}:{scope}"
                if now - timestamp(scan["observed_at"]) > timedelta(hours=max_age_hours):
                    problems.append(f"{prefix}: stale")
                if scan["status"] != "success" or not scan["complete"]:
                    problems.append(f"{prefix}: {scan.get('message') or scan['status']}")
                elif not self._subject_valid(asset, scan):
                    problems.append(f"{prefix}: runtime/source identity unverified")
            results.append(
                {
                    "asset": asset,
                    "status": "unknown" if problems else "checked",
                    "problems": problems,
                    "scans": list(latest.values()),
                }
            )
        return results

    def issue_link(self, finding_id: str, url: str):
        with self.db:
            self.db.execute("UPDATE findings SET issue_url=? WHERE id=?", (url, finding_id))
