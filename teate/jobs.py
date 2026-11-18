"""Durable repair runs and write-ahead external operation intents."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from .model import TeateError, canonical, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS repair_runs (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS repair_steps (
 run_id TEXT NOT NULL REFERENCES repair_runs(id), name TEXT NOT NULL,
 started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, data TEXT NOT NULL,
 PRIMARY KEY(run_id,name));
CREATE UNIQUE INDEX IF NOT EXISTS one_active_repair_per_asset ON repair_runs(asset_id)
 WHERE status NOT IN ('verified','rolled_back','stale','review');
"""
TERMINAL = {"verified", "rolled_back", "stale", "review"}


class Jobs:
    def __init__(self, ledger):
        self.db = ledger.db
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE name='repair_runs'").fetchone():
            self.db.executescript(SCHEMA)

    def active(self, asset_id):
        row = self.db.execute(
            "SELECT id FROM repair_runs WHERE asset_id=? AND status NOT IN ('verified','rolled_back','stale','review')",
            (asset_id,),
        ).fetchone()
        return self.get(row["id"]) if row else None

    def create(self, asset_id, record):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            active = self.active(asset_id)
            if active:
                self.db.commit()
                return active
            identifier, now = uuid.uuid4().hex, utcnow()
            self.db.execute(
                "INSERT INTO repair_runs VALUES (?,?,?,?,?,?)",
                (identifier, asset_id, now, now, "ready", canonical({"record": record})),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return self.get(identifier)

    def get(self, identifier):
        row = self.db.execute("SELECT * FROM repair_runs WHERE id=?", (identifier,)).fetchone()
        if not row:
            raise TeateError("unknown_repair_run")
        result = {**dict(row), **json.loads(row["data"])}
        result.pop("data")
        result["steps"] = [
            dict(r) | {"data": json.loads(r["data"])}
            for r in self.db.execute(
                "SELECT * FROM repair_steps WHERE run_id=? ORDER BY started_at,name", (identifier,)
            )
        ]
        return result

    def update(self, identifier, status, **values):
        run = self.get(identifier)
        data = {
            k: v
            for k, v in run.items()
            if k not in {"id", "asset_id", "created_at", "updated_at", "status", "steps"}
        }
        data.update(values)
        with self.db:
            self.db.execute(
                "UPDATE repair_runs SET status=?,updated_at=?,data=? WHERE id=?",
                (status, utcnow(), canonical(data), identifier),
            )
        return self.get(identifier)

    def intent(self, identifier, name, data=None):
        # INSERT fails on replay. An unfinished intent must be reconciled first.
        row = self.db.execute("SELECT data FROM repair_runs WHERE id=?", (identifier,)).fetchone()
        body = json.loads(row["data"])
        body["phase"] = name
        with self.db:
            self.db.execute(
                "UPDATE repair_runs SET updated_at=?,data=? WHERE id=?",
                (utcnow(), canonical(body), identifier),
            )
            self.db.execute(
                "INSERT INTO repair_steps VALUES (?,?,?,NULL,?,?)",
                (identifier, name, utcnow(), "running", canonical(data or {})),
            )

    def finish(self, identifier, name, data, *, status="done"):
        with self.db:
            self.db.execute(
                "UPDATE repair_steps SET finished_at=?,status=?,data=? WHERE run_id=? AND name=?",
                (utcnow(), status, canonical(data), identifier, name),
            )

    def history(self, *, identifier=None, asset_id=None):
        if identifier:
            return [self.get(identifier)]
        query = (
            "SELECT id FROM repair_runs"
            + (" WHERE asset_id=?" if asset_id else "")
            + " ORDER BY created_at DESC LIMIT 100"
        )
        return [self.get(r["id"]) for r in self.db.execute(query, (asset_id,) if asset_id else ())]


def load_candidate(state: Path, identifier: str) -> dict:
    import re

    from .model import load_json

    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise TeateError("invalid_repair_job_id")
    path = state / "repairs" / identifier / "result.json"
    if path.is_symlink() or not path.resolve().is_relative_to((state / "repairs").resolve()):
        raise TeateError("unsafe_repair_job_path")
    return load_json(path)
