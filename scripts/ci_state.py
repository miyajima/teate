#!/usr/bin/env python3
"""Persist the ledger on a private state branch; receipts stay immutable and replayable."""

import argparse
import base64
import gzip
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from teate.cli import ingest_file
from teate.config import load_config
from teate.control_state import export as export_control_state
from teate.control_state import restore as restore_control_state
from teate.github import api, repository_name, require_private_repository
from teate.model import TeateError
from teate.store import Ledger


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["restore", "receipts", "save"])
    parser.add_argument("--repository", required=True)
    parser.add_argument("--config", default="config/ci.json")
    args = parser.parse_args()
    name = repository_name(args.repository)
    require_private_repository(name)
    config = load_config(args.config)
    state = Path(config["state_dir"])
    state.mkdir(parents=True, exist_ok=True)
    if args.action == "restore":
        branch = api(f"repos/{name}/git/ref/heads/teate-state", allow_missing=True)
        if branch:
            remote = api(f"repos/{name}/contents/ledger.sqlite3.gz?ref=teate-state")
            if remote.get("encoding") != "base64":
                raise TeateError(
                    "Ledger exceeds Contents API size limit; migrate to a persistent service before continuing"
                )
            target = state / "ledger.sqlite3"
            target.write_bytes(gzip.decompress(base64.b64decode(remote["content"])))
            with sqlite3.connect(target) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise TeateError("Remote ledger integrity check failed")
            controls = api(f"repos/{name}/contents/control-state.json.gz?ref=teate-state", allow_missing=True)
            if controls:
                if controls.get("encoding") != "base64":
                    raise TeateError("Control-state transfer is incomplete")
                restore_control_state(state, base64.b64decode(controls["content"]))
        return
    if args.action == "receipts":
        branch = api(f"repos/{name}/git/ref/heads/teate-receipts", allow_missing=True)
        if not branch:
            return
        tree = api(f"repos/{name}/git/trees/{branch['object']['sha']}?recursive=1")
        if tree.get("truncated"):
            raise TeateError("Receipt tree is truncated; refusing an incomplete replay")
        ledger = Ledger(state / "ledger.sqlite3")
        ledger.register(config["assets"])
        known = {a["id"] for a in config["assets"]}
        try:
            for item in tree["tree"]:
                if (
                    item["type"] != "blob"
                    or not item["path"].startswith("receipts/")
                    or not item["path"].endswith(".json")
                ):
                    continue
                blob = api(f"repos/{name}/git/blobs/{item['sha']}")
                value = json.loads(base64.b64decode(blob["content"]))
                if value.get("asset_id") not in known:
                    print(
                        "Unregistered asset receipt remains pending inventory registration",
                        file=sys.stderr,
                    )
                    continue
                ingest_file(ledger, value)
        finally:
            ledger.close()
        return
    # Single serialized CI job writes all state files in one Git tree and one commit.
    ref = api(f"repos/{name}/git/ref/heads/teate-state", allow_missing=True)
    parent = ref["object"]["sha"] if ref else None
    entries = []
    control = export_control_state(state)
    for filename in ("ledger.sqlite3", "summary.json", "report.md", "control-state.json.gz"):
        file = state / filename
        if filename != "control-state.json.gz" and not file.exists():
            raise TeateError(f"Missing state output: {filename}")
        content = control if filename == "control-state.json.gz" else (
            gzip.compress(file.read_bytes(), mtime=0)
            if filename.endswith("sqlite3")
            else file.read_bytes()
        )
        remote_name = filename + ".gz" if filename.endswith("sqlite3") else filename
        if len(content) > 900_000:
            raise TeateError(
                "State is nearing the v1 transport limit; migrate storage rather than discard history"
            )
        blob = api(
            f"repos/{name}/git/blobs",
            method="POST",
            payload={"content": base64.b64encode(content).decode(), "encoding": "base64"},
        )
        entries.append({"path": remote_name, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    tree = api(f"repos/{name}/git/trees", method="POST", payload={"tree": entries})
    commit = api(
        f"repos/{name}/git/commits",
        method="POST",
        payload={
            "message": "Record Teate assessment",
            "tree": tree["sha"],
            "parents": [parent] if parent else [],
        },
    )
    if parent:
        api(
            f"repos/{name}/git/refs/heads/teate-state",
            method="PATCH",
            payload={"sha": commit["sha"], "force": False},
        )
    else:
        api(
            f"repos/{name}/git/refs",
            method="POST",
            payload={"ref": "refs/heads/teate-state", "sha": commit["sha"]},
        )
    print("Persisted ledger and report on teate-state")


if __name__ == "__main__":
    main()
