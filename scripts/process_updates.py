#!/usr/bin/env python3
"""Evaluate open update PRs from the explicit inventory, with a commit-specific gate."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from teate.config import load_config
from teate.github import apply_merge, inspect_patch_pr, pages, repository_name
from teate.model import TeateError, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/ci.json")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    policy = config["policy"]
    allowed_authors = policy.get("automation", {}).get("trusted_bots", [])
    records = []
    failed = False
    repositories = sorted(
        {
            repository_name(a["repository"])
            for a in config["assets"]
            if a["kind"] == "source" and a.get("repository") and not a.get("host_id")
        }
    )
    for repository in repositories:
        try:
            for pr in pages(f"repos/{repository}/pulls?state=open"):
                if pr["user"]["login"] not in allowed_authors:
                    continue
                update, decision = inspect_patch_pr(repository, pr["number"], policy)
                record = {"repository": repository, "pr": pr["number"], "decision": decision}
                if args.apply and decision["action"] == "auto_merge":
                    record["result"] = apply_merge(repository, pr["number"], update, decision)
                records.append(record)
        except TeateError as exc:
            failed = True
            records.append({"repository": repository, "status": "blocked", "reason": str(exc)})
    write_json(Path(config["state_dir"]) / "update-decisions.json", records)
    print(json.dumps(records, ensure_ascii=False, indent=2))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
