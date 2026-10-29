"""Publish only verified lockfile changes, without pushing local credentials."""

from __future__ import annotations

import base64
from pathlib import Path
from urllib.parse import quote

from .github import api, inspect_patch_pr, pages, repository_name
from .model import TeateError


def branch_name(run):
    return "teate/repair-" + run["id"]


def reconcile(run, asset):
    repository = repository_name(asset["remediation"]["repository"])
    branch = branch_name(run)
    ref = api(f"repos/{repository}/git/ref/heads/{branch}", allow_missing=True)
    if not ref:
        return None
    sha = ref["object"]["sha"]
    commit = api(f"repos/{repository}/git/commits/{sha}")
    record = run["record"]
    if [p["sha"] for p in commit["parents"]] != [record["original_subject"]["revision"]]:
        raise TeateError("published_commit_parent_mismatch")
    # Inspect the entire commit diff, including files outside the selection.
    diff = api(f"repos/{repository}/compare/{record['original_subject']['revision']}...{sha}")
    if diff.get("total_commits") != 1 or {f["filename"] for f in diff.get("files", [])} != set(
        record["changed_files"]
    ):
        raise TeateError("published_commit_scope_mismatch")
    for name in record["changed_files"]:
        data = api(f"repos/{repository}/contents/{quote(name, safe='/')}?ref={sha}")
        if base64.b64decode(data["content"]) != (Path(record["worktree"]) / name).read_bytes():
            raise TeateError("published_candidate_mismatch")
    prs = pages(
        f"repos/{repository}/pulls?state=all&head={quote(repository.split('/')[0] + ':' + branch, safe='')}"
    )
    if len(prs) != 1:
        return {"head_sha": sha, "pr": None, "repository": repository}
    pr = prs[0]
    return {"head_sha": sha, "pr": pr["number"], "repository": repository, "url": pr["html_url"]}


def publish(run, asset):
    repository = repository_name(asset["remediation"]["repository"])
    base = asset["remediation"].get("base_branch", "main")
    record = run["record"]
    ref = api(f"repos/{repository}/git/ref/heads/{quote(base, safe='')}")
    if ref["object"]["sha"] != record["original_subject"]["revision"]:
        raise TeateError("github_base_changed_reprepare")
    commit = api(f"repos/{repository}/git/commits/{ref['object']['sha']}")
    tree = api(
        f"repos/{repository}/git/trees",
        method="POST",
        payload={
            "base_tree": commit["tree"]["sha"],
            "tree": [
                {
                    "path": name,
                    "mode": "100644",
                    "type": "blob",
                    "content": (Path(record["worktree"]) / name).read_text(),
                }
                for name in record["changed_files"]
            ],
        },
    )
    candidate = api(
        f"repos/{repository}/git/commits",
        method="POST",
        payload={
            "message": "Apply verified Teate dependency repair " + run["id"],
            "tree": tree["sha"],
            "parents": [ref["object"]["sha"]],
        },
    )
    branch = branch_name(run)
    api(
        f"repos/{repository}/git/refs",
        method="POST",
        payload={"ref": "refs/heads/" + branch, "sha": candidate["sha"]},
    )
    pr = api(
        f"repos/{repository}/pulls",
        method="POST",
        payload={
            "title": "Apply verified dependency patch",
            "head": branch,
            "base": base,
            "body": "Teate dependency-only repair. Runtime verification remains required.",
        },
    )
    return {
        "repository": repository,
        "head_sha": candidate["sha"],
        "pr": pr["number"],
        "url": pr["html_url"],
    }


def gate(publication, policy):
    repository = publication["repository"]
    pr = api(f"repos/{repository}/pulls/{publication['pr']}")
    if pr["head"]["sha"] != publication["head_sha"]:
        raise TeateError("published_head_changed")
    if pr.get("merged"):
        # Manual/external merging does not waive the configured execution gates.
        automation = policy.get("automation", {})
        checks = api(
            f"repos/{repository}/commits/{publication['head_sha']}/check-runs?per_page=100"
        )
        complete = checks.get("total_count", 0) == len(checks.get("check_runs", []))
        successful = {
            c["name"]
            for c in checks.get("check_runs", [])
            if c.get("head_sha") == publication["head_sha"]
            and c.get("conclusion") == "success"
            and c.get("app", {}).get("slug") == "github-actions"
        }
        required = automation.get("required_checks", [])
        if (
            not complete
            or not required
            or not set(required) <= successful
            or pr.get("user", {}).get("login") not in automation.get("trusted_bots", [])
        ):
            raise TeateError("merged_commit_required_checks_or_author_unconfirmed")
        return {"merged": True, "merge_sha": pr["merge_commit_sha"]}
    update, decision = inspect_patch_pr(repository, publication["pr"], policy)
    if update["head_sha"] != publication["head_sha"]:
        raise TeateError("gate_head_changed")
    return {"merged": False, "update": update, "decision": decision}
