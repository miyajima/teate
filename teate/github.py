"""GitHub transport and patch-PR gate. No PR code is executed by this module."""

from __future__ import annotations

import base64
import json
import re

from .collect import run
from .model import TeateError, canonical, digest
from .policy import merge_decision


def repository_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise TeateError("Repository must be owner/name")
    return value


def api(
    endpoint: str, *, method: str = "GET", payload: dict | None = None, allow_missing: bool = False
):
    args = ["gh", "api", "--method", method, endpoint]
    if payload is None:
        result = run(args, timeout=60)
    else:
        import subprocess

        try:
            result = subprocess.run(
                [*args, "--input", "-"],
                input=canonical(payload),
                text=True,
                check=False,
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TeateError(
                "GitHub request outcome is unknown; inspect state before retrying a mutation"
            ) from exc
    if result.returncode:
        if allow_missing and "HTTP 404" in result.stderr:
            return None
        raise TeateError("GitHub API failed; check authentication, permissions and remote state")
    return json.loads(result.stdout) if result.stdout.strip() else None


def pages(endpoint: str) -> list:
    records = []
    for page in range(1, 101):
        chunk = api(endpoint + ("&" if "?" in endpoint else "?") + f"per_page=100&page={page}")
        if not isinstance(chunk, list):
            raise TeateError("Unexpected paginated GitHub response")
        records.extend(chunk)
        if len(chunk) < 100:
            return records
    raise TeateError("Pagination limit reached; refusing incomplete GitHub results")


def require_private_repository(repository: str) -> dict:
    """Keep operational evidence out of public repositories, including other branches."""
    repository_name(repository)
    info = api(f"repos/{repository}")
    if (
        not isinstance(info, dict)
        or info.get("private") is not True
        or info.get("full_name", "").casefold() != repository.casefold()
    ):
        raise TeateError("Operational evidence requires a verified private GitHub repository")
    return info


def sync_issues(ledger, repository: str, *, apply: bool = False) -> list[dict]:
    repository_name(repository)
    if apply:
        require_private_repository(repository)
    issues = pages(f"repos/{repository}/issues?state=all")
    by_marker = {}
    for issue in issues:
        if issue.get("pull_request"):
            continue
        for marker in re.findall(r"<!-- teate:([0-9a-f]{24}) -->", issue.get("body") or ""):
            if marker in by_marker:
                raise TeateError("Duplicate Teate issue markers; reconcile before syncing")
            by_marker[marker] = issue
    operations = []
    for finding in ledger.findings():
        asset = ledger.asset(finding["asset_id"])
        resolved = finding["effective_status"] == "resolved"
        existing = by_marker.get(finding["id"])
        if resolved and not existing:
            continue
        title = f"[Teate] {asset['project']} / {asset['environment']}: {finding['advisory_id']} · {finding['package']}"
        # JSON encoding keeps untrusted advisory content out of mentions and Markdown links.
        details = {
            k: finding.get(k)
            for k in (
                "id",
                "advisory_id",
                "package",
                "version",
                "fixed_versions",
                "effective_status",
                "first_seen",
                "last_seen",
                "resolved_at",
            )
        }
        body = f"<!-- teate:{finding['id']} -->\n\n" + "対象資産: `" + asset["id"] + "`\n\n"
        body += (
            "```json\n"
            + json.dumps(details, ensure_ascii=True, indent=2).replace("`", "\\u0060")
            + "\n```\n\n"
        )
        body += "対応完了は、対象環境に一致する完全な再検査で判断します。"
        payload = {"title": title, "body": body, "state": "closed" if resolved else "open"}
        if existing and all(existing.get(k) == value for k, value in payload.items()):
            continue
        operation = {
            "finding_id": finding["id"],
            "action": "update" if existing else "create",
            "payload": payload,
        }
        if apply:
            endpoint = f"repos/{repository}/issues" + (f"/{existing['number']}" if existing else "")
            record = api(endpoint, method="PATCH" if existing else "POST", payload=payload)
            ledger.issue_link(finding["id"], record["html_url"])
            operation["url"] = record["html_url"]
        operations.append(operation)
    return operations


def publish_receipt(repository: str, receipt: dict) -> dict:
    """Append immutable receipts on a dedicated branch, using content-derived names."""
    info = require_private_repository(repository)
    branch = "teate-receipts"
    ref = api(f"repos/{repository}/git/ref/heads/{branch}", allow_missing=True)
    if ref is None:
        main = api(f"repos/{repository}/git/ref/heads/{info['default_branch']}")
        api(
            f"repos/{repository}/git/refs",
            method="POST",
            payload={"ref": "refs/heads/" + branch, "sha": main["object"]["sha"]},
        )
    key = digest(receipt)
    path = f"receipts/{key}.json"
    existing = api(f"repos/{repository}/contents/{path}?ref={branch}", allow_missing=True)
    if existing is not None:
        actual = json.loads(base64.b64decode(existing["content"]))
        if digest(actual) != key:
            raise TeateError("Remote receipt content does not match its id")
        return {"id": key, "duplicate": True, "path": path}
    api(
        f"repos/{repository}/contents/{path}",
        method="PUT",
        payload={
            "message": f"Record Teate evidence {key[:12]}",
            "branch": branch,
            "content": base64.b64encode((canonical(receipt) + "\n").encode()).decode(),
        },
    )
    api(f"repos/{repository}/dispatches", method="POST", payload={"event_type": "teate-receipts"})
    return {"id": key, "duplicate": False, "path": path}


def _file(repository: str, path: str, sha: str) -> dict:
    from urllib.parse import quote

    response = api(f"repos/{repository}/contents/{quote(path, safe='/')}?ref={sha}")
    if response.get("encoding") != "base64" or response.get("type") != "file":
        raise TeateError("Expected a regular JSON dependency file")
    return json.loads(base64.b64decode(response["content"]))


def inspect_patch_pr(repository: str, number: int, policy: dict) -> tuple[dict, dict]:
    repository_name(repository)
    pr = api(f"repos/{repository}/pulls/{number}")
    reasons = []
    sha = pr["head"]["sha"]
    base_sha = pr["base"]["sha"]
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (sha, base_sha)):
        raise TeateError("Unexpected PR commit identity")
    if pr["state"] != "open" or pr.get("draft"):
        reasons.append("PR is not open and ready")
    if pr["base"].get("ref") not in policy.get("automation", {}).get(
        "allowed_base_branches", ["main"]
    ):
        reasons.append("PR target branch is not allowed")
    if (
        pr["head"]["repo"]["full_name"] != repository
        or pr["base"]["repo"]["full_name"] != repository
    ):
        reasons.append("fork or repository identity mismatch")
    files = pages(f"repos/{repository}/pulls/{number}/files")
    if len(files) != pr["changed_files"] or not files:
        reasons.append("incomplete changed-file list")
    packages = []
    for changed in files:
        path = changed["filename"]
        if changed["status"] != "modified" or path.split("/")[-1] not in {
            "package-lock.json",
            "package.json",
        }:
            reasons.append(
                "only modifications to existing npm manifests/lockfiles are supported for auto-merge"
            )
            continue
        before, after = _file(repository, path, base_sha), _file(repository, path, sha)
        if path.endswith("package-lock.json"):
            if before.get("lockfileVersion") not in (2, 3) or after.get(
                "lockfileVersion"
            ) != before.get("lockfileVersion"):
                reasons.append("unsupported lockfile version or migration")
                continue
            old_packages, new_packages = before.get("packages", {}), after.get("packages", {})
            for location in set(old_packages) | set(new_packages):
                old, new = old_packages.get(location), new_packages.get(location)
                if location == "":
                    if _manifest_sensitive(old or {}, new or {}):
                        reasons.append("root manifest changes are sensitive")
                    continue
                if old == new:
                    continue
                if not old or not new or "node_modules/" not in location:
                    reasons.append("dependency graph additions/removals require review")
                    continue
                name = location.rsplit("node_modules/", 1)[1]
                # Same-version integrity/source changes are never routine patch updates.
                packages.append(
                    {"name": name, "from": old.get("version", ""), "to": new.get("version", "")}
                )
                for record in (old, new):
                    source = record.get("resolved", "")
                    if source and not source.startswith("https://registry.npmjs.org/"):
                        reasons.append("nonstandard package source requires review")
                allowed_changes = {"version", "resolved", "integrity"}
                if any(old.get(k) != new.get(k) for k in (set(old) | set(new)) - allowed_changes):
                    reasons.append("package metadata or lifecycle changes require review")
        else:
            if _manifest_sensitive(before, after):
                reasons.append("manifest changes extend beyond existing dependency versions")
            for section in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                for name in set(before.get(section, {})) & set(after.get(section, {})):
                    old_version, new_version = before[section][name], after[section][name]
                    if old_version != new_version:
                        if not all(isinstance(v, str) for v in (old_version, new_version)):
                            reasons.append("invalid dependency specification")
                            continue
                        packages.append(
                            {
                                "name": name,
                                "from": old_version.lstrip("^~"),
                                "to": new_version.lstrip("^~"),
                            }
                        )
    if not packages:
        reasons.append("no verifiable patch updates")
    # Gate publication ages against the registry, never the PR description.
    publication_times = []
    for package in packages:
        publication_times.append(_npm_publication_time(package["name"], package["to"]))
    checks_response = api(f"repos/{repository}/commits/{sha}/check-runs?per_page=100")
    checks = [
        {"name": c["name"], "head_sha": c["head_sha"], "conclusion": c.get("conclusion")}
        for c in checks_response.get("check_runs", [])
        if c.get("app", {}).get("slug") == "github-actions"
    ]
    if checks_response.get("total_count", 0) > len(checks_response.get("check_runs", [])):
        reasons.append("check run list is incomplete")
    update = {
        "author": pr["user"]["login"],
        "packages": packages,
        "head_sha": sha,
        "checks": checks,
        "sensitive_change": bool(reasons),
        "published_at": max(publication_times) if publication_times else None,
    }
    decision = merge_decision(update, policy)
    decision["reasons"] = sorted(set(decision["reasons"] + reasons))
    if decision["reasons"]:
        decision["action"] = "review"
    return update, decision


def _manifest_sensitive(before: dict, after: dict) -> bool:
    sections = {"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
    if {k: v for k, v in before.items() if k not in sections} != {
        k: v for k, v in after.items() if k not in sections
    }:
        return True
    return any(set(before.get(k, {})) != set(after.get(k, {})) for k in sections)


def _npm_publication_time(name: str, version: str) -> str:
    from urllib.parse import quote
    from urllib.request import Request, urlopen

    try:
        request = Request(
            "https://registry.npmjs.org/" + quote(name, safe=""),
            headers={"User-Agent": "Teate/0.1"},
        )
        with urlopen(request, timeout=30) as response:
            data = json.load(response)
        return data["time"][version]
    except (OSError, ValueError, KeyError) as exc:
        raise TeateError("Cannot verify package publication time; auto-merge refused") from exc


def apply_merge(repository: str, number: int, update: dict, decision: dict) -> dict:
    if decision["action"] != "auto_merge":
        raise TeateError("Automatic merge policy did not pass")
    result = run(
        [
            "gh",
            "pr",
            "merge",
            str(number),
            "--repo",
            repository_name(repository),
            "--auto",
            "--squash",
            "--match-head-commit",
            update["head_sha"],
        ],
        timeout=60,
    )
    if result.returncode:
        raise TeateError("GitHub refused auto-merge; inspect branch rules and current PR state")
    return {"action": "auto_merge_requested", "head_sha": update["head_sha"], "pr": number}
