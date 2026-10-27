"""Prepare narrow npm patches in isolation; never merge or resolve live findings."""

from __future__ import annotations

import copy
import json
import platform
import re
import urllib.parse
import urllib.request
import uuid
from pathlib import Path, PurePosixPath

from .collect import run, scan_source, source_subject
from .model import TeateError, digest, timestamp, utcnow, write_json
from .policy import is_patch_update, merge_decision

MAX_FINDINGS = 5


def registry(package: str, target: str) -> dict:
    if not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", package):
        raise TeateError("Unsupported npm package name")
    url = "https://registry.npmjs.org/" + urllib.parse.quote(package, safe="")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if urllib.parse.urlsplit(response.geturl()).hostname != "registry.npmjs.org":
                raise ValueError("unexpected registry redirect")
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("registry record too large")
        data = json.loads(raw)
        version = data["versions"][target]
        published = data["time"][target]
        timestamp(published)
        dist = version["dist"]
        tarball = urllib.parse.urlsplit(dist["tarball"])
        if (
            version["name"] != package or version["version"] != target
            or tarball.scheme != "https" or tarball.netloc != "registry.npmjs.org"
            or tarball.query or tarball.fragment
            or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", dist["integrity"])
        ):
            raise ValueError("unexpected registry identity")
        return {"version": version, "published_at": published}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TeateError("Official npm metadata unavailable or unsupported") from exc


def _git(root: Path, *args: str) -> str:
    result = run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                  "-c", "submodule.recurse=false", "-C", str(root), *args])
    if result.returncode:
        raise TeateError("Git preparation failed; no live update was applied")
    return result.stdout


def _lock(root: Path, location: str) -> tuple[Path, dict]:
    relative = PurePosixPath(location)
    if (
        relative.is_absolute() or ".." in relative.parts
        or relative.name != "package-lock.json" or "node_modules" in relative.parts
    ):
        raise TeateError("Only existing project package-lock.json files are supported")
    path = root / location
    current = path
    while current != root:
        if current.is_symlink():
            raise TeateError("Symlink lockfile paths require review")
        current = current.parent
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise TeateError("Cannot read the finding's lockfile") from exc
    if data.get("lockfileVersion") != 3 or not isinstance(data.get("packages"), dict):
        raise TeateError("Local repair currently supports npm lockfile version 3")
    return path, data


def _patch_lock(data: dict, package: str, current: str, metadata: dict) -> dict:
    version = metadata["version"]
    target = version["version"]
    if not is_patch_update(current, target):
        raise TeateError("Only stable same-major/minor patch candidates are supported")
    result = copy.deepcopy(data)
    locations = [p for p in result["packages"] if p.endswith("node_modules/" + package)]
    if not locations:
        raise TeateError("Package is missing from the lockfile")
    # Do not guess about dependency graph, executable, lifecycle or platform changes.
    for key in ("dependencies", "optionalDependencies", "peerDependencies", "bin",
                "bundledDependencies", "bundleDependencies", "os", "cpu", "libc"):
        if version.get(key):
            raise TeateError("Package graph/lifecycle/platform metadata requires review")
    if any(name in version.get("scripts", {}) for name in
           ("preinstall", "install", "postinstall", "prepare")):
        raise TeateError("Package install lifecycle requires review")
    for location in locations:
        old = result["packages"][location]
        if old.get("version") != current:
            raise TeateError("Multiple installed versions require review")
        if any(old.get(k) != version.get(k) for k in ("license", "engines")):
            raise TeateError("Package metadata changed; review required")
        if not old.get("resolved", "").startswith("https://registry.npmjs.org/"):
            raise TeateError("Nonstandard package source requires review")
        if old.get("hasInstallScript") or old.get("link"):
            raise TeateError("Executable lifecycle/link metadata requires review")
        if any(old.get(k) for k in ("dependencies", "optionalDependencies", "peerDependencies", "bin")):
            raise TeateError("Only leaf dependencies are supported for local repair")
        for record in result["packages"].values():
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                requirement = record.get(section, {}).get(package)
                if requirement is None:
                    continue
                match = re.fullmatch(r"[~^](\d+)\.(\d+)\.(\d+)", requirement)
                wanted = tuple(map(int, match.groups())) if match else None
                actual = tuple(map(int, target.split(".")))
                if not wanted or wanted[0] == 0 or wanted[:2] != actual[:2] or wanted > actual:
                    raise TeateError("Unsupported or pinned dependency constraint requires review")
        old.update(version=target, resolved=version["dist"]["tarball"],
                   integrity=version["dist"]["integrity"])
    return result


def prepare(ledger, policy: dict, state: Path, finding_ids: list[str], target: str) -> dict:
    if not finding_ids or len(finding_ids) > MAX_FINDINGS or len(set(finding_ids)) != len(finding_ids):
        raise TeateError("Select one to five distinct finding IDs")
    if not re.fullmatch(r"\d+\.\d+\.\d+", target):
        raise TeateError("An explicit stable target version is required")
    findings = {f["id"]: f for f in ledger.findings()}
    selected = []
    for identifier in finding_ids:
        finding = findings.get(identifier)
        if not finding or finding["effective_status"] in {"resolved", "accepted_risk"}:
            raise TeateError("Finding is missing, resolved or accepted risk")
        if finding.get("malicious") or finding["ecosystem"] != "npm":
            raise TeateError("This finding requires manual investigation")
        selected.append(finding)
    job = state.resolve() / "repairs" / uuid.uuid4().hex
    job.mkdir(parents=True)
    records, metadata_cache = [], {}
    for asset_id in dict.fromkeys(f["asset_id"] for f in selected):
        items = [f for f in selected if f["asset_id"] == asset_id]
        record = {"asset_id": asset_id, "finding_ids": [f["id"] for f in items],
                  "status": "review", "live_applied": False, "resolved": False}
        records.append(record)
        try:
            asset = ledger.asset(asset_id)
            if asset["kind"] != "source" or asset.get("host_id", platform.node()) != platform.node():
                raise TeateError("Asset is not a source on this verified host")
            source = Path(asset["path"]).resolve()
            if _git(source, "status", "--porcelain", "--untracked-files=normal").strip():
                raise TeateError("Source checkout has local changes; review required")
            # A worktree checkout must not invoke configured external content filters.
            filters = run(["git", "-C", str(source), "config", "--name-only",
                           "--get-regexp", r"^filter\."])
            if filters.returncode not in (0, 1) or filters.stdout.strip():
                raise TeateError("Configured checkout filters require manual preparation")
            original = source_subject(source)
            baseline = scan_source(asset, scanner="npm-audit")
            directory = job / digest(asset_id)[:16]
            directory.mkdir()
            write_json(directory / "baseline.json", baseline)
            for f in items:
                _, old = _lock(source, f.get("location", ""))
                scans = [s for s in baseline if s["scope"] == f["location"]]
                if not scans or not all(s["status"] == "success" and s["complete"] for s in scans):
                    raise TeateError("Baseline scope could not be verified")
                if not any(v["advisory_id"] == f["advisory_id"] and v["package"] == f["package"]
                           for s in scans for v in s["findings"]):
                    raise TeateError("Finding changed since the ledger scan; rescan the live asset")
                if f["package"] not in metadata_cache:
                    metadata_cache[f["package"]] = registry(f["package"], target)
                _patch_lock(old, f["package"], f["version"], metadata_cache[f["package"]])
            write_json(directory / "registry.json", {
                f["package"]: metadata_cache[f["package"]] for f in items
            })
            worktree = directory / "worktree"
            _git(source, "worktree", "add", "--detach", str(worktree), original["revision"])
            for f in items:
                path, data = _lock(worktree, f["location"])
                patched = _patch_lock(data, f["package"], f["version"], metadata_cache[f["package"]])
                path.write_text(json.dumps(patched, indent=2) + "\n")
            if source_subject(source) != original or _git(source, "status", "--porcelain").strip():
                raise TeateError("Source changed during preparation; review required")
            candidate = {**asset, "path": str(worktree)}
            scans = scan_source(candidate, scanner="npm-audit")
            write_json(directory / "candidate.json", scans)
            before_ids = {(s["scope"], v["advisory_id"], v["package"])
                          for s in baseline for v in s["findings"]}
            new_ids = {(s["scope"], v["advisory_id"], v["package"])
                       for s in scans for v in s["findings"]} - before_ids
            if new_ids:
                raise TeateError("Candidate scan introduced additional findings")
            for f in items:
                scoped = [s for s in scans if s["scope"] == f["location"]]
                if not scoped or not all(s["status"] == "success" and s["complete"] for s in scoped):
                    raise TeateError("Candidate scope could not be verified")
                if any(v["advisory_id"] == f["advisory_id"] and v["package"] == f["package"]
                       for s in scoped for v in s["findings"]):
                    raise TeateError("Candidate did not remove the target finding")
            if source_subject(source) != original:
                raise TeateError("Source changed during candidate verification; review required")
            patch = _git(worktree, "diff", "--no-ext-diff", "--no-textconv", "--binary")
            (directory / "candidate.patch").write_text(patch)
            update = {"author": None, "head_sha": None, "checks": [], "sensitive_change": False,
                      "packages": [{"name": f["package"], "from": f["version"], "to": target}
                                   for f in items],
                      "published_at": max(metadata_cache[f["package"]]["published_at"] for f in items)}
            record.update(status="candidate_ready", worktree=str(worktree),
                          patch=str(directory / "candidate.patch"),
                          subject=source_subject(worktree),
                          target_scopes_verified=len({f["location"] for f in items}),
                          unverified_scopes=[s["scope"] for s in scans
                                             if s["status"] != "success" or not s["complete"]],
                          merge_decision=merge_decision(update, policy),
                          tests="pending_project_tests_and_commit_specific_CI")
            for f in items:
                ledger.mark(f["id"], "proposed", "Teate prepared an isolated candidate: " + str(job))
        except (TeateError, OSError, ValueError, KeyError, TypeError) as exc:
            record["status"] = "review"
            record["reason"] = str(exc) if isinstance(exc, TeateError) else type(exc).__name__
    result = {"schema_version": 1, "created_at": utcnow(), "job": str(job),
              "requires_review": True, "live_applied": False, "results": records}
    write_json(job / "result.json", result)
    return result
