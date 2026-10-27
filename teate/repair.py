"""Prepare narrow npm patches in isolation; never merge or resolve live findings."""

from __future__ import annotations

import difflib
import json
import platform
import re
import urllib.parse
import urllib.request
import uuid
from pathlib import Path, PurePosixPath

from . import sandbox
from . import source as sources
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
            version["name"] != package
            or version["version"] != target
            or tarball.scheme != "https"
            or tarball.netloc != "registry.npmjs.org"
            or tarball.query
            or tarball.fragment
            or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", dist["integrity"])
        ):
            raise ValueError("unexpected registry identity")
        return {"version": version, "published_at": published}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TeateError("Official npm metadata unavailable or unsupported") from exc


def _git(root: Path, *args: str) -> str:
    result = run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "submodule.recurse=false",
            "-C",
            str(root),
            *args,
        ]
    )
    if result.returncode:
        raise TeateError("Git preparation failed; no live update was applied")
    return result.stdout


def _lock(root: Path, location: str) -> tuple[Path, dict]:
    relative = PurePosixPath(location)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.name != "package-lock.json"
        or "node_modules" in relative.parts
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


def validate_lock(
    before: dict, after: dict, selected: list[dict], target: str, metadata: dict
) -> None:
    """Validate an OSS-produced change; never resolve or write a lockfile ourselves."""
    allowed = {f["package"]: f["version"] for f in selected}
    if after.get("lockfileVersion") != 3 or before.keys() != after.keys():
        raise TeateError("unsupported_lockfile_change")
    if {k: v for k, v in before.items() if k != "packages"} != {
        k: v for k, v in after.items() if k != "packages"
    }:
        raise TeateError("lockfile_root_changed")
    old, new = before["packages"], after.get("packages", {})
    if old.keys() != new.keys():
        raise TeateError("dependency_graph_changed")
    changed = 0
    for location, record in old.items():
        other = new[location]
        if record == other:
            continue
        name = location.rsplit("node_modules/", 1)[-1]
        if "node_modules/" not in location or name not in allowed:
            raise TeateError("unselected_package_changed")
        if (
            record.get("version") != allowed[name]
            or other.get("version") != target
            or not is_patch_update(allowed[name], target)
        ):
            raise TeateError("only_stable_same_major_minor_patch_supported")
        if not record.get("resolved", "").startswith("https://registry.npmjs.org/"):
            raise TeateError("nonstandard_original_package_source")
        version = metadata[name]["version"]
        if version.get("name") != name or version.get("version") != target:
            raise TeateError("registry_identity_changed")
        for entry in (record, other, version):
            if any(
                entry.get(k)
                for k in (
                    "dependencies",
                    "optionalDependencies",
                    "peerDependencies",
                    "bin",
                    "bundledDependencies",
                    "bundleDependencies",
                    "os",
                    "cpu",
                    "libc",
                    "hasInstallScript",
                    "link",
                )
            ):
                raise TeateError("package_graph_lifecycle_platform_requires_review")
        if any(
            k in version.get("scripts", {})
            for k in ("preinstall", "install", "postinstall", "prepare")
        ):
            raise TeateError("package_install_lifecycle_requires_review")
        fields = {"version", "resolved", "integrity"}
        if {k: v for k, v in record.items() if k not in fields} != {
            k: v for k, v in other.items() if k not in fields
        }:
            raise TeateError("package_metadata_changed")
        if any(record.get(k) != version.get(k) for k in ("license", "engines")):
            raise TeateError("package_metadata_changed")
        dist = version["dist"]
        if other.get("resolved") != dist["tarball"] or other.get("integrity") != dist["integrity"]:
            raise TeateError("registry_integrity_mismatch")
        changed += 1
    if not changed:
        raise TeateError("no_supported_patch_change")


def backend(root: Path, location: str, selected: list[dict], scanner: str) -> dict:
    cwd = (root / location).parent
    if scanner == "npm-audit":
        argv = [
            "npm",
            "audit",
            "fix",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-fund",
            "--registry=https://registry.npmjs.org",
        ]
        network = "npm"
    elif scanner == "osv":
        argv = [
            "osv-scanner",
            "fix",
            "--strategy=in-place",
            "--format=json",
            "-L",
            str(root / location),
            "-M",
            str(cwd / "package.json"),
            "--upgrade-config=none",
            "--no-introduce",
        ]
        for name in sorted({f["package"] for f in selected}):
            argv += ["--upgrade-config=" + name + ":patch"]
        for advisory in sorted({f["advisory_id"] for f in selected}):
            argv += ["--vulns=" + advisory]
        network = "osv"
    else:
        raise TeateError("unsupported_repair_scanner")
    result = sandbox.execute(root, argv, cwd=cwd, network=network)
    # npm exits 1 when other advisories remain. Full diff validation and same-scope
    # rescans, not the exit code alone, decide whether a candidate is acceptable.
    if (
        result.get("exit_code") not in (0, 1)
        or result.get("timed_out")
        or result["status"] == "blocked"
    ):
        raise TeateError(result.get("reason") or "repair_backend_unavailable_or_failed")
    return result


def verified_scans(scans: list[dict], baseline: list[dict], items: list[dict]) -> None:
    expected = {f["scope"] for f in items}
    complete = {s["scope"] for s in scans if s["status"] == "success" and s["complete"]}
    if not expected <= complete:
        raise TeateError("Candidate scope could not be verified")
    old = {
        (f.get("location", s["scope"]), f["advisory_id"], f["package"])
        for s in baseline
        for f in s["findings"]
    }
    new = {
        (f.get("location", s["scope"]), f["advisory_id"], f["package"])
        for s in scans
        for f in s["findings"]
    }
    if new - old:
        raise TeateError("Candidate introduced additional findings")
    if new & {(f["location"], f["advisory_id"], f["package"]) for f in items}:
        raise TeateError("Candidate did not remove the target finding")


def prepare(
    ledger,
    policy: dict,
    state: Path,
    finding_ids: list[str],
    target: str,
    *,
    metadata_cache: dict | None = None,
    scanner: str = "npm-audit",
) -> dict:
    if (
        not finding_ids
        or len(finding_ids) > MAX_FINDINGS
        or len(set(finding_ids)) != len(finding_ids)
    ):
        raise TeateError("Select one to five distinct finding IDs")
    if not re.fullmatch(r"\d+\.\d+\.\d+", target):
        raise TeateError("An explicit stable target version is required")
    findings = {f["id"]: f for f in ledger.findings()}
    items = []
    for identifier in finding_ids:
        f = findings.get(identifier)
        if (
            not f
            or f["effective_status"] in {"resolved", "accepted_risk"}
            or f.get("malicious")
            or f["ecosystem"] != "npm"
        ):
            raise TeateError("Finding missing or requires manual investigation")
        if f["scanner"] != scanner or not is_patch_update(f["version"], target):
            raise TeateError("Finding scanner/version does not match repair backend")
        items.append(f)
    job = state.resolve() / "repairs" / uuid.uuid4().hex
    job.mkdir(parents=True)
    records = []
    metadata = {} if metadata_cache is None else dict(metadata_cache)
    for asset_id in dict.fromkeys(f["asset_id"] for f in items):
        selected = [f for f in items if f["asset_id"] == asset_id]
        record = {
            "asset_id": asset_id,
            "finding_ids": [f["id"] for f in selected],
            "status": "review",
            "live_applied": False,
            "resolved": False,
            "scanner": scanner,
        }
        records.append(record)
        try:
            asset = ledger.asset(asset_id)
            if (
                asset["kind"] != "source"
                or asset.get("host_id", platform.node()) != platform.node()
            ):
                raise TeateError("Asset is not a source on this verified host")
            root = Path(asset["path"]).resolve()
            if (root / ".git").exists():
                if _git(root, "status", "--porcelain", "--untracked-files=normal").strip():
                    raise TeateError("Source checkout has local changes; review required")
                filters = run(
                    ["git", "-C", str(root), "config", "--name-only", "--get-regexp", r"^filter\."]
                )
                if filters.returncode not in (0, 1) or filters.stdout.strip():
                    raise TeateError("Configured checkout filters require manual preparation")
            original = source_subject(root)
            baseline = scan_source(asset, scanner=scanner)
            directory = job / digest(asset_id)[:16]
            directory.mkdir()
            write_json(directory / "baseline.json", baseline)
            for f in selected:
                _lock(root, f["location"])
                scopes = [s for s in baseline if s["scope"] == f["scope"]]
                if not scopes or not all(
                    s["status"] == "success" and s["complete"] for s in scopes
                ):
                    raise TeateError("Baseline scope could not be verified")
                if not any(
                    v["package"] == f["package"] and v["advisory_id"] == f["advisory_id"]
                    for s in scopes
                    for v in s["findings"]
                ):
                    raise TeateError("Finding changed since the ledger scan")
                if f["package"] not in metadata:
                    metadata[f["package"]] = registry(f["package"], target)
            worktree = directory / "worktree"
            before = sources.copy(root, worktree)
            backend_results = []
            record["backend"] = backend_results
            for location in sorted({f["location"] for f in selected}):
                _, old = _lock(root, location)
                local = [f for f in selected if f["location"] == location]
                backend_results.append(backend(worktree, location, local, scanner))
                _, new = _lock(worktree, location)
                validate_lock(old, new, local, target, metadata)
            changed = sources.changes(before, sources.files(worktree, include_private=True))
            if not changed or set(changed) - {f["location"] for f in selected}:
                raise TeateError("unauthorized_candidate_file_change")
            if any(
                before[p].split(":")[-1]
                != sources.files(worktree, include_private=True)[p].split(":")[-1]
                for p in changed
            ):
                raise TeateError("candidate_file_mode_changed")
            if sources.files(root) != before or source_subject(root) != original:
                raise TeateError("Source changed during candidate preparation")
            scans = scan_source({**asset, "path": str(worktree)}, scanner=scanner)
            write_json(directory / "candidate-scan.json", scans)
            verified_scans(scans, baseline, selected)
            if sources.files(root) != before:
                raise TeateError("Source changed during candidate verification")
            diff = "".join(
                "".join(
                    difflib.unified_diff(
                        (root / name).read_text().splitlines(True),
                        (worktree / name).read_text().splitlines(True),
                        fromfile="a/" + name,
                        tofile="b/" + name,
                    )
                )
                for name in changed
            )
            (directory / "candidate.patch").write_text(diff)
            update = {
                "author": None,
                "head_sha": None,
                "checks": [],
                "sensitive_change": False,
                "packages": [
                    {"name": f["package"], "from": f["version"], "to": target} for f in selected
                ],
                "published_at": max(metadata[f["package"]]["published_at"] for f in selected),
            }
            record.update(
                status="candidate_ready",
                worktree=str(worktree),
                patch=str(directory / "candidate.patch"),
                original_subject=original,
                source_files=before,
                candidate_files=sources.files(worktree, include_private=True),
                subject=source_subject(worktree),
                target=target,
                metadata={f["package"]: metadata[f["package"]] for f in selected},
                policy_id=digest(policy),
                asset_id_at_prepare=digest(asset),
                backend=backend_results,
                changed_files=changed,
                update=update,
                target_scopes_verified=len({f["scope"] for f in selected}),
                unverified_scopes=[
                    s["scope"] for s in scans if s["status"] != "success" or not s["complete"]
                ],
                merge_decision=merge_decision(update, policy),
                tests="pending_project_tests_and_commit_specific_CI",
            )
            for f in selected:
                ledger.mark(f["id"], "proposed", "Isolated repair candidate: " + job.name)
        except (TeateError, OSError, ValueError, KeyError, TypeError) as exc:
            record["reason"] = str(exc) if isinstance(exc, TeateError) else type(exc).__name__
    result = {
        "schema_version": 2,
        "created_at": utcnow(),
        "job": str(job),
        "job_id": job.name,
        "requires_review": True,
        "live_applied": False,
        "results": records,
    }
    write_json(job / "result.json", result)
    return result
