"""Deterministic fixes first; expensive model work is a separate, bounded queue."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import intel, repair
from .collect import scan_source, source_subject
from .model import TeateError, digest, load_json, timestamp, utcnow, write_json
from .policy import is_patch_update, plan
from .verification import verify

MAX_FINDINGS = 5


def _tree_id(root: Path) -> str | None:
    """Include ignored/untracked test inputs; an unbounded tree is never cacheable."""
    result, count, size = hashlib.sha256(), 0, 0
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d != ".git")
        if any((Path(current)/d).is_symlink() for d in directories):
            return None
        for name in sorted(names):
            if name == ".git":
                continue
            path = Path(current)/name
            if path.is_symlink():
                return None
            count += 1
            size += path.stat().st_size
            if count > 10_000 or size > 64_000_000:
                return None
            result.update(str(path.relative_to(root)).encode()+b"\x00")
            with path.open("rb") as file:
                while chunk := file.read(65536):
                    result.update(chunk)
    return result.hexdigest()


def _read(path: Path) -> dict:
    try:
        value = load_json(path) if path.exists() else {}
        return value if isinstance(value, dict) else {}
    except TeateError:
        return {}


def _scan_candidate(ledger, record: dict, findings: list[dict], filename: str) -> bool:
    asset = ledger.asset(record["asset_id"])
    path = Path(record["worktree"])
    scans = scan_source({**asset, "path": str(path)}, scanner="npm-audit")
    selected = [f for f in findings if f["asset_id"] == asset["id"]]
    scopes = {f["location"] for f in selected}
    actual = {s["scope"] for s in scans if s["status"] == "success" and s["complete"]}
    live = {(f["location"], f["advisory_id"], f["package"]) for f in ledger.findings()
            if f["asset_id"] == asset["id"] and f["effective_status"] != "resolved"}
    target = {(f["location"], f["advisory_id"], f["package"]) for f in selected}
    remaining = {(s["scope"], v["advisory_id"], v["package"]) for s in scans for v in s["findings"]}
    write_json(path.parent/filename, {"checked_at": utcnow(), "scans": scans})
    return scopes <= actual and not (remaining & target) and not (remaining - live)


def _cached(ledger, entry: dict, findings: list[dict], state: Path) -> dict | None:
    try:
        if datetime.now(UTC) - timestamp(entry["created_at"]) > timedelta(hours=24):
            return None
        result = entry["result"]
        for record in result["results"]:
            path = Path(record["worktree"])
            if not path.resolve().is_relative_to((state/"repairs").resolve()) or path.is_symlink():
                return None
            if source_subject(path) != record["subject"]:
                return None
            tree = _tree_id(path)
            if tree is None or tree != entry["tree_ids"][record["asset_id"]]:
                return None
            patch = repair._git(path, "diff", "--no-ext-diff", "--no-textconv", "--binary")
            if digest(patch) != entry["patch_ids"][record["asset_id"]]:
                return None
            if not _scan_candidate(ledger, record, findings, "cached-recheck.json"):
                return None
        return result
    except (KeyError, TypeError, ValueError, OSError):
        return None


def run(ledger, policy: dict, state: Path, *, prepare: bool = False, catalog: dict | None = None) -> dict:
    root = state/"autopilot"
    catalog = {} if catalog is None else catalog
    index = _read(root/"cache.json")
    findings = [f for f in ledger.findings()
                if f["effective_status"] not in {"resolved", "accepted_risk"}]
    order = {a["finding_id"]: i for i, a in enumerate(plan(findings, ledger.assets(), policy))}
    findings.sort(key=lambda f: order[f["id"]])
    chosen = findings[:MAX_FINDINGS]
    groups, recipes, decisions = {}, {}, []
    for finding in chosen:
        key = (finding["ecosystem"], finding["package"], finding["version"], finding["advisory_id"])
        groups.setdefault(key, []).append(finding)
    counts = {"groups": len(groups), "candidate_findings": 0, "reused_groups": 0,
              "tests_passed": 0, "tests_pending": 0, "llm_needed": 0, "llm_calls": 0,
              "omitted_findings": max(0, len(findings)-MAX_FINDINGS)}
    for key, items in groups.items():
        first = items[0]
        decision = {"case_id": digest(key)[:24], "finding_ids": [f["id"] for f in items],
                    "package": first["package"], "version": first["version"],
                    "advisory_id": first["advisory_id"], "status": "review", "needs_llm": False}
        decisions.append(decision)
        try:
            if first.get("malicious") or first["ecosystem"] != "npm":
                decision["reason"] = "manual_security_or_unsupported_ecosystem_review"
                continue
            official = catalog.get((first["package"],first["advisory_id"]))
            sources = [official] if official else []
            versions = sorted({v for f in items for v in f.get("fixed_versions", [])})
            if not versions:
                upstream = intel.resolve(first,catalog)
                if upstream is None:
                    raise TeateError("structured_advisory_unconfirmed")
                sources.append(upstream)
                versions = upstream["fixed_versions"]
            targets = sorted({v for v in versions if isinstance(v, str) and is_patch_update(first["version"], v)},
                             key=lambda v: tuple(map(int, v.lstrip("v").split("."))))
            if not targets:
                decision.update(reason="no_supported_patch_fix", needs_llm=True, sources=sources)
                continue
            target = targets[0].lstrip("v")
            metadata_key = (first["package"], target)
            if metadata_key not in recipes:
                recipes[metadata_key] = repair.registry(*metadata_key)
            metadata = recipes[metadata_key]
            assets = [ledger.asset(i) for i in dict.fromkeys(f["asset_id"] for f in items)]
            subjects = {a["id"]: source_subject(Path(a["path"])) for a in assets}
            evidence = {"findings": [{k: f.get(k) for k in ("id", "asset_id", "package", "version", "location", "advisory_id")} for f in items],
                        "subjects": subjects, "assets": assets, "policy": policy,
                        "metadata": metadata, "sources": sources}
            identifier = digest(evidence)
            semantic = {**evidence, "subjects": {i:{k:v for k,v in s.items() if k != "host_id"} for i,s in subjects.items()}}
            decision.update(target=target, sources=sources, evidence_id=identifier,
                            change_id=digest(semantic), evidence_inputs=evidence)
            if not prepare:
                decision.update(status="fix_identified", reason="candidate_preparation_not_requested")
                continue
            saved = _cached(ledger, index.get(identifier, {}), items, state)
            result = saved or repair.prepare(ledger, policy, state, [f["id"] for f in items], target,
                                              metadata_cache={first["package"]: metadata})
            if saved:
                counts["reused_groups"] += 1
            for record in result["results"]:
                if record["status"] != "candidate_ready":
                    continue
                if not saved:
                    try:
                        record["verification"] = verify(ledger.asset(record["asset_id"]), record)
                    except (TeateError, OSError, ValueError, KeyError, TypeError) as exc:
                        record["verification"] = {"status": "blocked", "reason": str(exc) if isinstance(exc, TeateError) else type(exc).__name__, "checks": []}
                status = record["verification"]["status"]
                if not saved:
                    path = Path(record["worktree"])
                    if source_subject(path) != record["subject"] or repair._git(path,"diff","--no-ext-diff","--no-textconv","--binary") != Path(record["patch"]).read_text():
                        record.update(status="review", reason="test_execution_changed_candidate")
                    elif status == "passed" and not _scan_candidate(ledger,record,items,"post-test-recheck.json"):
                        record.update(status="review", reason="post_test_scan_not_verified")
                if status == "failed":
                    decision["needs_llm"] = True
                if record["status"] != "candidate_ready":
                    continue
                counts["candidate_findings"] += len(record["finding_ids"])
                counts["tests_passed" if status == "passed" else "tests_pending"] += 1
            decision.update(status="candidate_prepared" if all(r["status"] == "candidate_ready" for r in result["results"]) else "review",
                            result=result)
            if all(r["status"] == "candidate_ready" for r in result["results"]):
                index[identifier] = {"created_at": index[identifier]["created_at"] if saved else utcnow(), "result": result,
                                     "tree_ids": {r["asset_id"]: _tree_id(Path(r["worktree"])) for r in result["results"]},
                                     "patch_ids": {r["asset_id"]: digest(repair._git(Path(r["worktree"]), "diff", "--no-ext-diff", "--no-textconv", "--binary")) for r in result["results"]}}
        except (TeateError, OSError, KeyError, ValueError, TypeError) as exc:
            decision["reason"] = str(exc) if isinstance(exc, TeateError) else type(exc).__name__
            # Missing auth, connectivity, tools or permissions are operational blockers.
    counts["llm_needed"] = sum(d["needs_llm"] for d in decisions)
    signal = [{k: d.get(k) for k in ("case_id", "target", "status", "reason", "change_id")} for d in decisions]
    previous = _read(root/"result.json")
    identity = digest({"decisions": signal, "policy": policy,
                       "coverage": [{"id": c["asset"]["id"], "status": c["status"], "problems": c["problems"]}
                                    for c in ledger.coverage(policy.get("max_scan_age_hours", 48))]})
    result = {"schema_version": 1, "checked_at": utcnow(), "content_id": identity,
              "changed": previous.get("content_id") != identity, "counts": counts,
              "decisions": decisions}
    write_json(root/"cache.json", dict(list(index.items())[-100:]))
    write_json(root/"result.json", result)
    return result
