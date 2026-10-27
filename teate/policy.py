"""Deterministic decisions. An LLM or an advisory body cannot grant execution rights."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from .model import timestamp


def priority(finding: dict, asset: dict) -> str:
    if finding.get("kev") or finding.get("malicious"):
        return "urgent"
    severity = finding.get("severity", "UNKNOWN")
    if severity == "CRITICAL" and asset.get("exposure") == "public":
        return "urgent"
    if severity in {"CRITICAL", "HIGH"}:
        return "high"
    return "normal"


def due_at(finding: dict, asset: dict, policy: dict) -> str:
    level = priority(finding, asset)
    hours = policy.get("deadline_hours", {}).get(
        level, {"urgent": 24, "high": 168, "normal": 720}[level]
    )
    return (timestamp(finding["first_seen"]) + timedelta(hours=hours)).isoformat()


def is_patch_update(current: str, target: str) -> bool:
    pattern = r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    left, right = re.fullmatch(pattern, current), re.fullmatch(pattern, target)
    if not left or not right:
        return False
    a, b = tuple(map(int, left.groups())), tuple(map(int, right.groups()))
    return a[:2] == b[:2] and b[2] > a[2]


def merge_decision(update: dict, policy: dict) -> dict:
    reasons = []
    automation = policy.get("automation", {})
    if not automation.get("enabled", False):
        reasons.append("automatic merge is disabled")
    if update.get("author") not in automation.get("trusted_bots", ["renovate[bot]"]):
        reasons.append("PR author is not a trusted update bot")
    packages = update.get("packages", [])
    allowed = set(automation.get("allowed_packages", []))
    if not packages or any(p.get("name") not in allowed for p in packages):
        reasons.append("every updated package must be explicitly allowed")
    if any(not is_patch_update(p.get("from", ""), p.get("to", "")) for p in packages):
        reasons.append("only stable patch updates within the same major/minor are allowed")
    if update.get("sensitive_change", True):
        reasons.append("change scope has not been verified as dependency-only")
    required = automation.get("required_checks", [])
    sha = update.get("head_sha")
    checks = update.get("checks", [])
    if not required:
        reasons.append("required checks must be configured")
    for name in required:
        matches = [
            c
            for c in checks
            if c.get("name") == name
            and c.get("head_sha") == sha
            and c.get("conclusion") == "success"
        ]
        if not sha or not matches:
            reasons.append(f"required check missing/failed for this commit: {name}")
    published = update.get("published_at")
    wait_hours = automation.get("minimum_release_age_hours", 336)
    if update.get("emergency") and automation.get("allow_emergency_fast_track", False):
        wait_hours = automation.get("emergency_minimum_release_age_hours", 0)
    if not published:
        reasons.append("release publication time is unknown")
    elif datetime.now(UTC) - timestamp(published) < timedelta(hours=wait_hours):
        reasons.append("release is inside the configured waiting period")
    return {"action": "auto_merge" if not reasons else "review", "reasons": reasons}


def plan(findings: list[dict], assets: list[dict], policy: dict) -> list[dict]:
    by_id = {a["id"]: a for a in assets}
    result = []
    for finding in findings:
        if finding["effective_status"] == "resolved":
            continue
        asset = by_id[finding["asset_id"]]
        accepted = finding["effective_status"] == "accepted_risk"
        fixes = finding.get("fixed_versions", [])
        workflow_action = {
            "proposed": "review_prepared_candidate",
            "testing": "complete_required_tests",
            "awaiting_deployment": "verify_deployed_runtime",
            "blocked": "resolve_blocker_and_rescan",
        }.get(finding["effective_status"])
        result.append(
            {
                "finding_id": finding["id"],
                "asset_id": asset["id"],
                "project": asset["project"],
                "environment": asset["environment"],
                "priority": priority(finding, asset),
                "due_at": due_at(finding, asset, policy),
                "package": finding["package"],
                "advisory_id": finding["advisory_id"],
                "current_version": finding["version"],
                "fixed_versions": fixes,
                "action": "accepted_risk"
                if accepted
                else "isolate_and_investigate"
                if finding.get("malicious")
                else workflow_action
                if workflow_action
                else "prepare_update_pr"
                if fixes
                else "investigate_fix",
                "note": "Potential malicious package: isolate affected execution environments, preserve evidence, "
                "and rotate exposed credentials from a clean host."
                if finding.get("malicious")
                else "Runtime verification is required after deployment; PR merge does not close this finding.",
            }
        )
    return sorted(
        result, key=lambda f: ({"urgent": 0, "high": 1, "normal": 2}[f["priority"]], f["due_at"])
    )
