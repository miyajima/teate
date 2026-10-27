"""Small, versioned interchange format shared by collectors and the ledger."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class TeateError(ValueError):
    pass


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(UTC)
    except (TypeError, ValueError, AttributeError) as exc:
        raise TeateError(f"Invalid timezone-aware timestamp: {value!r}") from exc


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise TeateError(f"Cannot read JSON: {path}: {exc}") from exc


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=target.parent, prefix="." + target.name, suffix=".tmp", delete=False
    ) as file:
        temporary = Path(file.name)
        file.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    try:
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def image_digest(value: str) -> str:
    match = re.search(r"(?:@|^)(sha256:[0-9a-f]{64})$", value)
    return match.group(1) if match else ""


def validate_asset(asset: dict) -> dict:
    for key in ("id", "project", "environment", "kind"):
        if not isinstance(asset.get(key), str) or not asset[key].strip():
            raise TeateError(f"Asset requires {key}")
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,180}", asset["id"]):
        raise TeateError("Invalid asset id")
    if asset["kind"] not in {"source", "image", "mac", "cloud-run"}:
        raise TeateError(f"Unsupported asset kind: {asset['kind']}")
    return asset


def validate_snapshot(snapshot: dict) -> dict:
    if snapshot.get("schema_version") != 1:
        raise TeateError("Only snapshot schema_version 1 is supported")
    for key in ("asset_id", "scanner", "scope", "observed_at"):
        if not isinstance(snapshot.get(key), str) or not snapshot[key]:
            raise TeateError(f"Snapshot requires {key}")
    observed = timestamp(snapshot["observed_at"])
    if (observed - datetime.now(UTC)).total_seconds() > 300:
        raise TeateError("Snapshot timestamp is in the future")
    snapshot["observed_at"] = observed.isoformat(timespec="microseconds")
    if snapshot.get("status") not in {"success", "error", "unsupported"}:
        raise TeateError("Invalid snapshot status")
    if type(snapshot.get("complete")) is not bool:
        raise TeateError("Snapshot complete must be a boolean")
    if not isinstance(snapshot.get("subject"), dict):
        raise TeateError("Snapshot requires a subject object")
    if not isinstance(snapshot.get("findings"), list):
        raise TeateError("Snapshot findings must be an array")
    for finding in snapshot["findings"]:
        for key in ("advisory_id", "package", "ecosystem", "version"):
            if not isinstance(finding.get(key), str) or not finding[key]:
                raise TeateError(f"Finding requires {key}")
        if not isinstance(finding.get("aliases", []), list):
            raise TeateError("Finding aliases must be an array")
        if not all(isinstance(a, str) and a for a in finding.get("aliases", [])):
            raise TeateError("Finding aliases must contain nonempty strings")
        finding["severity"] = str(finding.get("severity", "UNKNOWN")).upper()
        if finding["severity"] not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            raise TeateError("Invalid finding severity")
        if type(finding.get("kev", False)) is not bool:
            raise TeateError("Finding kev must be boolean")
        if type(finding.get("malicious", False)) is not bool:
            raise TeateError("Finding malicious must be boolean")
        fixes = finding.get("fixed_versions", [])
        if not isinstance(fixes, list) or not all(isinstance(f, str) and f for f in fixes):
            raise TeateError("Finding fixed_versions must contain nonempty strings")
        if "location" in finding and not isinstance(finding["location"], str):
            raise TeateError("Finding location must be a string")
    return snapshot


def snapshot(
    asset_id: str,
    scanner: str,
    scope: str,
    subject: dict,
    findings: list | None = None,
    *,
    status: str = "success",
    complete: bool = True,
    message: str = "",
    observed_at: str | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "asset_id": asset_id,
        "scanner": scanner,
        "scope": scope,
        "subject": subject,
        "observed_at": observed_at or utcnow(),
        "status": status,
        "complete": complete,
        "findings": findings or [],
        "message": message,
    }
