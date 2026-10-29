"""Operator-configured preparation and offline tests through sandbox-runtime."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from . import sandbox, source
from .model import TeateError, utcnow


def relative(root: Path, value: str) -> Path:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or any(p in {".git", ".teate"} for p in path.parts):
        raise TeateError("verification_path_outside_candidate")
    target = root / path
    if not target.resolve().is_relative_to(root.resolve()):
        raise TeateError("verification_symlink_path")
    current = target
    while current != root:
        if current.is_symlink():
            raise TeateError("verification_symlink_path")
        current = current.parent
    return target


def verify(asset: dict, record: dict) -> dict:
    settings = asset.get("verification", {})
    specs = settings.get("commands", [])
    if not specs:
        return {"status": "unconfigured", "checks": [], "reason": "project_tests_not_configured"}
    if not isinstance(specs, list) or not 1 <= len(specs) <= 5:
        raise TeateError("one_to_five_explicit_test_commands_required")
    root = Path(record["worktree"]).resolve()
    original = source.files(root, include_private=True)
    discard = settings.get("discard_outputs", [])
    if not isinstance(discard, list) or len(discard) > 20:
        raise TeateError("invalid_test_output_allowlist")
    outputs = {}
    for name in discard:
        path = relative(root, name)
        if (
            path.name in {"package-lock.json", "package.json"}
            or name not in original
            or path.stat().st_size > 5_000_000
        ):
            raise TeateError("test_cannot_discard_dependency_or_untracked_files")
        outputs[name] = path.read_bytes()
    checks = []
    # Fixed dependency install command, explicit opt-in; no user npm configuration
    # or lifecycle hooks, and only the registry network profile.
    install = settings.get("install_dependencies", False)
    if install is not False and install is not True:
        raise TeateError("install_dependencies_must_be_boolean")
    if install:
        locations = sorted({str(Path(p).parent) for p in record["changed_files"]})
        for location in locations:
            check = sandbox.execute(
                root,
                [
                    "npm",
                    "ci",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    "--registry=https://registry.npmjs.org",
                ],
                cwd=relative(root, location),
                network="npm",
                timeout=120,
            )
            checks.append({"name": "dependency_preparation", **check})
            if check["status"] != "passed":
                return {
                    "status": "blocked",
                    "checks": checks,
                    "reason": "test_prerequisites_unavailable",
                }
    for spec in specs:
        timeout = spec.get("timeout_seconds", 60)
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise TeateError("test_timeout_out_of_bounds")
        check = sandbox.execute(
            root,
            spec.get("argv"),
            cwd=relative(root, spec.get("cwd", ".")),
            timeout=timeout,
            network="offline",
        )
        checks.append({"name": str(spec.get("name", "test"))[:80], **check})
        if check["status"] != "passed":
            return {
                "status": check["status"],
                "checks": checks,
                "reason": "test_sandbox_or_prerequisites_unavailable"
                if check["status"] == "blocked"
                else "project_test_failed",
            }
    for name, content in outputs.items():
        relative(root, name).write_bytes(content)
    if original != source.files(root, include_private=True):
        return {"status": "failed", "checks": checks, "reason": "tests_modified_candidate"}
    return {
        "status": "passed",
        "checks": checks,
        "checked_at": utcnow(),
        "note": "Local tests do not replace required commit-specific GitHub checks",
    }
