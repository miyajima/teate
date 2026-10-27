"""Run only operator-configured tests, with no host credentials or network access."""

from __future__ import annotations

import json
import os
import re
import resource
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from .model import TeateError, digest, utcnow
from .repair import _git


def relative(root: Path, value: str) -> Path:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or any(p in {".git", ".teate"} for p in path.parts):
        raise TeateError("verification_path_outside_candidate")
    target = root / path
    if not target.resolve().is_relative_to(root.resolve()) or any(p.is_symlink() for p in [target, *target.parents] if p != root.parent):
        raise TeateError("verification_symlink_path")
    return target


def _command(root: Path, cwd: Path, argv: list[str], scratch: Path | None = None) -> list[str] | None:
    if shutil.which("bwrap"):
        command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv"]
        for path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(path).exists():
                command += ["--ro-bind", path, path]
        return [*command, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--bind", str(root), "/work", "--chdir", "/work/" + str(cwd.relative_to(root)),
                "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/tmp",
                "--setenv", "CI", "true", "--", *argv]
    if shutil.which("sandbox-exec"):
        if scratch is None:
            return None
        profile = '(version 1)(deny default)(allow process*)(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/opt/homebrew") (subpath "/Library/Developer") (subpath ' + json.dumps(str(root)) + '))(allow file-read* file-write* (subpath ' + json.dumps(str(root)) + ') (subpath ' + json.dumps(str(scratch)) + '))'
        return ["sandbox-exec", "-p", profile, *argv]
    return None


def _limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1_048_576, 1_048_576))


def verify(asset: dict, record: dict) -> dict:
    settings = asset.get("verification", {})
    specs = settings.get("commands", [])
    if not specs:
        return {"status": "unconfigured", "checks": [], "reason": "project_tests_not_configured"}
    if not isinstance(specs, list) or len(specs) > 5:
        raise TeateError("one_to_five_explicit_test_commands_required")
    root = Path(record["worktree"]).resolve()
    original = _git(root, "diff", "--binary", "--no-ext-diff", "--no-textconv")
    discard = settings.get("discard_outputs", [])
    if not isinstance(discard, list) or len(discard) > 20:
        raise TeateError("invalid_test_output_allowlist")
    tracked = set(_git(root, "ls-files").splitlines())
    files = {}
    for name in discard:
        path = relative(root, name)
        if Path(name).name in {"package-lock.json", "package.json"} or name not in tracked or path.stat().st_size > 5_000_000:
            raise TeateError("test_cannot_discard_dependency_or_untracked_files")
        files[name] = path.read_bytes()
    checks = []
    for spec in specs:
        argv = spec.get("argv")
        timeout = spec.get("timeout_seconds", 60)
        if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and "\x00" not in v for v in argv):
            raise TeateError("test_argv_must_be_explicit_strings")
        if type(timeout) is not int or not 1 <= timeout <= 120:
            raise TeateError("test_timeout_out_of_bounds")
        cwd = relative(root, spec.get("cwd", "."))
        timed_out = False
        with tempfile.TemporaryDirectory(prefix="teate-test-") as scratch_dir, tempfile.TemporaryFile(dir=scratch_dir) as output:
            command = _command(root, cwd, argv, Path(scratch_dir).resolve())
            if command is None:
                return {"status": "blocked", "checks": checks, "reason": "test_sandbox_unavailable"}
            process = subprocess.Popen(command, cwd=cwd, env={"PATH": "/usr/local/bin:/opt/homebrew/bin:"+os.defpath,
                                                            "HOME": scratch_dir, "TMPDIR": scratch_dir, "CI": "true"},
                                       stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=_limits)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                import signal

                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code, timed_out = -1, True
            output.seek(0, 2)
            output.seek(max(0, output.tell()-2000))
            excerpt = output.read(2000).decode(errors="replace").replace(str(root), "<candidate>")
        blocked = code != 0 and (excerpt.startswith("bwrap:") or "sandbox-exec:" in excerpt)
        checks.append({"name": str(spec.get("name", "test"))[:80], "exit_code": code,
                       "timed_out": timed_out, "excerpt": excerpt, "output_id": digest(excerpt)})
        if blocked:
            return {"status": "blocked", "checks": checks, "reason": "test_sandbox_not_permitted"}
        if code != 0:
            if re.search(r"MODULE_NOT_FOUND|Cannot find module|No module named|command not found", excerpt):
                return {"status": "blocked", "checks": checks, "reason": "test_prerequisites_unavailable"}
            return {"status": "failed", "checks": checks, "reason": "project_test_failed"}
    for name in discard:
        path = relative(root, name)
        path.write_bytes(files[name])
    if original != _git(root, "diff", "--binary", "--no-ext-diff", "--no-textconv"):
        return {"status": "failed", "checks": checks, "reason": "tests_modified_candidate"}
    return {"status": "passed", "checks": checks, "checked_at": utcnow(),
            "note": "Local tests do not replace required commit-specific GitHub checks"}
