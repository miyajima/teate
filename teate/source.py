"""Bounded source snapshots shared by Git and plain-directory repair jobs."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

from .model import TeateError

SKIP = {".git", ".teate", "node_modules", ".venv", "venv", "target", "__pycache__"}
PRIVATE = {
    ".env",
    ".ssh",
    ".aws",
    ".azure",
    ".config",
    ".codex",
    ".npmrc",
    ".netrc",
    ".gitconfig",
    "auth.json",
    "credentials.json",
    ".docker",
    "id_rsa",
    "id_ed25519",
}


def files(root: Path, *, include_private: bool = False) -> dict[str, str]:
    result, size = {}, 0
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in (SKIP - {".git", ".teate"} if include_private else SKIP)
            and (include_private or d not in PRIVATE)
        )
        for name in [*dirs, *sorted(names)]:
            path = Path(current) / name
            if path.is_symlink():
                raise TeateError("source_symlink_requires_review")
        for name in sorted(names):
            if name in (SKIP - {".git", ".teate"} if include_private else SKIP) or (
                not include_private
                and (
                    name in PRIVATE
                    or name.startswith(".env.")
                    or name.endswith((".pem", ".key", ".p12", ".pfx", "-credentials.json"))
                )
            ):
                continue
            path = Path(current) / name
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise TeateError("source_special_file_requires_review")
            size += info.st_size
            if len(result) >= 10000 or size > 64_000_000:
                raise TeateError("source_snapshot_limit_exceeded")
            h = hashlib.sha256(path.read_bytes()).hexdigest()
            result[path.relative_to(root).as_posix()] = h + ":" + str(stat.S_IMODE(info.st_mode))
    return result


def copy(root: Path, destination: Path) -> dict[str, str]:
    before = files(root)
    if destination.resolve().is_relative_to(root.resolve()):
        raise TeateError("candidate_must_be_outside_source")
    destination.mkdir(parents=True)
    for name in before:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, target)
    if files(root) != before or files(destination) != before:
        raise TeateError("source_changed_during_snapshot")
    return before


def changes(before: dict, after: dict) -> list[str]:
    return sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
