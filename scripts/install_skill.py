#!/usr/bin/env python3
"""Copy only Teate's public skill to a Codex user or project skill directory."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / ".agents" / "skills" / "teate"
FILES = ("SKILL.md", "agents/openai.yaml", "references/setup.md", "references/reporting.md")


def bundle(source: Path) -> dict[str, bytes]:
    contents = {}
    for name in FILES:
        path = source / name
        if any(parent.is_symlink() for parent in [path, *path.parents]):
            raise ValueError("Skill source must not traverse symlinks")
        data = path.read_bytes()
        if len(data) > 32_768:
            raise ValueError("Skill file exceeds 32KB")
        contents[name] = data
    return contents


def install(source: Path, destination: Path, *, dry_run: bool = False) -> str:
    data = bundle(source)
    if any(path.is_symlink() for path in [destination, *destination.parents]):
        raise ValueError("Refusing to install through a symlink")
    if destination.exists():
        if destination.is_dir():
            existing = {}
            for path in destination.rglob("*"):
                if path.is_symlink():
                    break
                if path.is_file():
                    name = str(path.relative_to(destination)).replace(os.sep, "/")
                    if name not in data or path.stat().st_size != len(data[name]):
                        break
                    existing[name] = path.read_bytes()
            else:
                if existing == data:
                    return "Already installed"
        raise ValueError("Skill already exists with different contents; review and move it before reinstalling")
    if dry_run:
        return "Would install"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".teate-skill-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "teate"
        for name, content in data.items():
            file = staged / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(content)
        staged.rename(destination)
    return "Installed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--user", action="store_true", help="install in ~/.agents/skills/teate")
    scope.add_argument("--project", type=Path, help="install in PROJECT/.agents/skills/teate")
    parser.add_argument("--dry-run", action="store_true", help="show destination without writes")
    args = parser.parse_args(argv)
    root = (Path.home() if args.user else args.project.expanduser()).resolve()
    if not root.is_dir():
        raise ValueError("User/project directory does not exist")
    destination = root / ".agents" / "skills" / "teate"
    message = install(SOURCE, destination, dry_run=args.dry_run)
    print(f"{message}: {destination}")
    print("In Codex use $teate. If it is missing, restart Codex in the target project.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"Skill installation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
