#!/usr/bin/env python3
"""Fetch explicitly registered repository sources; never execute dependency scripts."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from teate.config import load_config
from teate.github import repository_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/ci.json")
    args = parser.parse_args()
    failed = False
    config = load_config(args.config)
    checkout_root = (Path(config["config_path"]).parent.parent / "repositories").resolve()
    for asset in config["assets"]:
        if asset["kind"] != "source" or not asset.get("repository") or asset.get("host_id"):
            continue
        name = repository_name(asset["repository"])
        target = Path(asset["path"]).resolve()
        if not target.is_relative_to(checkout_root):
            raise ValueError("CI checkouts must be inside the dedicated repositories directory")
        if target.exists():
            raise ValueError("Refusing to overwrite an existing checkout")
        target.parent.mkdir(parents=True, exist_ok=True)
        environment = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "credential.helper",
            "GIT_CONFIG_VALUE_0": "!gh auth git-credential",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": "/dev/null",
        }
        try:
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "--no-recurse-submodules",
                    "https://github.com/" + name + ".git",
                    str(target),
                ],
                check=False,
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode:
                print(f"Unavailable repository: {name}; it will remain unchecked", file=sys.stderr)
                failed = True
        except subprocess.TimeoutExpired:
            print(f"Repository fetch timed out: {name}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
