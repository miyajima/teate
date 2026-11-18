#!/usr/bin/env python3
"""Check the reviewed licenses of the pinned npm tool dependencies."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LICENSES = {
    "MIT": "MIT",
    "Apache-2.0": "Apache-2.0",
    "BSD-2-Clause": "BSD-2-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "(BSD-3-Clause OR GPL-2.0)": "BSD-3-Clause",
}


def main():
    packages = []
    for bundle in ("runtime", "codex"):
        lock = json.loads((ROOT / "tools" / bundle / "package-lock.json").read_text())
        for name, package in lock["packages"].items():
            if not name:
                continue
            license_ = package.get("license")
            if license_ not in LICENSES:
                raise ValueError("Review tool dependency license: " + name)
            packages.append(
                {
                    "bundle": bundle,
                    "package": name,
                    "version": package["version"],
                    "declared_license": license_,
                    "selected_license": LICENSES[license_],
                }
            )
    print(json.dumps(packages, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
