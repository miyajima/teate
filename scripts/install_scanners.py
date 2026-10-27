#!/usr/bin/env python3
"""Compatibility entrypoint; scanner installation is delegated to mise."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.install_dependencies import ROOT, link
from scripts.install_dependencies import main as install


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="v2.7.0", choices=["v2.7.0"])
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    code = install([])
    if code:
        return code
    args.directory.mkdir(parents=True, exist_ok=True)
    link(ROOT / ".teate/bin/osv-scanner", args.directory / "osv-scanner")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
