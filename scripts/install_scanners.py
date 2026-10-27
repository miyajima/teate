#!/usr/bin/env python3
"""Install a pinned official scanner, validating the release SHA256 manifest."""

import argparse
import hashlib
import platform
import re
import urllib.request
from pathlib import Path


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Teate/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="v2.7.0")
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("a stable, exact scanner version is required")
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if not system or not arch:
        parser.error("supported platforms: macOS/Linux on amd64/arm64")
    filename = f"osv-scanner_{system}_{arch}"
    base = f"https://github.com/google/osv-scanner/releases/download/{args.version}/"
    sums = download(base + "osv-scanner_SHA256SUMS").decode()
    matches = [
        line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip("*") == filename
    ]
    if len(matches) != 1:
        raise RuntimeError("release checksum manifest does not identify this binary")
    binary = download(base + filename)
    if hashlib.sha256(binary).hexdigest() != matches[0]:
        raise RuntimeError("scanner checksum mismatch")
    args.directory.mkdir(parents=True, exist_ok=True)
    target = args.directory / "osv-scanner"
    temporary = target.with_suffix(".download")
    temporary.write_bytes(binary)
    temporary.chmod(0o755)
    temporary.replace(target)
    print(f"Installed OSV-Scanner {args.version} with SHA256 {matches[0]}")


if __name__ == "__main__":
    main()
