#!/usr/bin/env python3
"""Install checksum-verified, pinned tools into .teate; never log in or scan."""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
OSV_VERSION = "2.7.0"
TRIVY_VERSION = "0.76.1"
GH_VERSION = "2.103.3"
NODE_VERSION = "24.22.1"
CODEX_VERSION = "0.159.2"
GCLOUD_VERSION = "590.0.1"
# Versioned Google archives, SHA256 values published by Homebrew's gcloud-cli
# 590.0.1 cask: https://github.com/Homebrew/homebrew-cask/blob/3451e39e68d9d31f33516db3d5941f2f1ca5a6be/Casks/g/gcloud-cli.rb
# The Google quickstart lists different, unversioned archives; do not mix them.
GCLOUD_SHA256 = {
    ("linux", "amd64"): "d1ae7be7e12c4e7d8286fab4774f5441020aca89dc7793ddacbace8d11d20f06",
    ("linux", "arm64"): "fd760d8b1c2c4c484d7b659964994b07aaefddc6ac4350e681940477dbdbb22c",
    ("darwin", "amd64"): "32e41cdb54d3946bcd5d29bd2bd9f3d8923bf1578e8ecc94d0999f2f18f2f0f1",
    ("darwin", "arm64"): "02f20618f43b9147e049a73fec37ab71b586b0dc6a242fa6ca835229cb5e542f",
}


def target(system: str, machine: str) -> tuple[str, str]:
    systems = {"Linux": "linux", "Darwin": "darwin"}
    arches = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if system not in systems or machine not in arches:
        raise ValueError("Use Linux/macOS on amd64/arm64. Windows: run scripts/install.ps1 (WSL2).")
    return systems[system], arches[machine]


def checksum(manifest: str, filename: str) -> str:
    matches = []
    for line in manifest.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") == filename:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
                raise ValueError("Invalid SHA256 manifest")
            matches.append(fields[0].lower())
    if len(matches) != 1:
        raise ValueError(f"Checksum manifest must identify {filename} exactly once")
    return matches[0]


def download(url: str, destination: Path, limit: int = 512 * 1024 * 1024) -> None:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS downloads are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "Teate-installer/0.4"})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
        if not response.url.startswith("https://"):
            raise ValueError("Refusing a non-HTTPS redirect")
        total = 0
        while block := response.read(1024 * 1024):
            total += len(block)
            if total > limit:
                raise ValueError("Download exceeds size limit")
            output.write(block)


def verified(url: str, destination: Path, expected: str) -> None:
    download(url, destination)
    h = hashlib.sha256()
    with destination.open("rb") as source:
        while block := source.read(1024 * 1024):
            h.update(block)
    if h.hexdigest() != expected:
        raise ValueError(f"SHA256 mismatch for {url.rsplit('/', 1)[-1]}")


def extract(archive: Path, destination: Path) -> None:
    """Extract fresh archives without ownership, special nodes or link traversal."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if len(members) > 150_000 or sum(m.file_size for m in members) > 1_500_000_000:
                raise ValueError("Archive exceeds extraction limit")
            seen = set()
            for member in members:
                name = PurePosixPath(member.filename)
                mode = member.external_attr >> 16
                if (name.is_absolute() or ".." in name.parts or "\\" in member.filename
                        or name in seen or mode & 0o170000 == 0o120000):
                    raise ValueError("Unsafe ZIP member")
                seen.add(name)
            destination.mkdir(mode=0o700)
            for member in members:
                output = destination / member.filename
                if member.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(member) as source, output.open("xb") as sink:
                        shutil.copyfileobj(source, sink)
                    output.chmod((member.external_attr >> 16) & 0o755 or 0o644)
        return
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > 150_000 or sum(m.size for m in members) > 1_500_000_000:
            raise ValueError("Archive exceeds extraction limit")
        paths, links = {}, set()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or "\\" in member.name:
                raise ValueError("Unsafe archive path")
            if str(name) == ".":
                if not member.isdir():
                    raise ValueError("Invalid archive root")
                continue
            if name in paths or not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError("Duplicate or unsupported archive member")
            paths[name] = member
            if member.issym():
                links.add(name)
        if any(parent in links for name in paths for parent in name.parents):
            raise ValueError("Archive writes through a symlink")
        destination.mkdir(mode=0o700)
        for name, member in paths.items():
            output = destination / str(name)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                output.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, output.open("xb") as sink:
                    shutil.copyfileobj(source, sink)
                output.chmod(member.mode & 0o755)
        pending = list(links)
        while pending:
            progress = False
            for name in pending[:]:
                member = paths[name]
                output = destination / str(name)
                if PurePosixPath(member.linkname).is_absolute():
                    raise ValueError("Absolute archive symlink")
                resolved = (output.parent / member.linkname).resolve()
                if not resolved.is_relative_to(destination.resolve()):
                    raise ValueError("Archive symlink escapes destination")
                if not resolved.exists():
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                output.symlink_to(member.linkname)
                pending.remove(name)
                progress = True
            if not progress:
                raise ValueError("Unresolved archive symlink")


def version_matches(executable: Path, version: str) -> bool:
    if not executable.is_file():
        return False
    result = subprocess.run([str(executable), "--version"], check=False,
                            capture_output=True, text=True, timeout=30)
    return result.returncode == 0 and re.search(
        r"(?<![\d.])" + re.escape(version) + r"(?![\d.])", result.stdout + result.stderr
    ) is not None


def link(source: Path, destination: Path) -> None:
    if destination.is_symlink():
        if destination.resolve() == source.resolve():
            return
        destination.unlink()
    elif destination.exists():
        # Migrate a byte-identical binary from the older install_scanners.py
        # layout. A different operator-managed file must remain untouched.
        with source.open("rb") as first, destination.open("rb") as second:
            same = hashlib.file_digest(first, "sha256").digest() == hashlib.file_digest(second, "sha256").digest()
        if not same:
            raise ValueError(f"Refusing to overwrite unmanaged file: {destination}")
        destination.unlink()
    destination.symlink_to(source)


def install_tool(name: str, version: str, url: str, manifest_url: str | None,
                 binary: str, bins: Path, tools: Path, *, expected: str | None = None,
                 raw: bool = False) -> None:
    folder = tools / f"{name}-{version}"
    entry = folder / binary
    if folder.exists():
        if not version_matches(entry, version):
            raise ValueError(f"Existing installation is incomplete or unexpected: {folder}")
        print(f"Already installed: {name} {version}")
    else:
        print(f"Installing {name} {version}", flush=True)
        with tempfile.TemporaryDirectory(prefix=".install-", dir=tools) as temporary:
            scratch = Path(temporary)
            if manifest_url:
                manifest = scratch / "checksums"
                download(manifest_url, manifest, 2 * 1024 * 1024)
                expected = checksum(manifest.read_text(), url.rsplit("/", 1)[-1])
            if expected is None:
                raise ValueError("A SHA256 checksum is required")
            package = scratch / "package"
            verified(url, package, expected)
            staged = scratch / "unpacked"
            if raw:
                staged.mkdir()
                shutil.move(package, staged / binary)
                (staged / binary).chmod(0o755)
            else:
                extract(package, staged)
            # Validate offline before replacing anything or adding it to PATH.
            if not version_matches(staged / binary, version):
                raise ValueError(f"Downloaded {name} failed its version check")
            staged.rename(folder)
    link(entry, bins / name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="also install Node/npm, Trivy, gh, gcloud, Codex")
    parser.add_argument("--dry-run", action="store_true", help="print the plan without downloads or writes")
    args = parser.parse_args(argv)
    system, arch = target(platform.system(), platform.machine())
    print(f"Platform: {system}/{arch}; tools: OSV {OSV_VERSION}")
    if args.all:
        print(f"Also: Node {NODE_VERSION}, Trivy {TRIVY_VERSION}, gh {GH_VERSION}, gcloud {GCLOUD_VERSION}, Codex {CODEX_VERSION}")
    if args.dry_run:
        print("Dry run only. Use scripts/install.sh to bootstrap Python/Git and Linux bubblewrap.")
        return 0
    if not (3, 11) <= sys.version_info[:2] < (3, 16):
        raise ValueError("Python 3.11–3.15 is required")
    if not shutil.which("git"):
        raise ValueError("Git is missing; run bash scripts/install.sh first")
    os.umask(0o077)
    state = ROOT / ".teate"
    bins, tools = state / "bin", state / "tools"
    bins.mkdir(parents=True, exist_ok=True)
    tools.mkdir(parents=True, exist_ok=True)
    # Do not change shell profiles or copy authentication. The user activates
    # this environment explicitly for Teate; system/application runtimes stay put.
    link(Path(sys.executable).resolve(), bins / "python3")
    os.environ["PATH"] = str(bins) + os.pathsep + os.environ.get("PATH", os.defpath)
    os.environ["CLOUDSDK_PYTHON"] = sys.executable
    os.environ["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
    os.environ["CLOUDSDK_CORE_DISABLE_USAGE_REPORTING"] = "true"
    base = f"https://github.com/google/osv-scanner/releases/download/v{OSV_VERSION}/"
    install_tool("osv-scanner", OSV_VERSION, base + f"osv-scanner_{system}_{arch}",
                 base + "osv-scanner_SHA256SUMS", "osv-scanner", bins, tools, raw=True)
    if args.all:
        node_system = "darwin" if system == "darwin" else "linux"
        node_arch = "x64" if arch == "amd64" else "arm64"
        node_root = f"node-v{NODE_VERSION}-{node_system}-{node_arch}"
        base = f"https://nodejs.org/dist/v{NODE_VERSION}/"
        install_tool("node", NODE_VERSION, base + node_root + ".tar.gz", base + "SHASUMS256.txt",
                     node_root + "/bin/node", bins, tools)
        node_folder = tools / f"node-{NODE_VERSION}" / node_root
        link(node_folder / "bin/npm", bins / "npm")
        trivy_system = "macOS" if system == "darwin" else "Linux"
        trivy_arch = "64bit" if arch == "amd64" else "ARM64"
        base = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/"
        install_tool("trivy", TRIVY_VERSION, base + f"trivy_{TRIVY_VERSION}_{trivy_system}-{trivy_arch}.tar.gz",
                     base + f"trivy_{TRIVY_VERSION}_checksums.txt", "trivy", bins, tools)
        gh_system = "macOS" if system == "darwin" else "linux"
        gh_root = f"gh_{GH_VERSION}_{gh_system}_{arch}"
        base = f"https://github.com/cli/cli/releases/download/v{GH_VERSION}/"
        gh_suffix = ".zip" if system == "darwin" else ".tar.gz"
        install_tool("gh", GH_VERSION, base + gh_root + gh_suffix, base + f"gh_{GH_VERSION}_checksums.txt",
                     gh_root + "/bin/gh", bins, tools)
        gcloud_arch = "x86_64" if arch == "amd64" else "arm"
        filename = f"google-cloud-cli-{GCLOUD_VERSION}-{system}-{gcloud_arch}.tar.gz"
        install_tool("gcloud", GCLOUD_VERSION,
                     "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/" + filename,
                     None, "google-cloud-sdk/bin/gcloud", bins, tools, expected=GCLOUD_SHA256[system, arch])
        codex_root = tools / f"codex-{CODEX_VERSION}"
        if not version_matches(codex_root / "bin/codex", CODEX_VERSION):
            print(f"Installing Codex {CODEX_VERSION} (no login)", flush=True)
            subprocess.run([str(bins / "npm"), "install", "--global", "--prefix", str(codex_root),
                            "--cache", str(tools / "npm-cache"),
                            "--ignore-scripts", "--no-audit", "--no-fund",
                            "--registry=https://registry.npmjs.org", f"@openai/codex@{CODEX_VERSION}"],
                           check=True, timeout=600)
        if not version_matches(codex_root / "bin/codex", CODEX_VERSION):
            raise ValueError("Codex version check failed")
        link(codex_root / "bin/codex", bins / "codex")
    env = state / "env.sh"
    env.write_text("# Generated by Teate; source this file in a POSIX shell.\n"
                   + "export PATH=" + shlex.quote(str(bins)) + ':"$PATH"\n'
                   + "export CLOUDSDK_PYTHON=" + shlex.quote(str(Path(sys.executable).resolve())) + "\n")
    print("Installed. Run:\n  source " + shlex.quote(str(env)))
    print("No login, asset registration, source update, scan, merge or deployment was performed.")
    if args.all:
        print("Authentication is separate: gh / gcloud / Codex. Sandbox permission and project tests still need verification.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
