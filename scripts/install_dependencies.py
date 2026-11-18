#!/usr/bin/env python3
"""Bootstrap mise, then use reviewed locked OSS installers; never log in or scan."""

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
import tempfile
import urllib.request
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MISE_VERSION = "2026.10.21"
MISE_SHA256 = {
    ("linux", "arm64"): "a7c96627e56c075543fe1c1aafeb289d2588d6ddfd4d705fce4ae140c57e190c",
    ("linux", "x64"): "ccfe12d7a62c6fb9def2a20db1f210f13a51de881f21fd8c85db4b6312405d07",
    ("macos", "arm64"): "b20d30788a819fade398a1cb92aee56c383e3c34324162ec39fb8567dee79ba6",
    ("macos", "x64"): "5dde6e3fcda4d8a68b95cc2180dacd58e7b940f86e4579991e13540a5d009055",
}


def target(system, machine):
    systems = {"Linux": "linux", "Darwin": "macos"}
    arches = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}
    if system not in systems or machine not in arches:
        raise ValueError("Use macOS/Linux amd64/arm64. Windows: scripts/install.ps1 (WSL2).")
    return systems[system], arches[machine]


def checksum(manifest, filename):
    values = [
        v[0].lower()
        for line in manifest.splitlines()
        if len(v := line.split()) == 2 and v[1].lstrip("*").removeprefix("./") == filename
    ]
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
        raise ValueError("Checksum manifest must identify the exact artifact once")
    return values[0]


def download(url: str, destination: Path, limit: int = 512 * 1024 * 1024) -> None:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS downloads are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "Teate-installer/0.5"})
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


def link(source: Path, destination: Path) -> None:
    if destination.exists() and source.samefile(destination):
        return
    if destination.is_symlink():
        if destination.resolve() == source.resolve():
            return
        destination.unlink()
    elif destination.exists():
        # Migrate a byte-identical binary from the older install_scanners.py
        # layout. A different operator-managed file must remain untouched.
        with source.open("rb") as first, destination.open("rb") as second:
            same = (
                hashlib.file_digest(first, "sha256").digest()
                == hashlib.file_digest(second, "sha256").digest()
            )
        if not same:
            raise ValueError(f"Refusing to overwrite unmanaged file: {destination}")
        destination.unlink()
    destination.symlink_to(source)


def mise_environment(state):
    # Isolate mise's config/state as well as installed tools. Preserve platform
    # proxy/CA bindings; do not inherit user plugins, tasks or auto-update policy.
    env = {k: v for k, v in os.environ.items() if not k.startswith("MISE_")}
    folder = state / "mise-config"
    folder.mkdir(exist_ok=True)
    (folder / "global.toml").write_text("")
    env.update(
        MISE_DATA_DIR=str(state / "mise"),
        MISE_STATE_DIR=str(state / "mise-state"),
        MISE_CACHE_DIR=str(state / "mise-cache"),
        MISE_CONFIG_DIR=str(folder),
        MISE_GLOBAL_CONFIG_FILE=str(folder / "global.toml"),
        MISE_SYSTEM_CONFIG_DIR=str(folder / "system"),
        MISE_YES="1",
        MISE_DISABLE_UPDATE_WARNING="1",
        MISE_SELF_UPDATE_AUTO="0",
        MISE_CEILING_PATHS=str(ROOT),
        MISE_ENV_FILE="",
    )
    return env


def bootstrap(state, system, arch):
    folder = state / "bootstrap"
    folder.mkdir(exist_ok=True)
    entry = folder / "mise"
    if not entry.exists():
        artifact = f"mise-v{MISE_VERSION}-{system}-{arch}"
        base = f"https://github.com/jdx/mise/releases/download/v{MISE_VERSION}/"
        with tempfile.TemporaryDirectory(dir=folder) as temp:
            sums, binary = Path(temp) / "sums", Path(temp) / "mise"
            download(base + "SHASUMS256.txt", sums, 2_000_000)
            expected = checksum(sums.read_text(), artifact)
            if expected != MISE_SHA256[system, arch]:
                raise ValueError("Published mise checksum changed; review required")
            verified(base + artifact, binary, expected)
            binary.chmod(0o755)
            binary.rename(entry)
    if hashlib.file_digest(entry.open("rb"), "sha256").hexdigest() != MISE_SHA256[system, arch]:
        raise ValueError("Existing mise binary does not match the pinned artifact")
    return entry


def install_npm_bundle(name, state, npm, bins, env):
    folder = state / "npm-tools" / name
    folder.mkdir(parents=True, exist_ok=True)
    for filename in ("package.json", "package-lock.json"):
        shutil.copy2(ROOT / "tools" / name / filename, folder / filename)
    lock_id = hashlib.sha256((folder / "package-lock.json").read_bytes()).hexdigest()
    stamp = folder / ".installed"
    executable = "srt" if name == "runtime" else "codex"
    binary = folder / "node_modules/.bin" / executable
    if not stamp.exists() or stamp.read_text() != lock_id or not binary.exists():
        subprocess.run(
            [
                str(npm),
                "ci",
                "--prefix",
                str(folder),
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--cache",
                str(state / "npm-cache"),
                "--userconfig=" + str(state / "npm-user.conf"),
                "--globalconfig=" + str(state / "npm-global.conf"),
                "--registry=https://registry.npmjs.org",
            ],
            cwd=folder,
            env=env,
            check=True,
            timeout=600,
        )
        stamp.write_text(lock_id)
    if not binary.is_file():
        raise ValueError("Installed npm tool missing: " + executable)
    link(binary, bins / executable)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all", action="store_true", help="also install Trivy, gh, gcloud and optional Codex"
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    system, arch = target(platform.system(), platform.machine())
    print(
        f"Platform {system}/{arch}; mise {MISE_VERSION}, locked OSV/Node/npm/sandbox-runtime and Python dependencies"
    )
    if args.all:
        print("Also: locked Trivy, gh, gcloud, optional Codex (no login)")
    if args.dry_run:
        print("Dry run only. No downloads, writes, login, scan or source changes.")
        return 0
    os.umask(0o077)
    state = ROOT / ".teate"
    state.mkdir(exist_ok=True)
    bins = state / "bin"
    bins.mkdir(exist_ok=True)
    mise = bootstrap(state, system, arch)
    env = mise_environment(state)
    config = state / "tool-config"
    config.mkdir(exist_ok=True)
    for name in ("mise.toml", "mise.lock"):
        shutil.copy2(ROOT / "tools" / name, config / name)
    subprocess.run([str(mise), "trust", str(config / "mise.toml")], check=True, env=env, timeout=30)
    tools = ["osv-scanner", "node"] + (["trivy", "gh", "gcloud"] if args.all else [])
    subprocess.run(
        [str(mise), "-C", str(config), "install", "--locked", *["http:" + t for t in tools]],
        check=True,
        env=env,
        timeout=600,
    )
    for tool in tools:
        folder = Path(
            subprocess.run(
                [str(mise), "-C", str(config), "where", "http:" + tool],
                check=True,
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            ).stdout.strip()
        )
        link(folder / ("trivy" if tool == "trivy" else "bin/" + tool), bins / tool)
        if tool == "node":
            link(folder / "bin/npm", bins / "npm")
    (state / "npm-user.conf").write_text("")
    (state / "npm-global.conf").write_text("")
    env["PATH"] = str(bins) + os.pathsep + env.get("PATH", os.defpath)
    install_npm_bundle("runtime", state, bins / "npm", bins, env)
    if args.all:
        install_npm_bundle("codex", state, bins / "npm", bins, env)
    python = state / "python"
    if not (python / "bin/python3").is_file():
        venv.EnvBuilder(with_pip=True).create(python)
    subprocess.run(
        [
            str(python / "bin/python3"),
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--disable-pip-version-check",
            "-r",
            str(ROOT / "tools/requirements.lock"),
        ],
        check=True,
        env=env,
        timeout=180,
    )
    git = shutil.which("git")
    if git:
        link(Path(git).resolve(), bins / "git")
    link(mise, bins / "mise")
    envfile = state / "env.sh"
    envfile.write_text(
        "# Generated by Teate; no login or shell-profile changes.\nexport PATH="
        + shlex.quote(str(python / "bin") + os.pathsep + str(bins))
        + ':"$PATH"\nexport CLOUDSDK_PYTHON='
        + shlex.quote(str(python / "bin/python3"))
        + "\n"
    )
    print("Installed. Run:\n  source " + shlex.quote(str(envfile)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
