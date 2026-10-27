"""Explicit sandbox-runtime profiles; failures never trigger an unconfined retry."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

from .model import TeateError, digest, write_json
from .process import capture

NETWORK = {
    "offline": [],
    "npm": ["registry.npmjs.org"],
    "osv": ["api.osv.dev", "api.deps.dev", "deps.dev", "registry.npmjs.org"],
}
SYSTEM_READ = [
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
    "/System",
    "/Library/Apple",
    "/Library/Developer",
    "/opt/homebrew",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ld.so.cache",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/dev",
    "/proc/self",
    "/proc/cpuinfo",
    "/proc/meminfo",
]
PROXY_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
)


def execute(
    root: Path,
    argv: list[str],
    *,
    cwd: Path | None = None,
    network: str = "offline",
    timeout: int = 120,
) -> dict:
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 100
        or not all(isinstance(a, str) and "\x00" not in a for a in argv)
        or type(timeout) is not int
        or not 1 <= timeout <= 600
    ):
        raise TeateError("invalid_sandbox_command")
    if network not in NETWORK:
        raise TeateError("unregistered_sandbox_network")
    root = root.resolve()
    cwd = (cwd or root).resolve()
    if not cwd.is_relative_to(root):
        raise TeateError("sandbox_cwd_outside_candidate")
    srt = shutil.which("srt")
    executable = shutil.which(argv[0]) if not Path(argv[0]).is_absolute() else argv[0]
    if not srt or not executable:
        return {"status": "blocked", "reason": "sandbox_runtime_or_tool_unavailable"}
    executable = str(Path(executable).resolve())
    with tempfile.TemporaryDirectory(prefix="teate-sandbox-") as temp:
        scratch = Path(temp).resolve()
        home = scratch / "home"
        home.mkdir()
        (home / "user.npmrc").write_text("")
        (home / "global.npmrc").write_text("")
        # Grant only the installed tool distribution, never its enclosing .teate,
        # user home, live project, or ledger. Python/Node runtimes are system paths.
        read = [str(Path(p).resolve()) for p in SYSTEM_READ if Path(p).exists()] + [
            str(root),
            str(scratch),
            sys.base_prefix,
        ]
        paths = []
        for name in (srt, executable, shutil.which("node")):
            if name:
                resolved = Path(name).resolve()
                parent = (
                    resolved.parent.parent if resolved.parent.name == "bin" else resolved.parent
                )
                for ancestor in resolved.parents:
                    if ancestor.name == "node_modules":
                        parent = ancestor
                read.append(str(parent))
                paths.append(str(resolved.parent))
        env = {k: os.environ[k] for k in PROXY_ENV if k in os.environ}
        for key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            if env.get(key) and Path(env[key]).is_file():
                read.append(str(Path(env[key]).resolve()))
        env.update(
            PATH=os.pathsep.join(dict.fromkeys([*paths, "/usr/local/bin", "/usr/bin", "/bin"])),
            HOME=str(home),
            TMPDIR=str(scratch),
            CI="true",
            npm_config_userconfig=str(home / "user.npmrc"),
            npm_config_globalconfig=str(home / "global.npmrc"),
            npm_config_cache=str(home / "npm-cache"),
            npm_config_ignore_scripts="true",
            npm_config_registry="https://registry.npmjs.org",
        )
        profile = {
            "filesystem": {
                "denyRead": ["/"],
                "allowRead": sorted(set(read)),
                "allowWrite": [str(root), str(scratch)],
                "denyWrite": [],
            },
            "network": {"allowedDomains": NETWORK[network], "deniedDomains": []},
        }
        settings = scratch / "settings.json"
        write_json(settings, profile)
        # macOS can deny DNS resolution even for "localhost". Address only SRT's
        # own authenticated loopback proxy numerically; retain its port, token,
        # domain filter and the inherited managed upstream proxy unchanged.
        launcher = scratch / "proxy-launcher.cjs"
        launcher.write_text("""const {spawnSync} = require('node:child_process');
for (const key of ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']) {
  if (!process.env[key]) continue;
  const url = new URL(process.env[key]);
  if (url.hostname === 'localhost') { url.hostname = '127.0.0.1'; process.env[key] = url.href; }
}
const result = spawnSync(process.argv[2], process.argv.slice(3), {stdio:'inherit', env:process.env});
if (result.error) { console.error(result.error.code); process.exit(126); }
process.exit(result.status === null ? 126 : result.status);
""")
        node = shutil.which("node")
        if not node:
            return {"status": "blocked", "reason": "sandbox_runtime_or_tool_unavailable"}
        command = [
            srt,
            "--settings",
            str(settings),
            "--",
            str(Path(node).resolve()),
            str(launcher),
            executable,
            *argv[1:],
        ]
        result = capture(
            command, cwd=cwd, env=env, timeout=timeout, limit=1_048_576, merge_stderr=True
        )
        raw, code, timed_out = result["raw"], result["exit_code"], result["timed_out"]
        excerpt = raw[-2000:].decode(errors="replace").replace(str(root), "<candidate>")
        blocked = code != 0 and any(
            s in excerpt.lower()
            for s in ("bwrap:", "sandbox-exec:", "sandbox dependencies", "sandbox initialization")
        )
        return {
            "status": "passed" if code == 0 else "blocked" if blocked else "failed",
            "exit_code": code,
            "timed_out": timed_out,
            "output_limited": result["output_limited"],
            "excerpt": excerpt,
            "output_id": digest(raw.decode(errors="replace")),
            "reason": "sandbox_not_permitted" if blocked else None,
        }
