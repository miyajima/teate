"""Narrow native updater: explicitly allowed Homebrew formulae in a maintenance window."""

from __future__ import annotations

import fcntl
import platform
import plistlib
import re
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .collect import run
from .model import TeateError, digest, load_json, utcnow, write_json


def in_window(window: dict, now: datetime | None = None) -> bool:
    if not window or not all(k in window for k in ("timezone", "start", "end")):
        return False
    current = (now or datetime.now(ZoneInfo(window["timezone"]))).astimezone(
        ZoneInfo(window["timezone"])
    )
    value = current.strftime("%H:%M")
    start, end = window["start"], window["end"]
    if not all(re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", x) for x in (start, end)):
        raise TeateError("Maintenance window times must be HH:MM")
    if start == end:
        return False
    return start <= value < end if start < end else value >= start or value < end


def upgrade_formula(formula: str, policy: dict, state: Path, *, apply: bool = False) -> dict:
    mac_policy = policy.get("mac", {})
    if not re.fullmatch(r"[a-z0-9][a-z0-9+@._-]*", formula):
        raise TeateError("Only a simple Homebrew formula name is accepted")
    if formula not in mac_policy.get("allowed_formulae", []):
        raise TeateError("Formula is not in the explicit update allowlist")
    operation = {"formula": formula, "action": "brew_upgrade", "apply": apply}
    if not apply:
        return operation
    if platform.system() != "Darwin":
        raise TeateError("Mac updates require the Mac worker")
    if mac_policy.get("allow_dependency_updates") is not True:
        raise TeateError(
            "Homebrew may update dependencies too; this scope must be explicitly enabled in policy"
        )
    if not in_window(mac_policy.get("maintenance_window", {})):
        raise TeateError("Outside the configured maintenance window")
    names = mac_policy.get("process_names", {}).get(formula, [])
    if not names:
        raise TeateError("Configure process_names for this formula before unattended updates")
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise TeateError("Invalid process name")
        active = run(["/usr/bin/pgrep", "-x", re.escape(name)])
        if active.returncode == 0:
            raise TeateError("A configured process is running; update deferred")
        if active.returncode != 1:
            raise TeateError("Unable to verify idle processes")
    state.mkdir(parents=True, exist_ok=True)
    # One global Homebrew lock: two formula operations may share dependencies.
    with (state / "homebrew.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TeateError("Another Homebrew update is running") from exc
        journal = state / ("operation-" + digest(formula)[:16] + ".json")
        if journal.exists() and load_json(journal).get("status") in {"running", "ambiguous"}:
            raise TeateError(
                "Prior update outcome is uncertain; inspect the operation journal before retrying"
            )
        before = run(["brew", "list", "--versions", formula])
        if before.returncode:
            raise TeateError(
                "Formula is not already installed; installation is outside this updater's scope"
            )
        operation.update(status="running", started_at=utcnow(), before=before.stdout.strip())
        write_json(journal, operation)
        try:
            result = run(["brew", "upgrade", "--formula", formula], timeout=1200)
            after = run(["brew", "list", "--versions", formula])
            if after.returncode:
                raise TeateError("Unable to verify the installed version")
            operation.update(
                status="completed" if result.returncode == 0 else "failed",
                completed_at=utcnow(),
                after=after.stdout.strip(),
                exit_code=result.returncode,
            )
            write_json(journal, operation)
        except TeateError:
            operation.update(status="ambiguous", completed_at=utcnow())
            write_json(journal, operation)
            raise
    return operation


def launch_agent(
    config: Path,
    state: Path,
    *,
    interval: int = 3600,
    repository: str | None = None,
    scanner: str = "osv",
) -> bytes:
    if interval < 3600:
        raise TeateError("Worker interval must be at least one hour")
    args = [
        sys.executable,
        "-m",
        "teate",
        "--config",
        str(config.resolve()),
        "run",
        "--scanner",
        scanner,
    ]
    if repository:
        args += ["--publish", repository]
    return plistlib.dumps(
        {
            "Label": "dev.teate.worker",
            "ProgramArguments": args,
            "WorkingDirectory": str(Path(__file__).resolve().parent.parent),
            "StartInterval": interval,
            "RunAtLoad": True,
            "EnvironmentVariables": {
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            },
            "StandardOutPath": str(state.resolve() / "worker.log"),
            "StandardErrorPath": str(state.resolve() / "worker-error.log"),
        },
        sort_keys=False,
    )
