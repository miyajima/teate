"""Small durable control receipts; never persist candidate worktrees or credentials."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

from .model import TeateError, canonical

ALLOWED = re.compile(r"(?:intel/(?:jpcert|jvn|nodejs|summary)\.json|intel/events/[a-f0-9]{64}\.json|autopilot/(?:result|queue)\.json|autopilot/investigations/[a-f0-9]{64}/attempt\.json)")


def export(state: Path) -> bytes:
    files = {}
    candidates = [*(state/"intel").glob("*.json"), state/"autopilot/result.json", state/"autopilot/queue.json",
                  *(state/"intel/events").glob("*.json"),
                  *(state/"autopilot/investigations").glob("*/attempt.json")]
    for path in candidates:
        name = str(path.relative_to(state))
        if not path.is_file() or not ALLOWED.fullmatch(name):
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(state.resolve()):
            raise TeateError("Unsafe control-state path")
        if path.stat().st_size > 2_000_000 or len(files) >= 2000:
            raise TeateError("Control-state history needs a larger private store")
        files[name] = json.loads(path.read_text())
    data = canonical(files).encode()
    if len(data) > 8_000_000:
        raise TeateError("Control-state history needs a larger private store")
    return gzip.compress(data, mtime=0)


def restore(state: Path, data: bytes):
    import io

    with gzip.GzipFile(fileobj=io.BytesIO(data)) as file:
        raw = file.read(8_000_001)
    if len(raw) > 8_000_000:
        raise TeateError("Control-state response exceeds size limit")
    files = json.loads(raw)
    if not isinstance(files, dict) or len(files) > 2000:
        raise TeateError("Invalid control-state manifest")
    for name in files:
        if not ALLOWED.fullmatch(name) or not (state/name).resolve().is_relative_to(state.resolve()):
            raise TeateError("Unsafe remote control-state path")
    for name, content in files.items():
        path = state/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content,ensure_ascii=False,indent=2)+'\n')
