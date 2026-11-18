"""Bound captured output without limiting deployment artifacts or project files."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time


def capture(argv, *, cwd=None, env=None, timeout=120, limit=12000, merge_stderr=False):
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
        start_new_session=True,
    )
    output = bytearray()
    deadline = time.monotonic() + timeout
    timed_out = limited = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), min(4096, limit + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    output.extend(chunk)
                    if len(output) > limit:
                        limited = True
                        break
                if limited:
                    break
        if timed_out or limited:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        else:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    finally:
        process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return {
        "exit_code": process.returncode,
        "raw": bytes(output),
        "timed_out": timed_out,
        "output_limited": limited,
    }
