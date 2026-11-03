"""Bounded command capture shared by CLI execution and credential refresh."""

import math
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

MAX_OUTPUT = 1024 * 1024


class CaptureError(Exception):
    pass


@dataclass
class Captured:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool


def kill_group(proc):
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass


def capture(
    argv, *, timeout=None, cwd=None, env=None, input_data=None, inherit_stdin=False
):
    if timeout is not None:
        try:
            valid = (
                type(timeout) in (float, int)
                and math.isfinite(timeout)
                and 0 < timeout <= threading.TIMEOUT_MAX
            )
        except OverflowError:
            valid = False
        if not valid:
            raise CaptureError(
                "command timeout must be positive, finite, and within the platform limit"
            )
    deadline = None if timeout is None else time.monotonic() + timeout

    def remaining():
        return None if deadline is None else max(0, deadline - time.monotonic())

    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE
        if input_data is not None
        else (None if inherit_stdin else subprocess.DEVNULL),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    output = {}
    failures = []

    def read_pipe(name, pipe):
        try:
            data = pipe.read(MAX_OUTPUT + 1)
            if len(data) > MAX_OUTPUT:
                failures.append("command output exceeds 1 MiB")
                kill_group(proc)
            else:
                output[name] = data
        except OSError:
            failures.append("could not read command output")
            kill_group(proc)
        finally:
            pipe.close()

    def write_input():
        try:
            proc.stdin.write(input_data)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    workers = [
        threading.Thread(target=read_pipe, args=(name, pipe), daemon=True)
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr))
    ]
    if input_data is not None:
        workers.append(threading.Thread(target=write_input, daemon=True))
    timed_out = False
    try:
        for worker in workers:
            worker.start()
        try:
            proc.wait(timeout=remaining())
            for worker in workers:
                worker.join(timeout=remaining())
            if any(worker.is_alive() for worker in workers):
                timed_out = True
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        kill_group(proc)
        proc.wait()
        for worker in workers:
            if worker.ident is not None:
                worker.join(timeout=1)
        # Unstarted workers cannot own their pipe on a thread-start failure.
        for worker, pipe in zip(workers, (proc.stdout, proc.stderr, proc.stdin)):
            if worker.ident is None and pipe is not None:
                pipe.close()
    if failures:
        raise CaptureError(failures[0])
    return Captured(
        -getattr(signal, "SIGKILL", 9) if timed_out else proc.returncode,
        output.get("stdout", b""),
        output.get("stderr", b""),
        timed_out,
    )
