"""Bounded, read-only subprocess capture for native host diagnostics.

Linux/POSIX only: callers must pass a fixed argv vector, never a shell command.
On failure the entire process group is killed, including children inheriting pipes.
No command output is included in exception messages.
"""
import os
import selectors
import signal
import subprocess
import time


class CommandProbeError(ValueError):
    """Safe, output-free command execution failure."""


def capture_command(argv, *, timeout=5.0, max_bytes=65536):
    """Return (stdout, stderr, exit_code), with independent hard byte limits.

    Enforces a wall-clock deadline for both the process and all inherited pipes.
    Output is read incrementally; a malicious subprocess cannot make the
    caller buffer unlimited data or wait indefinitely for a forked child.
    """
    if (os.name != "posix" or not isinstance(argv, (tuple, list)) or not argv
            or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv)
            or not 0 < timeout <= 120 or not 0 < max_bytes <= 1024 * 1024):
        raise CommandProbeError("invalid bounded command arguments")
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
    except OSError as exc:
        raise CommandProbeError("command could not be executed") from exc
    selector = selectors.DefaultSelector()
    completed = False
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CommandProbeError("command timed out")
            for key, _ in selector.select(remaining):
                name = key.data
                chunk = os.read(key.fileobj.fileno(), min(8192, max_bytes + 1 - len(output[name])))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[name].extend(chunk)
                if len(output[name]) > max_bytes:
                    raise CommandProbeError("command output exceeds limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CommandProbeError("command timed out")
        try:
            code = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise CommandProbeError("command timed out") from exc
        completed = True
        return bytes(output["stdout"]), bytes(output["stderr"]), code
    except (OSError, ValueError) as exc:
        if isinstance(exc, CommandProbeError):
            raise
        raise CommandProbeError("command pipe read failed") from exc
    finally:
        selector.close()
        # Kill descendants on failure before reaping the leader. Never send
        # signals using a PID after successful wait() has reaped that PID.
        if not completed:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1)
        proc.stdout.close()
        proc.stderr.close()
