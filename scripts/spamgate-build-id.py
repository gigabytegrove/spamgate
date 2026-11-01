#!/usr/bin/env python3
"""Reserve SpamGate build identities using the America/New_York wall-clock hour.

The source version is independent of this ID. The automatic build in an hour
has no suffix. Manual invocations reserve a..z atomically within the output
directory. No build ID is silently recycled after a failed build.
"""
import argparse
import datetime as dt
import fcntl
import os
from pathlib import Path
import re
import stat
import sys
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")
ID_RE = re.compile(r"^[0-9]{8}-(?:[01][0-9]|2[0-3])[a-z]?$")
LEDGER = ".spamgate-build-ids"


def base_id(instant: dt.datetime) -> str:
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("build timestamp needs an explicit UTC offset")
    return instant.astimezone(ET).strftime("%Y%m%d-%H")


def reserve(out: Path, base: str, mode: str, letter: str | None) -> str:
    if not re.fullmatch(r"\d{8}-(?:[01]\d|2[0-3])", base):
        raise ValueError("invalid build hour")
    if mode not in ("automatic", "manual"):
        raise ValueError("mode must be automatic or manual")
    if letter is not None and (mode != "manual" or not re.fullmatch("[a-z]", letter)):
        raise ValueError("letter a-z is only valid for manual builds")
    out.mkdir(parents=True, exist_ok=True)
    info = out.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("build directory cannot be a symlink or group/world writable")
    fd = os.open(out / LEDGER, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        current = (out / LEDGER).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or                 stat.S_IMODE(info.st_mode) != 0o600 or not os.path.samestat(info, current):
            raise ValueError("unsafe build reservation ledger")
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        entries = set(os.read(fd, 1 << 18).decode("ascii").splitlines())
        if mode == "automatic":
            selected = base
        elif letter is not None:
            selected = base + letter
        else:
            selected = next((base + ch for ch in "abcdefghijklmnopqrstuvwxyz" if base + ch not in entries), "")
        if not selected:
            raise ValueError("all 26 manual build letters are already reserved this hour")
        if not ID_RE.fullmatch(selected) or selected in entries:
            raise ValueError("build ID already reserved: " + selected)
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, (selected + "\n").encode("ascii"))
        os.fsync(fd)
        return selected
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["automatic", "manual"], default="manual")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--letter", help="optional explicit manual build suffix a-z")
    parser.add_argument("--at", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        instant = dt.datetime.fromisoformat(args.at) if args.at else dt.datetime.now(dt.timezone.utc)
        build = reserve(args.out, base_id(instant), args.mode, args.letter)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"SpamGate build version reservation failed: {exc}", file=sys.stderr)
        return 1
    print(build)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
