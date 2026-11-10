#!/usr/bin/env python3
"""Read-only native SpamGate recovery filesystem preflight.

A clean result is necessary, not sufficient, for an offline snapshot. No service
state, database transaction, or mail disposition is modified or certified.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys


def nested_mounts(path, mountinfo="/proc/self/mountinfo"):
    """Find mounts nested under data, including same-device bind mounts.

    Linux mountinfo uses octal escapes for spaces and other path bytes.
    Failure to inspect the mount table is an unsafe/unknown result, not clean.
    """
    def unescape(value):
        import re
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)

    root = str(path)
    mounts = []
    try:
        with open(mountinfo, encoding="utf-8") as stream:
            for line in stream:
                fields = line.split(" - ", 1)[0].split()
                if len(fields) < 5:
                    raise ValueError("malformed mountinfo record")
                target = unescape(fields[4])
                if target == root or target.startswith(root.rstrip("/") + "/"):
                    mounts.append(target)
    except (OSError, UnicodeError, ValueError) as exc:
        return [], "mount table cannot be inspected: " + str(exc)
    return mounts, None


def check(path):
    findings = []
    if not path.is_absolute():
        return ["data path must be absolute"]
    if any(part in (".", "..") for part in str(path).split("/")):
        return ["data path must not contain dot or parent traversal components"]
    if path == Path("/"):
        return ["filesystem root cannot be used as data root"]

    # Path.is_symlink() on the final component alone misses symlinked parents.
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except OSError as exc:
            findings.append("unreadable path component: " + str(component) + ": " + str(exc))
            return findings
        if stat.S_ISLNK(info.st_mode):
            findings.append("symlinked path component: " + str(component))
            return findings
    try:
        root_info = path.stat()
    except OSError as exc:
        return ["data root cannot be inspected: " + str(exc)]
    if not stat.S_ISDIR(root_info.st_mode):
        return ["data root must be a real directory"]
    root_device = root_info.st_dev
    mounts, mount_error = nested_mounts(path)
    if mount_error:
        findings.append(mount_error)
    nested = {mount for mount in mounts if mount != str(path)}
    for mount in sorted(nested):
        findings.append("nested mount point: " + mount)

    def walk_error(exc):
        findings.append("directory traversal failed: " + str(exc))

    for directory, dirs, files in os.walk(path, topdown=True, followlinks=False,
                                           onerror=walk_error):
        # Never descend into a known nested mount, even when the underlying
        # device number is identical (bind mounts). The tree is already unsafe.
        dirs[:] = [name for name in dirs if str(Path(directory) / name) not in nested]
        for name in dirs + files:
            child = Path(directory) / name
            try:
                info = child.lstat()
            except OSError as exc:
                findings.append("unreadable entry: " + str(child) + ": " + str(exc))
                continue
            if info.st_dev != root_device:
                findings.append("filesystem boundary: " + str(child))
            if stat.S_ISLNK(info.st_mode):
                findings.append("symlink: " + str(child))
            elif stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                findings.append("hardlinked file: " + str(child))
            elif not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                findings.append("special file: " + str(child))
    # Detect changes to root metadata while scanning; this is not an atomic
    # filesystem snapshot and cannot eliminate concurrent replacement races.
    try:
        final_root = path.lstat()
        if (final_root.st_dev, final_root.st_ino, final_root.st_mtime_ns,
                final_root.st_ctime_ns) != (root_info.st_dev, root_info.st_ino,
                root_info.st_mtime_ns, root_info.st_ctime_ns):
            findings.append("data root changed during inspection")
    except OSError as exc:
        findings.append("data root disappeared during inspection: " + str(exc))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="/opt/spamgate/data")
    args = parser.parse_args(argv)
    path = Path(args.data)
    try:
        if any(part in (".", "..") for part in args.data.split("/")):
            findings = ["data path must not contain dot or parent traversal components"]
        else:
            findings = check(path)
    except OSError as exc:
        findings = ["filesystem inspection failed: " + str(exc)]
    print(json.dumps({"data": str(path), "safe_for_offline_snapshot": not findings,
                      "findings": findings}, sort_keys=True))
    return 0 if not findings else 2


if __name__ == "__main__":
    sys.exit(main())
