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


def check(path):
    findings = []
    if not path.is_absolute():
        return ["data path must be absolute"]
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

    def walk_error(exc):
        findings.append("directory traversal failed: " + str(exc))

    for directory, dirs, files in os.walk(path, topdown=True, followlinks=False,
                                           onerror=walk_error):
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
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="/opt/spamgate/data")
    args = parser.parse_args(argv)
    path = Path(args.data)
    try:
        findings = check(path)
    except OSError as exc:
        findings = ["filesystem inspection failed: " + str(exc)]
    print(json.dumps({"data": str(path), "safe_for_offline_snapshot": not findings,
                      "findings": findings}, sort_keys=True))
    return 0 if not findings else 2


if __name__ == "__main__":
    sys.exit(main())
