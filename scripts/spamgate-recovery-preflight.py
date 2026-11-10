#!/usr/bin/env python3
"""Read-only preflight for native SpamGate offline recovery.

This tool never stops services, changes mail configuration, or invokes restore.
It emits machine-readable findings and exits nonzero on unsafe conditions.
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
        findings.append("data path must be absolute")
    if path.is_symlink() or not path.is_dir():
        findings.append("data root must be a real directory")
        return findings
    root = path.resolve()
    if root == Path("/"):
        findings.append("filesystem root cannot be used as data root")
        return findings
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            child = Path(directory) / name
            try:
                info = child.lstat()
            except OSError as exc:
                findings.append("unreadable entry: " + str(child) + ": " + str(exc))
                continue
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
