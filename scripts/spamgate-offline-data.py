#!/usr/bin/env python3
"""Offline, fail-closed SpamGate data-directory snapshot and restore.

This tool never stops services, changes Postfix, or alters a running mail host.
The operator MUST stop SpamGate before snapshot or restore. Acknowledgement is
an explicit safety gate, not an automatic process-state detector.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

SCHEMA = 1
MAX_FILES = 100000
MAX_BYTES = 100 * 1024 ** 3
CHUNK = 1024 * 1024


class SnapshotError(Exception):
    pass


def regular_metadata(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SnapshotError(f"not a unique regular file: {path}")
    return info


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def walk(root):
    if not root.is_dir() or root.is_symlink():
        raise SnapshotError("source must be a real directory")
    results = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_dir():
                raise SnapshotError(f"unsafe directory: {path}")
        for name in files:
            path = Path(directory) / name
            info = regular_metadata(path)
            relative = path.relative_to(root).as_posix()
            if not relative or any(part in (".", "..") for part in Path(relative).parts):
                raise SnapshotError("unsafe relative path")
            results.append((relative, path, info))
            if len(results) > MAX_FILES:
                raise SnapshotError("file count exceeds limit")
    return sorted(results)


def digest_copy(source, destination=None):
    sha = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(source, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SnapshotError(f"unsafe opened file: {source}")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            while True:
                block = handle.read(CHUNK)
                if not block:
                    break
                total += len(block)
                if total > MAX_BYTES:
                    raise SnapshotError("file exceeds size limit")
                sha.update(block)
                if destination is not None:
                    destination.write(block)
        after = os.fstat(fd)
        current = os.lstat(source)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or identity(before) != identity(current):
            raise SnapshotError(f"file changed while copying: {source}")
    finally:
        os.close(fd)
    return total, sha.hexdigest()


def validate_relative(name):
    if (not isinstance(name, str) or not name or name.startswith("/")
            or "\\" in name or "\x00" in name or
            any(p in ("", ".", "..") for p in name.split("/"))):
        raise SnapshotError("unsafe manifest path")
    return name


def manifest_entries(snapshot):
    manifest_path = snapshot / "manifest.json"
    regular_metadata(manifest_path)
    if manifest_path.stat().st_size > 32 * 1024 * 1024:
        raise SnapshotError("manifest too large")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SnapshotError("duplicate JSON key")
            result[key] = value
        return result
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(SnapshotError("invalid JSON constant")))
    if type(manifest) is not dict or set(manifest) != {"schema", "files"} or manifest["schema"] != SCHEMA:
        raise SnapshotError("unsupported manifest")
    files = manifest["files"]
    if type(files) is not list or len(files) > MAX_FILES:
        raise SnapshotError("invalid file list")
    seen = set()
    total = 0
    for entry in files:
        if type(entry) is not dict or set(entry) != {"path", "bytes", "sha256", "mode"}:
            raise SnapshotError("invalid file entry")
        name = validate_relative(entry["path"])
        if name in seen:
            raise SnapshotError("duplicate file path")
        seen.add(name)
        size, sha, mode = entry["bytes"], entry["sha256"], entry["mode"]
        if (type(size) is not int or size < 0 or type(sha) is not str
                or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)
                or type(mode) is not int or not 0 <= mode <= 0o777):
            raise SnapshotError("invalid file metadata")
        total += size
        if total > MAX_BYTES:
            raise SnapshotError("snapshot exceeds size limit")
    return files


def verify(snapshot):
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise SnapshotError("snapshot must be a real directory")
    # The snapshot root is an exact-format artifact, not an arbitrary directory.
    # Refuse undeclared payloads and symlinked metadata before trusting it.
    allowed = {"manifest.json", "files"}
    if {p.name for p in snapshot.iterdir()} != allowed:
        raise SnapshotError("unexpected snapshot root entry")
    if (snapshot / "manifest.json").is_symlink():
        raise SnapshotError("symlinked manifest refused")
    payload = snapshot / "files"
    if payload.is_symlink() or not payload.is_dir():
        raise SnapshotError("unsafe snapshot payload directory")
    files = manifest_entries(snapshot)
    expected = {entry["path"] for entry in files}
    actual = {name for name, _, _ in walk(snapshot / "files")}
    if expected != actual:
        raise SnapshotError("snapshot contents differ from manifest")
    for entry in files:
        path = snapshot / "files" / entry["path"]
        metadata = regular_metadata(path)
        if stat.S_IMODE(metadata.st_mode) & 0o777 != entry["mode"]:
            raise SnapshotError(f"snapshot permission mismatch: {entry['path']}")
        size, digest = digest_copy(path)
        if size != entry["bytes"] or digest != entry["sha256"]:
            raise SnapshotError(f"snapshot checksum mismatch: {entry['path']}")
    return files


def directory_inventory(root):
    """Capture directory identity and entries to detect concurrent mutations."""
    inventory = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        path = Path(directory)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
            raise SnapshotError(f"unsafe directory: {path}")
        for name in dirs:
            child = path / name
            if child.is_symlink() or not child.is_dir():
                raise SnapshotError(f"unsafe directory: {child}")
        inventory[path.relative_to(root).as_posix()] = (
            info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns,
            tuple(sorted(dirs)), tuple(sorted(files)))
        if len(inventory) > MAX_FILES:
            raise SnapshotError("directory count exceeds limit")
    return inventory


def verify_restored_stage(stage, entries):
    """Verify actual restored bytes before atomic publication."""
    expected = {entry["path"] for entry in entries}
    actual = {name for name, _, _ in walk(stage)}
    if actual != expected:
        raise SnapshotError("restored file inventory mismatch")
    for entry in entries:
        path = stage / entry["path"]
        metadata = regular_metadata(path)
        if stat.S_IMODE(metadata.st_mode) & 0o777 != entry["mode"]:
            raise SnapshotError(f"restored permission mismatch: {entry['path']}")
        size, digest = digest_copy(path)
        if (size, digest) != (entry["bytes"], entry["sha256"]):
            raise SnapshotError(f"restored checksum mismatch: {entry['path']}")


def snapshot(source, target):
    if source.is_symlink() or not source.is_dir():
        raise SnapshotError("source must be a real directory")
    if target.exists() or target.is_symlink():
        raise SnapshotError("snapshot target already exists")
    if not target.parent.is_dir():
        raise SnapshotError("snapshot parent must exist")
    # Refuse placing a snapshot inside the live source.
    if source.resolve() == target.parent.resolve() or source.resolve() in target.parent.resolve().parents:
        raise SnapshotError("snapshot destination inside source")
    if target.resolve() == source.resolve() or target.resolve() in source.resolve().parents:
        raise SnapshotError("snapshot target contains source")
    stage = Path(tempfile.mkdtemp(prefix=".spamgate-snapshot-", dir=target.parent))
    try:
        (stage / "files").mkdir(mode=0o700)
        original_directories = directory_inventory(source)
        entries = []
        total = 0
        for name, path, info in walk(source):
            destination = stage / "files" / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with destination.open("xb") as output:
                size, sha = digest_copy(path, output)
                output.flush()
                os.fsync(output.fileno())
            current = regular_metadata(path)
            if (size != info.st_size or
                    (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_mode) !=
                    (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns, current.st_mode)):
                raise SnapshotError("source metadata changed during snapshot")
            mode = stat.S_IMODE(info.st_mode) & 0o777
            os.chmod(destination, mode)
            entries.append({"path": name, "bytes": size, "sha256": sha, "mode": mode})
            total += size
            if total > MAX_BYTES:
                raise SnapshotError("snapshot exceeds size limit")
        if directory_inventory(source) != original_directories:
            raise SnapshotError("source directory tree changed during snapshot")
        with (stage / "manifest.json").open("x", encoding="utf-8") as output:
            json.dump({"schema": SCHEMA, "files": entries}, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        verify(stage)
        for directory, _, _ in os.walk(stage, topdown=False):
            fsync_dir(directory)
        stage.rename(target)
        fsync_dir(target.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def restore(source, target):
    if target.exists() or target.is_symlink():
        raise SnapshotError("restore target must not exist")
    if not target.parent.is_dir():
        raise SnapshotError("restore parent must exist")
    if source.resolve() == target.parent.resolve() or source.resolve() in target.parent.resolve().parents:
        raise SnapshotError("restore target inside snapshot")
    if target.resolve() == source.resolve() or target.resolve() in source.resolve().parents:
        raise SnapshotError("restore target contains snapshot")
    files = verify(source)
    stage = Path(tempfile.mkdtemp(prefix=".spamgate-restore-", dir=target.parent))
    try:
        for entry in files:
            destination = stage / entry["path"]
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with destination.open("xb") as output:
                size, digest = digest_copy(source / "files" / entry["path"], output)
                output.flush()
                os.fsync(output.fileno())
            if (size, digest) != (entry["bytes"], entry["sha256"]):
                raise SnapshotError("source changed during restore")
            os.chmod(destination, entry["mode"])
        verify_restored_stage(stage, files)
        for directory, _, _ in os.walk(stage, topdown=False):
            fsync_dir(directory)
        stage.rename(target)
        fsync_dir(target.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("snapshot", "verify", "restore"):
        cmd = sub.add_parser(action)
        cmd.add_argument("--source", required=True)
        if action != "verify":
            cmd.add_argument("--target", required=True)
            cmd.add_argument("--acknowledge-offline", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        source = Path(args.source).absolute()
        if args.action == "verify":
            files = verify(source)
        elif args.action == "snapshot":
            snapshot(source, Path(args.target).absolute())
            files = verify(Path(args.target).absolute())
        else:
            restore(source, Path(args.target).absolute())
            files = verify(source)
        print(json.dumps({"result": "ok", "action": args.action, "files": len(files)}))
        return 0
    except (SnapshotError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"spamgate offline data operation refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
