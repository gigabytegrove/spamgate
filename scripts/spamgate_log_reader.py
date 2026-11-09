"""Bounded, read-only Postfix log reader for plain and gzip-rotated files.

No live journal access, decompression to disk, subprocesses, or MTA changes.
"""
import gzip
import os
import pathlib
import stat
import zlib

MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65536
GZIP_MAGIC = b"\x1f\x8b"


def bounded_log_lines(path):
    """Yield decoded log lines; refuse unsafe paths and corrupt/oversized input.

    The 64 MiB bound applies independently to compressed input and expanded
    content. A read is bounded before decoding, including a single huge line.
    The caller is responsible for supplying logs oldest to newest.
    """
    target = pathlib.Path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_LOG_BYTES:
        raise ValueError("log must be a regular file within 64 MiB")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(target, flags)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (not stat.S_ISREG(opened.st_mode) or
                not os.path.samestat(before, opened) or
                opened.st_size > MAX_LOG_BYTES):
            raise ValueError("log identity changed during open or exceeds 64 MiB")
        magic = source.read(2)
        source.seek(0)
        compressed = magic == GZIP_MAGIC
        if target.suffix.lower() == ".gz" and not compressed:
            raise ValueError(".gz log has no gzip header")
        stream = gzip.GzipFile(fileobj=source, mode="rb") if compressed else source
        total = 0
        try:
            while True:
                raw = stream.readline(MAX_LINE_BYTES + 1)
                if not raw:
                    break
                total += len(raw)
                if len(raw) > MAX_LINE_BYTES or total > MAX_LOG_BYTES:
                    raise ValueError("oversized Postfix log line or expanded file")
                yield raw.decode("utf-8", "replace")
            # Revalidate the directory entry as well as the open descriptor.
            # Rotation can replace/unlink a pathname without changing the
            # inode still held open by this reader.
            try:
                current_path = target.lstat()
            except FileNotFoundError as exc:
                raise ValueError("Postfix log changed during evidence read") from exc
            if (not stat.S_ISREG(current_path.st_mode) or
                    not os.path.samestat(opened, current_path)):
                raise ValueError("Postfix log changed during evidence read")
            # Evidence must come from one stable file snapshot. In-place writes,
            # truncation and replacement during a scan invalidate the result.
            after = os.fstat(source.fileno())
            if (not os.path.samestat(opened, after) or
                    after.st_size != opened.st_size or
                    after.st_mtime_ns != opened.st_mtime_ns or
                    after.st_ctime_ns != opened.st_ctime_ns):
                raise ValueError("Postfix log changed during evidence read")
        except (OSError, EOFError, zlib.error) as exc:
            raise ValueError("corrupt or unreadable Postfix log") from exc
        finally:
            if compressed:
                stream.close()
