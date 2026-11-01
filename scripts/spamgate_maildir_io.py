"""Descriptor-anchored, read-only Maildir evidence I/O.

A Maildir supplied by an operator is not a trusted evidence source. Keep
new/cur traversal relative to an already opened root directory and reject
file substitutions or in-place mutations while reading message headers.
This does not authenticate the mailbox or freeze noncooperating writers.
"""
import contextlib
import os
import stat

_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


@contextlib.contextmanager
def open_directory(path):
    """Open a real directory and verify the lstat/open identity."""
    before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"not a real directory: {path}")
    fd = os.open(path, _DIRECTORY_FLAGS)
    try:
        after = os.fstat(fd)
        if not stat.S_ISDIR(after.st_mode) or not os.path.samestat(before, after):
            raise ValueError(f"directory changed during open: {path}")
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def open_maildir_child(root_fd, name):
    """Never resolve new/cur through a mutable pathname or symlink parent."""
    if name not in ("new", "cur"):
        raise ValueError("unsupported Maildir subdirectory")
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root_fd)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ValueError(f"Maildir {name} is not a directory")
        yield fd
    finally:
        os.close(fd)


def check_message_identity(listed, opened, finished):
    """Reject replacement and observed in-place writes during header reads."""
    if (not stat.S_ISREG(listed.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(finished.st_mode)
            or not os.path.samestat(listed, opened)
            or not os.path.samestat(opened, finished)
            or opened.st_size != finished.st_size
            or opened.st_mtime_ns != finished.st_mtime_ns
            or opened.st_ctime_ns != finished.st_ctime_ns):
        raise ValueError("Maildir message changed during evidence scan")
