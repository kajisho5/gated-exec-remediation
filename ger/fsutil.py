"""Shared file system parts (no external processes).

- resolve(): walks to the target from / one element at a time with O_PATH|O_NOFOLLOW|O_DIRECTORY and returns the fd of the parent directory.
  Rejects an intermediate element that is a symbolic link or not a directory. To prevent TOCTOU replacement of intermediate elements after the check,
  every later read and write (stat / open / rename / link) is relative to this parent fd.
- tree_hash(): hash of a directory tree, ger-tree-v1 (definition shared with ZES; docs/design/design.md §11.3)
- read_file(): reads a regular file relative to the parent fd and checks that it matches the earlier (st_dev, st_ino)
"""
from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import dataclass, field

O_PATH = getattr(os, "O_PATH", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
# On macOS without O_PATH, open for reading (each directory needs read permission)
DIR_FLAGS = (O_PATH if O_PATH else os.O_RDONLY) | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC

TREE_MAX_ENTRIES = 50000
TREE_MAX_BYTES = 2 * 1024 ** 3
TREE_MAX_DEPTH = 256
EDIT_MAX_BYTES = 1024 * 1024


class FsError(Exception):
    """A state that cannot be checked or breaks the rules. applied=True means "a change may have been made"."""

    def __init__(self, message: str, applied: bool = False):
        super().__init__(message)
        self.applied = applied


Ident = tuple[int, int, int]


def ident_of(st: os.stat_result) -> Ident:
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Resolved:
    """Result of resolve(). The caller closes parent_fd with close() (registering it in an FdPool closes all at once)."""
    path: str
    parent_fd: int
    name: str
    st: os.stat_result | None  # lstat of the last element (None if it does not exist)
    parent_path: str = ""

    def lstat(self) -> os.stat_result:
        return os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)

    def close(self) -> None:
        try:
            os.close(self.parent_fd)
        except OSError:
            pass


@dataclass
class FdPool:
    fds: list = field(default_factory=list)

    def add(self, r: Resolved) -> Resolved:
        self.fds.append(r)
        return r

    def close(self) -> None:
        for r in self.fds:
            r.close()
        self.fds.clear()


def split_abs(path: str) -> list[str]:
    if not path.startswith("/") or "\0" in path:
        raise FsError("must be an absolute path (no NUL characters)")
    parts = [p for p in path.split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise FsError("the path must not contain . / ..")
    return parts


def open_dir(path: str) -> int:
    """Opens the directory of path (O_PATH), checking that there is no symbolic link on the way."""
    parts = split_abs(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        for p in parts:
            try:
                nfd = os.open(p, DIR_FLAGS, dir_fd=fd)
            except OSError as e:
                if e.errno in (errno.ENOTDIR, errno.ELOOP):
                    raise FsError(f"the path contains a symbolic link or a non-directory: /{p}") from None
                raise
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def resolve(path: str, must_exist: bool = True) -> Resolved:
    parts = split_abs(path)
    if not parts:
        raise FsError("/ itself cannot be a target")
    parent = "/" + "/".join(parts[:-1])
    fd = open_dir(parent)
    name = parts[-1]
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        if must_exist:
            os.close(fd)
            raise
        st = None
    except BaseException:
        os.close(fd)
        raise
    return Resolved(path, fd, name, st, parent)


def kind_of(st: os.stat_result) -> str:
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISDIR(st.st_mode):
        return "tree"
    return "special"


def open_file(dir_fd: int, name: str, expect: os.stat_result | None = None) -> int:
    fd = os.open(name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise FsError("not a regular file")
        if expect is not None and (st.st_dev, st.st_ino) != (expect.st_dev, expect.st_ino):
            raise FsError("the target was replaced while it was being checked")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(dir_fd: int, name: str, expect: os.stat_result | None = None, limit: int | None = None) -> bytes:
    fd = open_file(dir_fd, name, expect)
    with os.fdopen(fd, "rb") as f:
        if limit is not None:
            data = f.read(limit + 1)
            if len(data) > limit:
                raise FsError(f"the file is too large (limit {limit} bytes)")
            return data
        return f.read()


def hash_file(dir_fd: int, name: str, expect: os.stat_result | None = None) -> str:
    fd = open_file(dir_fd, name, expect)
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def readlink(dir_fd: int, name: str) -> str:
    return os.readlink(name, dir_fd=dir_fd)


@dataclass
class TreeInfo:
    hash: str
    entries: int
    bytes: int
    modes: dict  # relative path (str, surrogateescape) -> mode (masked with 0o7777). Symbolic links are not included
    kinds: dict  # relative path -> "f" / "d"


def tree_hash(dir_fd: int, name: str, root_dev: int | None = None) -> TreeInfo:
    """ger-tree-v1. Entries (the root is ".") sorted in ascending order of the relative path bytes, each line being
    type \\0 relpath \\0 mode(4 octal digits) \\0 (file: size \\0 sha256hex / link: readlink / directory: empty) \\n
    and the SHA-256 of their concatenation. mtime / ctime / uid are not included.
    Rejects exceeding the entry count or total size limit, FIFOs, sockets, devices, a different st_dev, and regular files with st_nlink > 1."""
    lines: list[tuple[bytes, bytes]] = []
    modes: dict = {}
    kinds: dict = {}
    total = 0
    top = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=dir_fd)
    try:
        st0 = os.fstat(top)
        dev = st0.st_dev if root_dev is None else root_dev
        if st0.st_dev != dev:
            raise FsError("the tree is on a different device")
        lines.append((b".", b"d\0.\0" + f"{st0.st_mode & 0o7777:04o}".encode() + b"\0\n"))
        modes["."] = st0.st_mode & 0o7777
        kinds["."] = "d"
        stack: list[tuple[int, bytes, int]] = [(top, b"", 0)]
        opened = [top]
        while stack:
            dfd, prefix, depth = stack.pop()
            if depth > TREE_MAX_DEPTH:
                raise FsError("the tree is too deep")
            for n in os.listdir(dfd):
                rel_b = prefix + os.fsencode(n)
                rel_s = os.fsdecode(rel_b)
                st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
                if st.st_dev != dev:
                    raise FsError(f"the tree contains a mount boundary (a different device): {rel_s}")
                if len(lines) >= TREE_MAX_ENTRIES:
                    raise FsError(f"the tree has too many entries (limit {TREE_MAX_ENTRIES})")
                m = f"{st.st_mode & 0o7777:04o}".encode()
                if stat.S_ISLNK(st.st_mode):
                    lines.append((rel_b, b"l\0" + rel_b + b"\0" + m + b"\0" + os.fsencode(os.readlink(n, dir_fd=dfd)) + b"\n"))
                elif stat.S_ISREG(st.st_mode):
                    if st.st_nlink > 1:
                        raise FsError(f"the tree contains a hard-linked file (rejected because the content would remain under another name): {rel_s}")
                    total += st.st_size
                    if total > TREE_MAX_BYTES:
                        raise FsError("the total size of the tree exceeds the limit (2 GiB)")
                    hx = hash_file(dfd, n, st)[len("sha256:"):]
                    lines.append((rel_b, b"f\0" + rel_b + b"\0" + m + b"\0" + str(st.st_size).encode() + b"\0" + hx.encode() + b"\n"))
                    modes[rel_s] = st.st_mode & 0o7777
                    kinds[rel_s] = "f"
                elif stat.S_ISDIR(st.st_mode):
                    lines.append((rel_b, b"d\0" + rel_b + b"\0" + m + b"\0\n"))
                    modes[rel_s] = st.st_mode & 0o7777
                    kinds[rel_s] = "d"
                    cfd = os.open(n, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=dfd)
                    opened.append(cfd)
                    stack.append((cfd, rel_b + b"/", depth + 1))
                else:
                    raise FsError(f"the tree contains a FIFO, socket or device: {rel_s}")
        for fd in opened[1:]:
            os.close(fd)
    finally:
        os.close(top)
    lines.sort(key=lambda x: x[0])
    h = hashlib.sha256()
    for _, ln in lines:
        h.update(ln)
    return TreeInfo("sha256:" + h.hexdigest(), len(lines), total, modes, kinds)


def set_tree_modes(dir_fd: int, name: str, modes: dict) -> None:
    """Sets modes (relative path -> mode) on the tree. Children first, parents last (the parent's x bit is not dropped first)."""
    order = sorted(modes, key=lambda r: (0 if r == "." else r.count("/") + 1), reverse=True)
    for rel in order:
        mode = modes[rel]
        path = name if rel == "." else name + "/" + rel
        # Intermediate elements are inside the store GER created (or the original location being rolled back). The last element is not followed
        parts = path.split("/")
        dfd = dir_fd
        opened = []
        try:
            for p in parts[:-1]:
                nfd = os.open(p, DIR_FLAGS, dir_fd=dfd)
                opened.append(nfd)
                dfd = nfd
            last = parts[-1]
            st = os.stat(last, dir_fd=dfd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                continue
            flags = os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            if stat.S_ISDIR(st.st_mode):
                flags |= O_DIRECTORY
            try:
                fd = os.open(last, flags, dir_fd=dfd)
            except PermissionError:
                fd = None
            if fd is not None:
                try:
                    os.fchmod(fd, mode)
                finally:
                    os.close(fd)
            else:
                os.chmod(last, mode, dir_fd=dfd)
        finally:
            for fd in opened:
                os.close(fd)


def locked_modes(kinds: dict) -> dict:
    """Mode after quarantine: files 0400, directories 0500 (execute and write bits dropped)."""
    return {rel: (0o500 if k == "d" else 0o400) for rel, k in kinds.items()}


def xattrs(fd: int) -> list[str]:
    try:
        names = os.listxattr(fd)
    except (AttributeError, OSError):
        return []
    return [n for n in names if n != "security.selinux"]


def is_under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/") or root == "/"
