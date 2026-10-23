"""ファイルシステムの共通部品（外部プロセスを使わない）。

- resolve(): 対象を / から 1 要素ずつ O_PATH|O_NOFOLLOW|O_DIRECTORY でたどり、親ディレクトリの fd を返す。
  途中の要素がシンボリックリンクや非ディレクトリなら拒否する。確かめた後に途中を差し替える TOCTOU を防ぐため、
  以後の読み書き（stat / open / rename / link）はすべてこの親 fd を基準に行う。
- tree_hash(): ディレクトリツリーのハッシュ ger-tree-v1（ZES と共通の定義。docs/design/design.md §11.3）
- read_file(): 親 fd 基準で通常ファイルを読み、事前の (st_dev, st_ino) と一致することを確かめる
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
# O_PATH が無い macOS では読み取りで開く（各ディレクトリに読み取り権限が要る）
DIR_FLAGS = (O_PATH if O_PATH else os.O_RDONLY) | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC

TREE_MAX_ENTRIES = 50000
TREE_MAX_BYTES = 2 * 1024 ** 3
TREE_MAX_DEPTH = 256
EDIT_MAX_BYTES = 1024 * 1024


class FsError(Exception):
    """確かめられない・規則に合わない状態。applied=True は「変更が行われた可能性がある」ことを示す。"""

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
    """resolve() の結果。parent_fd は呼び出し側が close() で閉じる（FdPool に登録すると一括で閉じる）。"""
    path: str
    parent_fd: int
    name: str
    st: os.stat_result | None  # 最後の要素の lstat（存在しなければ None）
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
        raise FsError("絶対パスであること（NUL 文字は不可）")
    parts = [p for p in path.split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise FsError("パスに . / .. を含めないこと")
    return parts


def open_dir(path: str) -> int:
    """path のディレクトリを、途中にシンボリックリンクが無いことを確かめながら開く（O_PATH）。"""
    parts = split_abs(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        for p in parts:
            try:
                nfd = os.open(p, DIR_FLAGS, dir_fd=fd)
            except OSError as e:
                if e.errno in (errno.ENOTDIR, errno.ELOOP):
                    raise FsError(f"パスの途中にシンボリックリンクまたはディレクトリ以外があります: /{p}") from None
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
        raise FsError("/ そのものは対象にできません")
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
            raise FsError("通常ファイルではありません")
        if expect is not None and (st.st_dev, st.st_ino) != (expect.st_dev, expect.st_ino):
            raise FsError("確かめている間に対象が差し替えられました")
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
                raise FsError(f"ファイルが大きすぎます（上限 {limit} バイト）")
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
    modes: dict  # 相対パス（str, surrogateescape）→ mode（0o7777 でマスク）。シンボリックリンクは含めない
    kinds: dict  # 相対パス → "f" / "d"


def tree_hash(dir_fd: int, name: str, root_dev: int | None = None) -> TreeInfo:
    """ger-tree-v1。エントリ（ルートは "."）を相対パスのバイト列の昇順に並べ、各行
    type \\0 relpath \\0 mode(4 桁 8 進) \\0 (ファイル: size \\0 sha256hex / リンク: readlink / ディレクトリ: 空) \\n
    を連結した SHA-256。mtime / ctime / uid は含めない。
    エントリ数・合計サイズの上限超過、FIFO・ソケット・デバイス、別の st_dev、st_nlink > 1 の通常ファイルは拒否する。"""
    lines: list[tuple[bytes, bytes]] = []
    modes: dict = {}
    kinds: dict = {}
    total = 0
    top = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=dir_fd)
    try:
        st0 = os.fstat(top)
        dev = st0.st_dev if root_dev is None else root_dev
        if st0.st_dev != dev:
            raise FsError("ツリーが別のデバイスにあります")
        lines.append((b".", b"d\0.\0" + f"{st0.st_mode & 0o7777:04o}".encode() + b"\0\n"))
        modes["."] = st0.st_mode & 0o7777
        kinds["."] = "d"
        stack: list[tuple[int, bytes, int]] = [(top, b"", 0)]
        opened = [top]
        while stack:
            dfd, prefix, depth = stack.pop()
            if depth > TREE_MAX_DEPTH:
                raise FsError("ツリーが深すぎます")
            for n in os.listdir(dfd):
                rel_b = prefix + os.fsencode(n)
                rel_s = os.fsdecode(rel_b)
                st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
                if st.st_dev != dev:
                    raise FsError(f"ツリーにマウント境界（別のデバイス）があります: {rel_s}")
                if len(lines) >= TREE_MAX_ENTRIES:
                    raise FsError(f"ツリーのエントリが多すぎます（上限 {TREE_MAX_ENTRIES}）")
                m = f"{st.st_mode & 0o7777:04o}".encode()
                if stat.S_ISLNK(st.st_mode):
                    lines.append((rel_b, b"l\0" + rel_b + b"\0" + m + b"\0" + os.fsencode(os.readlink(n, dir_fd=dfd)) + b"\n"))
                elif stat.S_ISREG(st.st_mode):
                    if st.st_nlink > 1:
                        raise FsError(f"ツリーにハードリンクされたファイルがあります（別名に内容が残るため拒否）: {rel_s}")
                    total += st.st_size
                    if total > TREE_MAX_BYTES:
                        raise FsError("ツリーの合計サイズが上限（2 GiB）を超えています")
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
                    raise FsError(f"ツリーに FIFO・ソケット・デバイスがあります: {rel_s}")
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
    """modes（相対パス → mode）をツリーに設定する。子を先に、親を後に（親の x を先に落とさない）。"""
    order = sorted(modes, key=lambda r: (0 if r == "." else r.count("/") + 1), reverse=True)
    for rel in order:
        mode = modes[rel]
        path = name if rel == "." else name + "/" + rel
        # パスの途中は GER が作ったストアの中（またはロールバック対象の元の位置）。末尾はリンクを辿らない
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
    """隔離後の mode: ファイルは 0400、ディレクトリは 0500（実行ビットと書き込みを落とす）。"""
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
