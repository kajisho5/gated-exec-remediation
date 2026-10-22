"""chmod 操作。外部コマンドを使わず os.fchmod / os.chmod で行う。

- params は {"mode": "0NNN"}（8 進 3 桁）のみ。setuid / setgid / sticky ビットは付与できない
- 対象は事前検証時の (st_dev, st_ino, st_ctime_ns) と一致することを適用直前に確認する（差し替え検出）。
  i-node 番号は削除・再作成で再利用されうるため、ctime も含めて同一実体を判定する
- 再帰しない。シンボリックリンクは辿らない
"""
from __future__ import annotations

import os
import re
import stat

TYPE = "chmod"
REVERSIBLE = True
_MODE = re.compile(r"^0[0-7]{3}$")


class ActionError(Exception):
    pass


def parse_params(params: dict) -> int:
    if set(params) != {"mode"} or not isinstance(params["mode"], str) or not _MODE.match(params["mode"]):
        raise ActionError('params は {"mode": "0NNN"}（8 進 3 桁、特殊ビットなし）のみ受け付けます')
    return int(params["mode"], 8)


def fmt(mode: int) -> str:
    return f"0{mode & 0o777:03o}" if mode & 0o7000 == 0 else f"{mode & 0o7777:04o}"


def inspect(target: str) -> os.stat_result:
    """事前検証。対象が通常ファイルかディレクトリで、所有者として変更できることを確認する。"""
    st = os.lstat(target)
    if stat.S_ISLNK(st.st_mode):
        raise ActionError("シンボリックリンクは対象にできません")
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise ActionError("通常ファイルまたはディレクトリのみ対象にできます")
    if os.geteuid() != 0 and st.st_uid != os.geteuid():
        raise ActionError("所有者ではないため権限を変更できません")
    return st


Ident = tuple[int, int, int]


def ident_of(st: os.stat_result) -> Ident:
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def _same(st: os.stat_result, ident: Ident) -> bool:
    return ident_of(st) == ident


def set_mode(target: str, mode: int, ident: Ident) -> Ident:
    """ident と同じ実体にだけ mode を設定し、変更後の ident を返す（ロールバック時の照合に使う）。"""
    st = os.lstat(target)
    if stat.S_ISLNK(st.st_mode) or not _same(st, ident):
        raise ActionError("事前検証後に対象が差し替えられました")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if stat.S_ISDIR(st.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(target, flags)
    except PermissionError:
        fd = None  # 読み取り権限が無い（例: 0000）。lstat の前後確認で代替する
    if fd is not None:
        try:
            if not _same(os.fstat(fd), ident):
                raise ActionError("事前検証後に対象が差し替えられました")
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    else:
        os.chmod(target, mode)
    after = os.lstat(target)
    if stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != ident[:2]:
        raise ActionError("適用中に対象が差し替えられました")
    if after.st_mode & 0o7777 != mode:
        raise ActionError(f"適用後の権限が {fmt(after.st_mode)} です（期待値 {fmt(mode)}）")
    return ident_of(after)
