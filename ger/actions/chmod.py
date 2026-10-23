"""chmod 操作。外部コマンドを使わず os.fchmod / os.chmod で行う。

- params は {"mode": "0NNN"}（8 進 3 桁）のみ。setuid / setgid / sticky ビットと world-writable は付与できない
- 現在の mode に無い権限を足す chmod は G-7 で拒否する（修復は権限を絞る操作に限る）
- 対象は事前検証時の (st_dev, st_ino, st_ctime_ns) と一致することを適用直前に確認する（差し替え検出）。
  i-node 番号は削除・再作成で再利用されうるため、ctime も含めて同一実体を判定する
- 再帰しない。シンボリックリンクは辿らない
"""
from __future__ import annotations

import os
import re
import stat

from .base import ActionError, PreviewResult, Step

TYPE = "chmod"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 2
_MODE = re.compile(r"^0[0-7]{3}$")


def parse_params(params: dict) -> int:
    if set(params) != {"mode"} or not isinstance(params["mode"], str) or not _MODE.fullmatch(params["mode"]):
        raise ActionError('params は {"mode": "0NNN"}（8 進 3 桁、特殊ビットなし）のみ受け付けます')
    mode = int(params["mode"], 8)
    if mode & 0o002:  # ZET の I-4 と同じ。現在の mode に権限を足さないこと（G-7）とは別に、静的に拒否する
        raise ActionError("他者の書き込み権限（world-writable）を付ける chmod は受け付けません")
    return mode


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
    # ここから先の失敗は変更済みの可能性がある（applied=True）
    try:
        after = os.lstat(target)
    except OSError as e:
        raise ActionError(f"適用後に対象を確認できません: {e}", applied=True) from e
    if stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != ident[:2]:
        raise ActionError("適用中に対象が差し替えられました", applied=True)
    if after.st_mode & 0o7777 != mode:
        raise ActionError(f"適用後の権限が {fmt(after.st_mode)} です（期待値 {fmt(mode)}）", applied=True)
    return ident_of(after)


def validate_params(params: dict) -> None:
    parse_params(params)


class ChmodStep(Step):
    type = TYPE
    order = ORDER

    def __init__(self, items, target, mode, ident, before):
        super().__init__(items, target)
        self.mode, self.ident, self.before = mode, ident, before
        self.noop = before == mode
        self.applied_ident = None

    def before_after(self):
        return fmt(self.before), fmt(self.mode)

    def apply(self, rt):
        self.applied_ident = set_mode(self.target, self.mode, self.ident)
        self.undo = {"op": "chmod", "target": self.target, "before": self.before, "ident": list(self.applied_ident)}
        rt.note(rt.step_no, self.undo)

    def rollback(self, rt):
        set_mode(self.target, self.before, self.applied_ident)


def rollback_undo(u: dict) -> None:
    set_mode(u["target"], u["before"], tuple(u["ident"]))


def prepare(ctx, items):
    """事前検証（G-7 / G-10）。chmod は現在の mode に無い権限を足せない（絞る操作だけ）。"""
    if len(items) != 1:
        raise ActionError("chmod は group にまとめられません")
    a = items[0].action
    t = a["target"]
    mode = parse_params(a["params"])
    st = inspect(t)
    if os.path.realpath(t) != t:
        raise ActionError("パスの途中にシンボリックリンクがあります")
    before = st.st_mode & 0o7777
    added = mode & ~before
    if added:  # 修復は権限を絞る操作に限る。改ざんされた plan でも権限を緩められないようにする
        raise ActionError(f"chmod {fmt(mode)} は現在の mode {fmt(before)} に無い権限（{added:04o}）を足します"
                          "（権限を絞る操作だけを受け付けます）")
    step = ChmodStep(items, t, mode, ident_of(st), before)
    step.st = st
    return step


def preview(ctx, items) -> PreviewResult:
    p = items[0].action["params"]
    parse_params(p)
    return PreviewResult(p, f"chmod {p['mode']}")
