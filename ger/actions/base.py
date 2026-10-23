"""操作の共通部品: 例外、item / ステップの型、隔離ストアへの移動と戻し、ファイルの差し替え。

各操作のモジュールは次を持つ:
  TYPE, REVERSIBLE, DESTRUCTIVE（承認者 2 名を要するか）, ORDER（実行順。参照を取り除く編集 → quarantine → chmod → checklist）
  validate_params(params)               形の検査（actions.schema.json に加えて意味の検査）
  prepare(ctx, items) -> Step           事前検証（G-7 / G-9 / G-10）。変更はしない
  preview(ctx, items) -> PreviewResult  ger preview 用。params の派生値（ハッシュ・ops）を埋める。変更はしない
Step は apply(rt) / rollback(rt) を持ち、undo（JSON にできる dict）をジャーナルに残す。
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field

from .. import fsutil, store
from ..fsutil import FsError, Resolved, ident_of


class ActionError(Exception):
    """applied=True は「変更は既に行われた可能性があり、検証できなかった」ことを示す（ロールバック不能）。"""

    def __init__(self, message: str, applied: bool = False):
        super().__init__(message)
        self.applied = applied


@dataclass
class Item:
    finding_id: str
    action: dict
    approved_by: list
    index: int
    level: str = ""


@dataclass
class Ctx:
    plan: dict
    scope_roots: list
    scope_home: str | None
    pool: fsutil.FdPool
    protected_paths: set
    protected_ino: set
    euid: int = field(default_factory=os.geteuid)
    store_dev: int | None = None


@dataclass
class PreviewResult:
    params: dict
    summary: str
    diff: str | None = None


class Runtime:
    """1 回の apply / restore / recover の実行時情報（隔離ストアの run とジャーナル）。"""

    def __init__(self, run_id: str, journal, plan_id: str | None, plan_hash: str | None, clock):
        self.run_id, self.journal, self.plan_id, self.plan_hash, self.clock = run_id, journal, plan_id, plan_hash, clock
        self.seq = 0
        self.step_no = 0

    def new_entry(self) -> store.Entry:
        self.seq += 1
        return store.Entry(self.run_id, self.seq)

    def note(self, step_no: int, undo: dict) -> None:
        if self.journal is not None:
            self.journal.write({"event": "step", "step": step_no, "undo": undo})


class Step:
    type = ""
    order = 9
    noop = False  # already_compliant

    def __init__(self, items: list[Item], target: str | None):
        self.items, self.target = items, target
        self.undo: dict = {}

    @property
    def finding_ids(self) -> list[str]:
        return [i.finding_id for i in self.items]

    @property
    def group(self) -> str | None:
        return self.items[0].action.get("group")

    def before_after(self) -> tuple[str | None, str | None]:
        return None, None

    def apply(self, rt: Runtime) -> None:
        raise NotImplementedError

    def rollback(self, rt: Runtime) -> None:
        raise NotImplementedError

    def result_extra(self) -> dict:
        return {}

    def audit(self) -> dict:
        b, a = self.before_after()
        return {"type": self.type, "target": self.target, "finding_ids": self.finding_ids, "before": b, "after": a,
                **self.result_extra()}


def same_group_params(items: list[Item], keys=None) -> dict:
    """group の item の params が一致すること（quarantine など、まとめても 1 回の操作になるもの）。"""
    p0 = items[0].action["params"]
    for it in items[1:]:
        if it.action["params"] != p0:
            raise ActionError("同じ group の item の params が一致しません")
    return p0


# --- 隔離ストアへの移動 -------------------------------------------------------------------------
def lock_payload(efd: int, kind: str, tree_kinds: dict | None) -> None:
    if kind == "file":
        fd = os.open("payload", os.O_RDONLY | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC | fsutil.O_NONBLOCK, dir_fd=efd)
        try:
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
    elif kind == "tree":
        fsutil.set_tree_modes(efd, "payload", fsutil.locked_modes(tree_kinds))


def unlock_payload(efd: int, kind: str, mode: int, tree_modes: dict | None) -> None:
    if kind == "file":
        fd = os.open("payload", os.O_RDONLY | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC | fsutil.O_NONBLOCK, dir_fd=efd)
        try:
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    elif kind == "tree":
        fsutil.set_tree_modes(efd, "payload", tree_modes)


def move_in(rt: Runtime, res: Resolved, kind: str, expect_ident, digest: str, tree: fsutil.TreeInfo | None,
            meta: dict, undo_list: list, step_no: int) -> dict:
    """res を隔離ストアへ rename で移し、mode を落とし、マニフェストを書く。undo_list に途中経過を積む。"""
    entry = rt.new_entry()
    efd = entry.create()
    u = {"op": "move", "qid": entry.qid, "orig": res.path, "kind": kind, "stage": "entry",
         "mode": res.st.st_mode & 0o7777, "ident": [res.st.st_dev, res.st.st_ino],
         "tree_modes": tree.modes if tree else None}
    undo_list.append(u)
    rt.note(step_no, {"entries": undo_list})
    try:
        cur = res.lstat()
        if ident_of(cur) != tuple(expect_ident):
            raise ActionError("事前検証の後に対象が差し替えられました")
        os.rename(res.name, "payload", src_dir_fd=res.parent_fd, dst_dir_fd=efd)
        u["stage"] = "moved"
        rt.note(step_no, {"entries": undo_list})
        pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
        if (pst.st_dev, pst.st_ino) != (cur.st_dev, cur.st_ino):
            raise ActionError("移した後の実体が一致しません", applied=True)
        lock_payload(efd, kind, tree.kinds if tree else None)
        u["stage"] = "locked"
        locked = fsutil.tree_hash(efd, "payload", pst.st_dev).hash if kind == "tree" else digest
        manifest = {"schema": "ger-quarantine-manifest/1", "quarantine_id": entry.qid, "operation": "quarantine",
                    "original_path": res.path, "kind": kind, "ident": [cur.st_dev, cur.st_ino],
                    "mode": cur.st_mode & 0o7777, "uid": cur.st_uid, "gid": cur.st_gid, "mtime_ns": cur.st_mtime_ns,
                    "hash": digest, "locked_hash": locked, "tree_modes": tree.modes if tree else None,
                    "tree_kinds": tree.kinds if tree else None,
                    "created_at": rt.clock().strftime("%Y-%m-%dT%H:%M:%SZ"), "plan_id": rt.plan_id,
                    "plan_hash": rt.plan_hash, **meta}
        u["manifest_sha256"] = store.write_json_excl(efd, "manifest.json", manifest)
        u["stage"] = "done"
        rt.note(step_no, {"entries": undo_list})
        return u
    finally:
        os.close(efd)


def move_out(u: dict, verify_digest: bool = False) -> None:
    """move_in の逆。元の場所が空いていることを確かめてから、mode を戻し rename で戻す。"""
    if u["stage"] == "entry":
        return  # まだ移していない
    efd = store.open_entry(u["qid"])
    try:
        res = fsutil.resolve(u["orig"], must_exist=False)
        try:
            if res.st is not None:
                raise ActionError(f"元の場所に別のものがあるため戻せません: {u['orig']}")
            pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
            if [pst.st_dev, pst.st_ino] != list(u["ident"]):
                raise ActionError("隔離ストアの中身が差し替えられています")
            # rename の後なら mode を元に戻す（mode を落とす途中で失敗した場合も、元の mode をすべて書き直す）
            unlock_payload(efd, u["kind"], u["mode"], u.get("tree_modes"))
            os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
            after = os.stat(res.name, dir_fd=res.parent_fd, follow_symlinks=False)
            if [after.st_dev, after.st_ino] != list(u["ident"]):
                raise ActionError("戻した後の実体が一致しません", applied=True)
        finally:
            res.close()
        if u["stage"] == "done":
            try:
                store.write_json_excl(efd, "rolled_back.json", {"quarantine_id": u["qid"]})
            except FileExistsError:
                pass
    finally:
        os.close(efd)


# --- ファイルの差し替え（edit_json / edit_toml / remove_line） ---------------------------------
def replace_file(rt: Runtime, res: Resolved, expect_ident, before_sha: str, new_bytes: bytes, after_sha: str,
                 meta: dict, undo: dict, step_no: int) -> None:
    """一時ファイルに書いて fsync → 元のファイルを隔離ストアにハードリンク（バックアップ）→ 同一性を照合して rename。"""
    st0 = res.st
    tmp = f".ger-{rt.run_id}-{rt.seq + 1}.tmp"
    entry = rt.new_entry()
    undo.update(op="edit", qid=entry.qid, target=res.path, tmp=tmp, stage="start", mode=st0.st_mode & 0o7777,
                ident=[st0.st_dev, st0.st_ino], before_sha256=before_sha, after_sha256=after_sha)
    rt.note(step_no, undo)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC, 0o600,
                 dir_fd=res.parent_fd)
    undo["stage"] = "tmp"
    try:
        os.write(fd, new_bytes)
        os.fchmod(fd, st0.st_mode & 0o7777)
        if rt_is_root() and (st0.st_uid, st0.st_gid) != (os.geteuid(), os.getegid()):
            os.fchown(fd, st0.st_uid, st0.st_gid)
        os.fsync(fd)
    finally:
        os.close(fd)
    efd = entry.create()
    try:
        cur = res.lstat()
        if ident_of(cur) != tuple(expect_ident):
            raise ActionError("事前検証の後に対象が差し替えられました")
        os.link(res.name, "payload", src_dir_fd=res.parent_fd, dst_dir_fd=efd, follow_symlinks=False)
        undo["stage"] = "linked"
        rt.note(step_no, undo)
        pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
        cur2 = res.lstat()
        if (pst.st_dev, pst.st_ino) != (cur.st_dev, cur.st_ino) or (cur2.st_dev, cur2.st_ino) != (cur.st_dev, cur.st_ino) \
                or cur2.st_mtime_ns != cur.st_mtime_ns or cur2.st_size != cur.st_size:
            raise ActionError("バックアップの作成中に対象が差し替えられました")
        os.rename(tmp, res.name, src_dir_fd=res.parent_fd, dst_dir_fd=res.parent_fd)
        undo["stage"] = "replaced"
        rt.note(step_no, undo)
        nst = res.lstat()
        undo["new_ident"] = [nst.st_dev, nst.st_ino]
        got = fsutil.hash_file(res.parent_fd, res.name, nst)
        if got != after_sha:
            raise ActionError("適用後のファイルの SHA-256 が expected_after_sha256 と一致しません（V）")
        # バックアップ（元の i-node）の mode を落とす（元の mode はマニフェストに残す）
        bfd = os.open("payload", os.O_RDONLY | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC | fsutil.O_NONBLOCK, dir_fd=efd)
        try:
            os.fchmod(bfd, 0o400)
        finally:
            os.close(bfd)
        manifest = {"schema": "ger-quarantine-manifest/1", "quarantine_id": entry.qid, "operation": "edit_backup",
                    "original_path": res.path, "kind": "file", "ident": [cur.st_dev, cur.st_ino],
                    "mode": cur.st_mode & 0o7777, "uid": cur.st_uid, "gid": cur.st_gid, "mtime_ns": cur.st_mtime_ns,
                    "hash": before_sha, "after_sha256": after_sha, "created_at": rt.clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "plan_id": rt.plan_id, "plan_hash": rt.plan_hash, **meta}
        undo["manifest_sha256"] = store.write_json_excl(efd, "manifest.json", manifest)
        undo["stage"] = "done"
        rt.note(step_no, undo)
    finally:
        os.close(efd)


def rt_is_root() -> bool:
    return os.geteuid() == 0


def unreplace_file(u: dict) -> None:
    """replace_file の逆。現在のファイルが GER の書いたもの（after_sha256）であることを確かめてから、
    編集後のファイルを隔離ストアに残し（ハードリンク）、バックアップを rename で戻す。何も削除しない。"""
    stage = u.get("stage")
    res = fsutil.resolve(u["target"], must_exist=False)
    try:
        if stage in ("start", "tmp", "linked"):
            # まだ置き換えていない。一時ファイル（GER が作ったもの）だけを片付ける
            try:
                tst = os.stat(u["tmp"], dir_fd=res.parent_fd, follow_symlinks=False)
                if stat.S_ISREG(tst.st_mode):
                    os.unlink(u["tmp"], dir_fd=res.parent_fd)
            except FileNotFoundError:
                pass
            return
        efd = store.open_entry(u["qid"])
        try:
            if res.st is None:
                raise ActionError(f"編集したファイルがありません: {u['target']}")
            if "new_ident" in u and [res.st.st_dev, res.st.st_ino] != list(u["new_ident"]):
                raise ActionError("編集後のファイルが差し替えられているため戻せません")
            cur = fsutil.hash_file(res.parent_fd, res.name, res.st)
            if cur != u["after_sha256"]:
                raise ActionError("編集後のファイルが GER の書いた内容から変わっているため戻せません")
            pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
            if [pst.st_dev, pst.st_ino] != list(u["ident"]):
                raise ActionError("隔離ストアのバックアップが差し替えられています")
            unlock_payload(efd, "file", u["mode"], None)
            try:
                os.link(res.name, "replaced", src_dir_fd=res.parent_fd, dst_dir_fd=efd, follow_symlinks=False)
            except FileExistsError:
                pass
            os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
            back = os.stat(res.name, dir_fd=res.parent_fd, follow_symlinks=False)
            if [back.st_dev, back.st_ino] != list(u["ident"]):
                raise ActionError("戻した後の実体が一致しません", applied=True)
            if fsutil.hash_file(res.parent_fd, res.name, back) != u["before_sha256"]:
                raise ActionError("戻した後の内容が編集前と一致しません", applied=True)
            if stage == "done":
                try:
                    store.write_json_excl(efd, "rolled_back.json", {"quarantine_id": u["qid"]})
                except FileExistsError:
                    pass
        finally:
            os.close(efd)
    finally:
        res.close()


def rollback_undo(undo: dict) -> None:
    """ジャーナルの undo 記録だけから戻す（executor のロールバックと ger recover の共通部分）。"""
    if undo.get("op") == "edit":
        unreplace_file(undo)
    elif "entries" in undo:
        for u in reversed(undo["entries"]):
            move_out(u)


def check_regular(st, what="対象"):
    if stat.S_ISLNK(st.st_mode):
        raise ActionError(f"{what}がシンボリックリンクです")
    if not stat.S_ISREG(st.st_mode):
        raise ActionError(f"{what}が通常ファイルではありません")
    if st.st_nlink != 1:
        raise ActionError(f"{what}にハードリンクがあります（st_nlink={st.st_nlink}。別名に内容が残るため拒否）")


__all__ = ["ActionError", "FsError", "Item", "Ctx", "Step", "Runtime", "PreviewResult"]
