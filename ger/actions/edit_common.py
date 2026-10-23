"""ファイルを書き換える操作（edit_json / edit_toml / remove_line / disable_mcp_server）の共通部分。

params には必ず file_sha256（preview 時の内容）と expected_after_sha256（変更後の内容）がある。承認者は
変更後の正確なバイト列を承認することになる。apply は計算し直した結果がこの値と違えば止まる。
"""
from __future__ import annotations

import os
import re

from .. import fsutil
from ..core import canonical, sha256
from . import base
from .base import ActionError, Item, Step

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


def check_sha(v, name):
    if not isinstance(v, str) or not _SHA.fullmatch(v):
        raise ActionError(f"params.{name} は sha256:<64 桁の 16 進> であること")


def merged_ops(items: list[Item], key: str = "ops") -> list:
    """group の item の ops の和（同じ op は 1 つにまとめる）。file_sha256 / expected_after_sha256 は一致すること。"""
    p0 = items[0].action["params"]
    seen, out = set(), []
    for it in items:
        p = it.action["params"]
        for k in ("file_sha256", "expected_after_sha256", "format"):
            if p.get(k) != p0.get(k):
                raise ActionError(f"同じ group の item の params.{k} が一致しません")
        for o in p.get(key, []):
            c = canonical(o)
            if c not in seen:
                seen.add(c)
                out.append(o)
    return out


class EditStep(Step):
    order = 0

    def __init__(self, items, target, res, data: bytes, new: bytes, type_, ops_digest: str, noop=False):
        super().__init__(items, target)
        self.type, self.res, self.before_sha, self.new = type_, res, sha256(data), new
        self.after_sha = sha256(new)
        self.ident = fsutil.ident_of(res.st)
        self.ops_digest = ops_digest
        self.noop = noop

    def before_after(self):
        return (self.before_sha, self.after_sha)

    def result_extra(self):
        e = {"ops_digest": self.ops_digest}
        if self.undo.get("qid"):
            e.update(quarantine_ids=[self.undo["qid"]], manifest_sha256=self.undo.get("manifest_sha256"))
        return e

    def apply(self, rt):
        self.undo = {}
        base.replace_file(rt, self.res, self.ident, self.before_sha, self.new, self.after_sha,
                          {"finding_ids": self.finding_ids, "action_type": self.type, "ops_digest": self.ops_digest},
                          self.undo, rt.step_no)

    def rollback(self, rt):
        base.unreplace_file(self.undo)


def prepare_edit(ctx, items: list[Item], type_: str, compute) -> EditStep:
    """compute(path, data: bytes, ops) -> 変更後のバイト列。定義 T（H / K / T-3）の検査は compute の中で行う。"""
    a0 = items[0].action
    target = a0["target"]
    p0 = a0["params"]
    check_sha(p0.get("file_sha256"), "file_sha256")
    check_sha(p0.get("expected_after_sha256"), "expected_after_sha256")
    ops = merged_ops(items, "lines" if type_ == "remove_line" else "ops")
    res = ctx.pool.add(fsutil.resolve(target))
    base.check_regular(res.st)
    if ctx.store_dev is not None and res.st.st_dev != ctx.store_dev:
        raise ActionError("対象が隔離ストアと別のデバイスにあります（編集前のファイルをストアに残せないため拒否。"
                          "GER_QUARANTINE_DIR で同じデバイスのストアを指定してください）")
    if ctx.euid != 0 and res.st.st_uid != ctx.euid:
        raise ActionError("所有者ではないため書き換えられません")
    if res.st.st_size > fsutil.EDIT_MAX_BYTES:
        raise ActionError(f"編集できるファイルは {fsutil.EDIT_MAX_BYTES} バイトまでです")
    fd = fsutil.open_file(res.parent_fd, res.name, res.st)
    try:
        xs = fsutil.xattrs(fd)
    finally:
        os.close(fd)
    if xs:
        raise ActionError("拡張属性（xattr）があるファイルは書き換えられません（rename で置き換えると失われるため）")
    data = fsutil.read_file(res.parent_fd, res.name, res.st, limit=fsutil.EDIT_MAX_BYTES)
    cur = sha256(data)
    digest = sha256(canonical(ops))
    if cur == p0["expected_after_sha256"] and cur != p0["file_sha256"]:
        return EditStep(items, target, res, data, data, type_, digest, noop=True)
    if cur != p0["file_sha256"]:
        raise ActionError("対象の内容が preview（承認）の時から変わっています（params.file_sha256 と不一致）。preview からやり直してください")
    new = compute(target, data, ops)
    if sha256(new) != p0["expected_after_sha256"]:
        raise ActionError("計算した変更後の内容が expected_after_sha256 と一致しません（承認された変更と違います）")
    return EditStep(items, target, res, data, new, type_, digest)


def decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ActionError("UTF-8 として読めないファイルは編集できません") from None


def unified_diff(path: str, old: bytes, new: bytes) -> str:
    import difflib
    a = old.decode("utf-8", "replace").splitlines(keepends=True)
    b = new.decode("utf-8", "replace").splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path + " (after)"))
