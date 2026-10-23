"""Shared part of the operations that rewrite files (edit_json / edit_toml / remove_line / disable_mcp_server).

params always has file_sha256 (the content at preview time) and expected_after_sha256 (the content after the change). Approvers
approve the exact bytes after the change. apply stops if its recomputed result differs from this value.
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
        raise ActionError(f"params.{name} must be sha256:<64 hex digits>")


def merged_ops(items: list[Item], key: str = "ops") -> list:
    """Union of the ops of a group's items (identical ops are merged). file_sha256 / expected_after_sha256 must match."""
    p0 = items[0].action["params"]
    seen, out = set(), []
    for it in items:
        p = it.action["params"]
        for k in ("file_sha256", "expected_after_sha256", "format"):
            if p.get(k) != p0.get(k):
                raise ActionError(f"params.{k} differs between items of the same group")
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
    """compute(path, data: bytes, ops) -> bytes after the change. The definition T checks (H / K / T-3) run inside compute."""
    a0 = items[0].action
    target = a0["target"]
    p0 = a0["params"]
    check_sha(p0.get("file_sha256"), "file_sha256")
    check_sha(p0.get("expected_after_sha256"), "expected_after_sha256")
    ops = merged_ops(items, "lines" if type_ == "remove_line" else "ops")
    res = ctx.pool.add(fsutil.resolve(target))
    base.check_regular(res.st)
    if ctx.store_dev is not None and res.st.st_dev != ctx.store_dev:
        raise ActionError("the target is on a different device from the quarantine store (rejected because the file before the edit cannot be kept in the store;"
                          " set GER_QUARANTINE_DIR to a store on the same device)")
    if ctx.euid != 0 and res.st.st_uid != ctx.euid:
        raise ActionError("cannot rewrite: not the owner")
    if res.st.st_size > fsutil.EDIT_MAX_BYTES:
        raise ActionError(f"files up to {fsutil.EDIT_MAX_BYTES} bytes can be edited")
    fd = fsutil.open_file(res.parent_fd, res.name, res.st)
    try:
        xs = fsutil.xattrs(fd)
    finally:
        os.close(fd)
    if xs:
        raise ActionError("a file with extended attributes (xattr) cannot be rewritten (they would be lost when replaced by rename)")
    data = fsutil.read_file(res.parent_fd, res.name, res.st, limit=fsutil.EDIT_MAX_BYTES)
    cur = sha256(data)
    digest = sha256(canonical(ops))
    if cur == p0["expected_after_sha256"] and cur != p0["file_sha256"]:
        return EditStep(items, target, res, data, data, type_, digest, noop=True)
    if cur != p0["file_sha256"]:
        raise ActionError("the target content changed since preview (approval) (does not match params.file_sha256). Start again from preview")
    new = compute(target, data, ops)
    if sha256(new) != p0["expected_after_sha256"]:
        raise ActionError("the computed result does not match expected_after_sha256 (differs from the approved change)")
    return EditStep(items, target, res, data, new, type_, digest)


def decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ActionError("a file that cannot be read as UTF-8 cannot be edited") from None


def unified_diff(path: str, old: bytes, new: bytes) -> str:
    import difflib
    a = old.decode("utf-8", "replace").splitlines(keepends=True)
    b = new.decode("utf-8", "replace").splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path + " (after)"))
