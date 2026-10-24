"""Shared parts of the operations: exceptions, item / step types, moving into and out of the quarantine store, replacing files.

Each operation module has:
  TYPE, REVERSIBLE, DESTRUCTIVE (whether 2 approvers are required), ORDER (execution order: edits that remove references -> quarantine -> chmod -> checklist)
  validate_params(params)               shape check (meaning checks on top of actions.schema.json)
  prepare(ctx, items) -> Step           pre-validation (G-7 / G-9 / G-10). Changes nothing
  preview(ctx, items) -> PreviewResult  for ger preview. Fills the derived params values (hashes, ops). Changes nothing
A Step has apply(rt) / rollback(rt) and leaves undo (a dict that can be JSON) in the journal.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field

from .. import fsutil, store
from ..fsutil import FsError, Resolved, ident_of


class ActionError(Exception):
    """applied=True means "the change may already have been made and could not be verified" (rollback not possible).
    gate names the gate of a pre-validation failure (set for T-* violations, "G-10"); the message text never decides it."""

    def __init__(self, message: str, applied: bool = False, gate: str | None = None):
        super().__init__(message)
        self.applied = applied
        self.gate = gate


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
    """Runtime information of one apply / restore / recover (the quarantine store run and the journal)."""

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
    """The params of the group's items must match (for operations such as quarantine that stay one operation when grouped)."""
    p0 = items[0].action["params"]
    for it in items[1:]:
        if it.action["params"] != p0:
            raise ActionError("params differ between items of the same group")
    return p0


# --- Moving into the quarantine store ------------------------------------------------------------
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
    """Moves res into the quarantine store with rename, drops its mode and writes the manifest. Records progress in undo_list."""
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
            raise ActionError("the target was replaced after pre-validation")
        os.rename(res.name, "payload", src_dir_fd=res.parent_fd, dst_dir_fd=efd)
        u["stage"] = "moved"
        rt.note(step_no, {"entries": undo_list})
        pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
        if (pst.st_dev, pst.st_ino) != (cur.st_dev, cur.st_ino):
            raise ActionError("the moved object does not match", applied=True)
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


def _payload_ident(efd: int):
    try:
        pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return [pst.st_dev, pst.st_ino]


def _move_state(u: dict) -> str:
    """State of the object of move record u: "not_moved", "moved" (in the store) or "restored" (back at the original
    location, for example by a rollback killed before it was journaled). ActionError for any other state.

    Stage "entry" is noted before the rename, so a process killed right after the rename leaves "entry" with the object
    already in the store: the payload itself decides then."""
    try:
        efd = store.open_entry(u["qid"])
    except FileNotFoundError:
        if u["stage"] == "entry":
            return "not_moved"
        raise ActionError(f"the quarantine store entry {u['qid']} is missing") from None
    try:
        pid = _payload_ident(efd)
    finally:
        os.close(efd)
    res = fsutil.resolve(u["orig"], must_exist=False)
    try:
        orig = None if res.st is None else [res.st.st_dev, res.st.st_ino]
    finally:
        res.close()
    if pid == list(u["ident"]):
        if orig is not None:
            raise ActionError(f"cannot restore: something else is at the original location: {u['orig']}")
        return "moved"
    if pid is None and (u["stage"] == "entry" or orig == list(u["ident"])):
        return "not_moved" if u["stage"] == "entry" else "restored"
    raise ActionError(f"cannot restore: the quarantined object {u['qid']} is missing or was replaced")


def check_move(u: dict) -> None:
    """ActionError unless move_out(u) would put back exactly what GER moved (and nothing else is at the original location)."""
    _move_state(u)


def move_out(u: dict, verify_digest: bool = False) -> None:
    """Reverse of move_in. Checks that the original location is free, then restores the mode and moves it back with rename."""
    if u["stage"] == "entry" and _move_state(u) == "not_moved":
        return  # Not moved yet
    if u["stage"] != "entry" and _move_state(u) == "restored":
        return  # Already back
    efd = store.open_entry(u["qid"])
    try:
        res = fsutil.resolve(u["orig"], must_exist=False)
        try:
            if res.st is not None:
                raise ActionError(f"cannot restore: something else is at the original location: {u['orig']}")
            pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
            if [pst.st_dev, pst.st_ino] != list(u["ident"]):
                raise ActionError("the content of the quarantine store was replaced")
            # After the rename, restore the mode (even if dropping the mode failed halfway, all original modes are written again)
            unlock_payload(efd, u["kind"], u["mode"], u.get("tree_modes"))
            os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
            after = os.stat(res.name, dir_fd=res.parent_fd, follow_symlinks=False)
            if [after.st_dev, after.st_ino] != list(u["ident"]):
                raise ActionError("the restored object does not match", applied=True)
        finally:
            res.close()
        if u["stage"] == "done":
            try:
                store.write_json_excl(efd, "rolled_back.json", {"quarantine_id": u["qid"]})
            except FileExistsError:
                pass
    finally:
        os.close(efd)


# --- Replacing files (edit_json / edit_toml / remove_line) ---------------------------------------
def replace_file(rt: Runtime, res: Resolved, expect_ident, before_sha: str, new_bytes: bytes, after_sha: str,
                 meta: dict, undo: dict, step_no: int) -> None:
    """Write a temporary file and fsync -> hard-link the original file into the quarantine store (backup) -> check identity and rename."""
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
            raise ActionError("the target was replaced after pre-validation")
        os.link(res.name, "payload", src_dir_fd=res.parent_fd, dst_dir_fd=efd, follow_symlinks=False)
        undo["stage"] = "linked"
        rt.note(step_no, undo)
        pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
        cur2 = res.lstat()
        if (pst.st_dev, pst.st_ino) != (cur.st_dev, cur.st_ino) or (cur2.st_dev, cur2.st_ino) != (cur.st_dev, cur.st_ino) \
                or cur2.st_mtime_ns != cur.st_mtime_ns or cur2.st_size != cur.st_size:
            raise ActionError("the target was replaced while creating the backup")
        os.rename(tmp, res.name, src_dir_fd=res.parent_fd, dst_dir_fd=res.parent_fd)
        undo["stage"] = "replaced"
        rt.note(step_no, undo)
        nst = res.lstat()
        undo["new_ident"] = [nst.st_dev, nst.st_ino]
        got = fsutil.hash_file(res.parent_fd, res.name, nst)
        if got != after_sha:
            raise ActionError("the SHA-256 of the file after applying does not match expected_after_sha256 (V)")
        # Drop the mode of the backup (the original i-node); the original mode is kept in the manifest
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


def _edit_state(u: dict, res: Resolved) -> str:
    """State of the target of edit record u: "not_replaced", "replaced" (holds what GER wrote) or "restored" (the backup
    is back, for example by a rollback killed before it was journaled). ActionError for any other state.

    Stages before "replaced" are noted before the rename of the temporary file, so a process killed right after it
    leaves "linked": then the temporary file is gone and the target is another i-node with the content GER wrote."""
    stage = u.get("stage")
    cur = None if res.st is None else [res.st.st_dev, res.st.st_ino]
    if stage in ("start", "tmp", "linked"):
        if stage != "linked" or cur is None or cur == list(u["ident"]):
            return "not_replaced"
        try:
            os.stat(u["tmp"], dir_fd=res.parent_fd, follow_symlinks=False)
            return "not_replaced"
        except FileNotFoundError:
            pass
    efd = store.open_entry(u["qid"])
    try:
        pid = _payload_ident(efd)
    finally:
        os.close(efd)
    if cur is None:
        raise ActionError(f"the edited file is missing: {u['target']}")
    if pid is None and cur == list(u["ident"]) and stage not in ("start", "tmp", "linked"):
        if fsutil.hash_file(res.parent_fd, res.name, res.st) == u["before_sha256"]:
            return "restored"
    if "new_ident" in u and cur != list(u["new_ident"]):
        raise ActionError("cannot restore: the edited file was replaced")
    if not stat.S_ISREG(res.st.st_mode) or fsutil.hash_file(res.parent_fd, res.name, res.st) != u["after_sha256"]:
        raise ActionError("cannot restore: the edited file changed from the content GER wrote")
    if pid != list(u["ident"]):
        raise ActionError("the backup in the quarantine store was replaced")
    return "replaced"


def check_edit(u: dict) -> None:
    """ActionError unless unreplace_file(u) would restore the file from before the edit over exactly what GER wrote."""
    res = fsutil.resolve(u["target"], must_exist=False)
    try:
        _edit_state(u, res)
    finally:
        res.close()


def _drop_stale_backup_link(u: dict, res: Resolved) -> None:
    """A process killed between the backup hard link and the replacement leaves a second name of the unchanged target in
    the store (st_nlink 2, which GER itself refuses later). Only that extra name is removed; the content stays at the
    target, so nothing is deleted."""
    if res.st is None or [res.st.st_dev, res.st.st_ino] != list(u["ident"]):
        return
    try:
        efd = store.open_entry(u["qid"])
    except FileNotFoundError:
        return
    try:
        if _payload_ident(efd) == list(u["ident"]):
            try:
                os.stat("manifest.json", dir_fd=efd, follow_symlinks=False)
            except FileNotFoundError:
                os.unlink("payload", dir_fd=efd)
    finally:
        os.close(efd)


def unreplace_file(u: dict) -> None:
    """Reverse of replace_file. Checks that the current file is what GER wrote (after_sha256), then
    keeps the edited file in the quarantine store (hard link) and moves the backup back with rename. Deletes nothing."""
    stage = u.get("stage")
    res = fsutil.resolve(u["target"], must_exist=False)
    try:
        state = _edit_state(u, res)
        if state == "restored":
            return
        if state == "not_replaced":
            # Not replaced yet. Clean up only the temporary file (created by GER)
            try:
                tst = os.stat(u["tmp"], dir_fd=res.parent_fd, follow_symlinks=False)
                if stat.S_ISREG(tst.st_mode):
                    os.unlink(u["tmp"], dir_fd=res.parent_fd)
            except FileNotFoundError:
                pass
            _drop_stale_backup_link(u, res)
            return
        efd = store.open_entry(u["qid"])
        try:
            unlock_payload(efd, "file", u["mode"], None)
            try:
                os.link(res.name, "replaced", src_dir_fd=res.parent_fd, dst_dir_fd=efd, follow_symlinks=False)
            except FileExistsError:
                pass
            os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
            back = os.stat(res.name, dir_fd=res.parent_fd, follow_symlinks=False)
            if [back.st_dev, back.st_ino] != list(u["ident"]):
                raise ActionError("the restored object does not match", applied=True)
            if fsutil.hash_file(res.parent_fd, res.name, back) != u["before_sha256"]:
                raise ActionError("the restored content does not match the content before the edit", applied=True)
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
    """Restores only from the undo records in the journal (shared by executor rollback and ger recover)."""
    if undo.get("op") == "edit":
        unreplace_file(undo)
    elif "entries" in undo:
        for u in reversed(undo["entries"]):
            move_out(u)


def check_undo(undo: dict) -> None:
    """ActionError unless rollback_undo(undo) would undo exactly GER's change (ger recover checks every step first)."""
    if undo.get("op") == "edit":
        check_edit(undo)
    elif "entries" in undo:
        for u in undo["entries"]:
            check_move(u)


def check_regular(st, what="the target"):
    if stat.S_ISLNK(st.st_mode):
        raise ActionError(f"{what} is a symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise ActionError(f"{what} is not a regular file")
    if st.st_nlink != 1:
        raise ActionError(f"{what} has hard links (st_nlink={st.st_nlink}; rejected because the content would remain under another name)")


__all__ = ["ActionError", "FsError", "Item", "Ctx", "Step", "Runtime", "PreviewResult"]
