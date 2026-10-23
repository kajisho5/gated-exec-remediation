"""ger restore - moves quarantined objects and files from before an edit back to their original location (a command outside the plan; Q-4).

restore-request.json (schemas/restore-request.schema.json):
  {"schema_version": "1.0", "restore_id": UUID, "created_at", "mode": "dry-run"|"apply",
   "entries": [{"quarantine_id", "manifest_sha256"}],
   "approval": {"restore_id", "approved_by": [2 or more], "approved_at", "approval_token"}}
approval_token is the SHA-256 of the canonical JSON of the request without approval and mode. Restoring "adds" something
(an exception to definition T), so it requires 2 approvers and, like ger, a mandatory dry-run that one apply uses up.

Preconditions: the SHA-256 of the manifest matches. For a quarantined object, the original path is free and the store content (hash after locking)
matches the manifest. For an edit backup, the current file must still be the content GER wrote (after_sha256).
The file before restoring (the edited version) is kept in the quarantine store (nothing is deleted). If something fails halfway, restored objects are quarantined again.
"""
from __future__ import annotations

import datetime as dt
import os

from . import fsutil, store
from .actions import base
from .actions.base import ActionError
from .core import Rejection, canonical, parse_ts, sha256


def request_token(req: dict) -> str:
    return sha256(canonical({k: v for k, v in req.items() if k not in ("approval", "mode")}))


def check_request(req, operator: str, now: dt.datetime, approval_max_age: int) -> list[Rejection]:
    from .core import validator
    errs = [Rejection("G-1", f"restore-request{e}") for e in validator("restore-request.schema.json").errors(req)]
    if errs:
        return errs
    rej = []
    appr = req["approval"]
    for label, v in (("created_at", req["created_at"]), ("approval.approved_at", appr["approved_at"])):
        try:
            parse_ts(v)
        except ValueError:
            return [Rejection("G-1", f"{label} is not a valid date and time: {v}")]
    if appr["restore_id"] != req["restore_id"]:
        rej.append(Rejection("G-3", "approval.restore_id does not match restore_id"))
    if appr["approval_token"] != request_token(req):
        rej.append(Rejection("G-3", "approval_token does not match the content of the restore-request (it may have been replaced after approval)"))
    at = parse_ts(appr["approved_at"])
    if at > now:
        rej.append(Rejection("G-3", "approved_at is in the future"))
    if at < parse_ts(req["created_at"]):
        rej.append(Rejection("G-3", "approved_at is earlier than the creation of the restore-request"))
    if (now - at).total_seconds() > approval_max_age:
        rej.append(Rejection("G-3", "the approval is too old. Get a new approval"))
    approvers = {a.casefold() for a in appr["approved_by"]}
    if len(approvers) != len(appr["approved_by"]):
        rej.append(Rejection("G-3", "approved_by contains duplicates"))
    if len(approvers) < 2:
        rej.append(Rejection("G-6", "restore (moving quarantined objects back) requires 2 or more approvers"))
    if operator.casefold() in approvers:
        rej.append(Rejection("G-4", "the operator (--operator) is one of the approvers"))
    qids = [e["quarantine_id"] for e in req["entries"]]
    if len(set(qids)) != len(qids):
        rej.append(Rejection("G-1", "entries contains the same quarantine_id twice"))
    return rej


class RestoreStep:
    def __init__(self, qid: str, manifest: dict, mhash: str):
        self.qid, self.m, self.mhash = qid, manifest, mhash
        self.state = "pending"

    @property
    def target(self):
        return self.m["original_path"]

    def check(self) -> None:
        m = self.m
        if m.get("schema") != "ger-quarantine-manifest/1" or m.get("quarantine_id") != self.qid:
            raise ActionError("invalid manifest format")
        from .gates import protected_reason
        why = protected_reason(m["original_path"])
        if why:
            raise ActionError(f"G-9: the restore destination is protected ({why})")
        efd = store.open_entry(self.qid)
        try:
            for marker in ("restored.json",):
                try:
                    os.stat(marker, dir_fd=efd, follow_symlinks=False)
                    raise ActionError("this entry was already restored")
                except FileNotFoundError:
                    pass
            pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
            if [pst.st_dev, pst.st_ino] != list(m["ident"]):
                raise ActionError("the content of the quarantine store does not match the object at quarantine time")
            if m["operation"] == "quarantine":
                k = m["kind"]
                if fsutil.kind_of(pst) != k:
                    raise ActionError("the type of the quarantine store content does not match the manifest")
                if k == "file":
                    got = fsutil.hash_file(efd, "payload", pst)
                elif k == "tree":
                    got = fsutil.tree_hash(efd, "payload", pst.st_dev).hash
                else:
                    got = "link:" + fsutil.readlink(efd, "payload")
                if got != m.get("locked_hash", m["hash"]):
                    raise ActionError("the content of the quarantine store does not match the manifest hash (possible tampering)")
            elif m["operation"] == "edit_backup":
                if fsutil.hash_file(efd, "payload", pst) != m["hash"]:
                    raise ActionError("the backup content does not match the manifest hash (possible tampering)")
            else:
                raise ActionError(f"unknown operation: {m['operation']}")
        finally:
            os.close(efd)
        res = fsutil.resolve(m["original_path"], must_exist=False)
        try:
            if m["operation"] == "quarantine":
                if res.st is not None:
                    raise ActionError(f"cannot restore: something else is at the original location: {m['original_path']}")
                if os.fstat(res.parent_fd).st_dev != m["ident"][0]:
                    raise ActionError("the restore destination is on a different device")
            else:
                if res.st is None:
                    raise ActionError(f"the edited file is missing: {m['original_path']}")
                if fsutil.hash_file(res.parent_fd, res.name, res.st) != m["after_sha256"]:
                    raise ActionError("cannot restore: the edited file changed from the content GER wrote (check it by hand)")
        finally:
            res.close()

    def apply(self) -> None:
        m = self.m
        efd = store.open_entry(self.qid)
        try:
            res = fsutil.resolve(m["original_path"], must_exist=False)
            try:
                if m["operation"] == "quarantine":
                    if res.st is not None:
                        raise ActionError("something else appeared at the original location")
                    base.unlock_payload(efd, m["kind"], m["mode"], m.get("tree_modes"))
                    self.state = "unlocked"
                    if m["kind"] == "tree":
                        got = fsutil.tree_hash(efd, "payload").hash
                        if got != m["hash"]:
                            raise ActionError("the hash of the tree after restoring modes does not match the hash before quarantine")
                    os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
                    self.state = "moved"
                else:
                    cur = res.lstat()
                    if fsutil.hash_file(res.parent_fd, res.name, cur) != m["after_sha256"]:
                        raise ActionError("the edited file changed")
                    os.link(res.name, "replaced", src_dir_fd=res.parent_fd, dst_dir_fd=efd, follow_symlinks=False)
                    self.state = "linked"
                    base.unlock_payload(efd, "file", m["mode"], None)
                    os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
                    self.state = "moved"
                back = os.stat(res.name, dir_fd=res.parent_fd, follow_symlinks=False)
                if [back.st_dev, back.st_ino] != list(m["ident"]):
                    raise ActionError("the restored object does not match", applied=True)
            finally:
                res.close()
        finally:
            os.close(efd)

    def rollback(self) -> None:
        """Reverse of apply (quarantines restored objects again)."""
        m = self.m
        efd = store.open_entry(self.qid)
        try:
            res = fsutil.resolve(m["original_path"], must_exist=False)
            try:
                if self.state == "moved":
                    os.rename(res.name, "payload", src_dir_fd=res.parent_fd, dst_dir_fd=efd)
                    if m["operation"] == "edit_backup":
                        os.rename("replaced", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
                    self.state = "unlocked" if m["operation"] == "quarantine" else "linked"
                if self.state in ("unlocked", "linked"):
                    if m["operation"] == "quarantine" and m["kind"] == "tree":
                        base.lock_payload(efd, "tree", m["tree_kinds"])
                    elif m["kind"] == "file":
                        base.lock_payload(efd, "file", None)
                self.state = "pending"
            finally:
                res.close()
        finally:
            os.close(efd)

    def commit(self, restore_id: str, at: str) -> None:
        efd = store.open_entry(self.qid)
        try:
            store.write_json_excl(efd, "restored.json", {"restore_id": restore_id, "restored_at": at})
        finally:
            os.close(efd)


def prepare(req: dict) -> tuple[list[RestoreStep], list[Rejection]]:
    steps, rej = [], []
    for e in req["entries"]:
        qid = e["quarantine_id"]
        try:
            m, h = store.read_manifest(qid)
            if h != e["manifest_sha256"]:
                raise ActionError("the SHA-256 of the manifest does not match the restore-request")
            s = RestoreStep(qid, m, h)
            s.check()
            steps.append(s)
        except FileNotFoundError:
            rej.append(Rejection("G-7", f"entry {qid} not found in the quarantine store"))
        except (ActionError, fsutil.FsError, store.StoreError, OSError, ValueError, KeyError) as ex:
            msg = str(ex)
            rej.append(Rejection("G-9" if msg.startswith("G-9:") else "G-7", f"{qid}: {msg}"))
    paths = [s.target for s in steps]
    if len(set(paths)) != len(paths):
        rej.append(Rejection("G-7", "several entries restore to the same original path (use separate restores)"))
    # Restore later quarantines first (within one plan, quarantine runs after the edits)
    steps.sort(key=lambda s: s.qid, reverse=True)
    return steps, rej


def run(steps: list[RestoreStep], restore_id: str, at: str) -> tuple[list[dict], bool]:
    """(results, ok). If something fails halfway, restored objects are quarantined again."""
    done = []
    results = []
    failed = None
    for s in steps:
        try:
            s.apply()
            done.append(s)
            results.append(_res(s, "applied", "ok", at))
        except Exception as e:
            try:
                s.rollback()
            except Exception as e2:
                results.append(_res(s, "failed", f"{type(e).__name__}: {e}; cannot undo the partial change: {e2}"))
                failed = "hard"
                break
            results.append(_res(s, "failed", f"{type(e).__name__}: {e}"))
            failed = "soft"
            break
    if failed is None:
        for s in steps:
            s.commit(restore_id, at)
        return results, True
    for s in steps[len(results):]:
        results.append(_res(s, "skipped", "aborted_after_failure"))
    hard = failed == "hard"
    for s in reversed(done):
        r = next(r for r in results if r["target"] == s.target)
        try:
            s.rollback()
            r.update(result="rolled_back", reason="rolled_back_after_failure")
        except Exception as e:
            hard = True
            r.update(reason=f"rollback_failed: {type(e).__name__}: {e}")
    return results, (False if not hard else None)


def _res(s: RestoreStep, result: str, reason: str, at=None) -> dict:
    fids = s.m.get("finding_ids") or ["sha256:" + "0" * 64]
    return {"finding_id": fids[0], "action_type": "restore", "target": s.target, "before": "quarantined:" + s.qid,
            "after": s.m["hash"] if result == "applied" else None, "result": result, "reason": reason, "applied_at": at,
            "quarantine_ids": [s.qid]}


def dry_run(steps: list[RestoreStep]) -> list[dict]:
    return [_res(s, "skipped", "dry_run:would_restore") for s in steps]
