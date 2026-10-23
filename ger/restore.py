"""ger restore — 隔離したもの・編集前のファイルを元の場所へ戻す（計画の外のコマンド。Q-4）。

restore-request.json（schemas/restore-request.schema.json）:
  {"schema_version": "1.0", "restore_id": UUID, "created_at", "mode": "dry-run"|"apply",
   "entries": [{"quarantine_id", "manifest_sha256"}],
   "approval": {"restore_id", "approved_by": [2 名以上], "approved_at", "approval_token"}}
approval_token は request から approval と mode を除いた正規化 JSON の SHA-256。戻すことは「足す」ことになる
（定義 T の例外）ため承認者 2 名を要求し、ger と同じく dry-run を必須にして 1 回の apply で使い切る。

前提: マニフェストの SHA-256 が一致する。隔離したものは元のパスが空いていて、ストアの中身（ロック後のハッシュ）が
マニフェストと一致する。編集のバックアップは、現在のファイルが GER の書いた内容（after_sha256）のままであること。
戻す前のファイル（編集後の版）は隔離ストアに残す（何も削除しない）。途中で失敗したら、戻したものを再び隔離する。
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
            return [Rejection("G-1", f"{label} が実在しない日時です: {v}")]
    if appr["restore_id"] != req["restore_id"]:
        rej.append(Rejection("G-3", "approval.restore_id が restore_id と一致しません"))
    if appr["approval_token"] != request_token(req):
        rej.append(Rejection("G-3", "approval_token が restore-request の内容と一致しません（承認後に差し替えられた可能性）"))
    at = parse_ts(appr["approved_at"])
    if at > now:
        rej.append(Rejection("G-3", "approved_at が未来の時刻です"))
    if at < parse_ts(req["created_at"]):
        rej.append(Rejection("G-3", "approved_at が restore-request の作成より前です"))
    if (now - at).total_seconds() > approval_max_age:
        rej.append(Rejection("G-3", "承認が古すぎます。承認を取り直してください"))
    approvers = {a.casefold() for a in appr["approved_by"]}
    if len(approvers) != len(appr["approved_by"]):
        rej.append(Rejection("G-3", "approved_by に重複があります"))
    if len(approvers) < 2:
        rej.append(Rejection("G-6", "restore（隔離したものを戻す）には承認者 2 名以上が必要です"))
    if operator.casefold() in approvers:
        rej.append(Rejection("G-4", "実行者（--operator）が承認者に含まれています"))
    qids = [e["quarantine_id"] for e in req["entries"]]
    if len(set(qids)) != len(qids):
        rej.append(Rejection("G-1", "entries に同じ quarantine_id が 2 回あります"))
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
            raise ActionError("マニフェストの形式が不正です")
        from .gates import protected_reason
        why = protected_reason(m["original_path"])
        if why:
            raise ActionError(f"G-9: 戻し先が保護対象です（{why}）")
        efd = store.open_entry(self.qid)
        try:
            for marker in ("restored.json",):
                try:
                    os.stat(marker, dir_fd=efd, follow_symlinks=False)
                    raise ActionError("このエントリは既に戻されています")
                except FileNotFoundError:
                    pass
            pst = os.stat("payload", dir_fd=efd, follow_symlinks=False)
            if [pst.st_dev, pst.st_ino] != list(m["ident"]):
                raise ActionError("隔離ストアの中身が隔離した時の実体と一致しません")
            if m["operation"] == "quarantine":
                k = m["kind"]
                if fsutil.kind_of(pst) != k:
                    raise ActionError("隔離ストアの中身の種類がマニフェストと一致しません")
                if k == "file":
                    got = fsutil.hash_file(efd, "payload", pst)
                elif k == "tree":
                    got = fsutil.tree_hash(efd, "payload", pst.st_dev).hash
                else:
                    got = "link:" + fsutil.readlink(efd, "payload")
                if got != m.get("locked_hash", m["hash"]):
                    raise ActionError("隔離ストアの中身がマニフェストのハッシュと一致しません（改ざんの可能性）")
            elif m["operation"] == "edit_backup":
                if fsutil.hash_file(efd, "payload", pst) != m["hash"]:
                    raise ActionError("バックアップの内容がマニフェストのハッシュと一致しません（改ざんの可能性）")
            else:
                raise ActionError(f"未知の operation: {m['operation']}")
        finally:
            os.close(efd)
        res = fsutil.resolve(m["original_path"], must_exist=False)
        try:
            if m["operation"] == "quarantine":
                if res.st is not None:
                    raise ActionError(f"元の場所に別のものがあるため戻せません: {m['original_path']}")
                if os.fstat(res.parent_fd).st_dev != m["ident"][0]:
                    raise ActionError("戻し先が別のデバイスです")
            else:
                if res.st is None:
                    raise ActionError(f"編集したファイルがありません: {m['original_path']}")
                if fsutil.hash_file(res.parent_fd, res.name, res.st) != m["after_sha256"]:
                    raise ActionError("編集したファイルが GER の書いた内容から変わっているため戻せません（手で確かめてください）")
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
                        raise ActionError("元の場所に別のものが現れました")
                    base.unlock_payload(efd, m["kind"], m["mode"], m.get("tree_modes"))
                    self.state = "unlocked"
                    if m["kind"] == "tree":
                        got = fsutil.tree_hash(efd, "payload").hash
                        if got != m["hash"]:
                            raise ActionError("mode を戻したツリーのハッシュが隔離前と一致しません")
                    os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
                    self.state = "moved"
                else:
                    cur = res.lstat()
                    if fsutil.hash_file(res.parent_fd, res.name, cur) != m["after_sha256"]:
                        raise ActionError("編集したファイルが変わりました")
                    os.link(res.name, "replaced", src_dir_fd=res.parent_fd, dst_dir_fd=efd, follow_symlinks=False)
                    self.state = "linked"
                    base.unlock_payload(efd, "file", m["mode"], None)
                    os.rename("payload", res.name, src_dir_fd=efd, dst_dir_fd=res.parent_fd)
                    self.state = "moved"
                back = os.stat(res.name, dir_fd=res.parent_fd, follow_symlinks=False)
                if [back.st_dev, back.st_ino] != list(m["ident"]):
                    raise ActionError("戻した後の実体が一致しません", applied=True)
            finally:
                res.close()
        finally:
            os.close(efd)

    def rollback(self) -> None:
        """apply の逆（戻したものを再び隔離する）。"""
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
                raise ActionError("マニフェストの SHA-256 が restore-request と一致しません")
            s = RestoreStep(qid, m, h)
            s.check()
            steps.append(s)
        except FileNotFoundError:
            rej.append(Rejection("G-7", f"隔離ストアにエントリ {qid} がありません"))
        except (ActionError, fsutil.FsError, store.StoreError, OSError, ValueError, KeyError) as ex:
            msg = str(ex)
            rej.append(Rejection("G-9" if msg.startswith("G-9:") else "G-7", f"{qid}: {msg}"))
    paths = [s.target for s in steps]
    if len(set(paths)) != len(paths):
        rej.append(Rejection("G-7", "同じ元のパスへ戻すエントリが複数あります（別々の restore にしてください）"))
    # 後から隔離したものを先に戻す（同じ計画の中では quarantine は編集より後に実行している）
    steps.sort(key=lambda s: s.qid, reverse=True)
    return steps, rej


def run(steps: list[RestoreStep], restore_id: str, at: str) -> tuple[list[dict], bool]:
    """(results, ok)。途中で失敗したら、戻したものを再び隔離する。"""
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
                results.append(_res(s, "failed", f"{type(e).__name__}: {e}; 途中の変更を戻せません: {e2}"))
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
