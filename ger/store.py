"""隔離ストア（quarantine store）とジャーナル。

場所: GER_QUARANTINE_DIR（指定時）、なければ $XDG_STATE_HOME/ger/quarantine、なければ ~/.local/state/ger/quarantine。
起動時に一度だけ実パスへ解決する。所有者は実行ユーザー、mode は 0700。マーカーファイル .ger-quarantine-store を置く
（ZES 1.1 はこのマーカーのあるディレクトリを走査しない予定。docs/design/design.md §11）。

構成:
  <store>/<run_id>/<seq>/payload        隔離したもの（ファイル・ツリー・リンク）または編集前のファイル（ハードリンク）
  <store>/<run_id>/<seq>/manifest.json  元のパス・実体 ID・mode・ハッシュ・plan_id など（0600）。その SHA-256 を監査ログに載せる
  <store>/<run_id>/<seq>/restored.json  ger restore で戻した記録
  <store>/journal/<run_id>.jsonl        各ステップの意図と結果（fsync）。途中で落ちた実行は ger recover で巻き戻す
ストアの中の名前は連番だけを使い、元の名前は使わない（.pth や package.json の名前で読み込まれないように）。
GER はストアから何も削除しない（purge は作業者が手で行う。消した後は restore もロールバックもできない）。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import stat

from . import fsutil
from .core import canonical, sha256

MARKER = ".ger-quarantine-store"
_conf: dict[str, str] = {}


def _given() -> str:
    d = os.environ.get("GER_QUARANTINE_DIR")
    if not d:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        d = os.path.join(base, "ger", "quarantine")
    return d


def configure() -> None:
    g = _given()
    _conf.clear()
    _conf.update(raw=g, real=os.path.realpath(g))


def store_dir() -> str:
    if _conf.get("raw") != _given():
        configure()
    return _conf["real"]


class StoreError(Exception):
    pass


def ensure() -> int:
    """ストアを用意し、そのディレクトリの fd（O_PATH）を返す。所有者・mode を確かめる。"""
    d = store_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = fsutil.open_dir(d)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid():
        os.close(fd)
        raise StoreError(f"隔離ストアの所有者が実行ユーザーではありません: {d}")
    if st.st_mode & 0o077:
        os.close(fd)
        raise StoreError(f"隔離ストアがグループ・他者から読み書きできます（0700 にしてください）: {d}")
    try:
        os.stat(MARKER, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        mfd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC, 0o600, dir_fd=fd)
        os.write(mfd, b"ger quarantine store. ZES: do not scan. Do not import from here.\n")
        os.close(mfd)
    for sub in ("journal",):
        try:
            os.mkdir(sub, 0o700, dir_fd=fd)
        except FileExistsError:
            pass
    return fd


def device() -> int:
    fd = ensure()
    try:
        return os.fstat(fd).st_dev
    finally:
        os.close(fd)


def new_run_id(now: dt.datetime) -> str:
    return now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def write_json_excl(dir_fd: int, name: str, obj) -> str:
    data = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha256(data)


class Entry:
    """1 回の移動（rename）に対応するストアのエントリ。"""

    def __init__(self, run_id: str, seq: int):
        self.run_id, self.seq = run_id, seq
        self.qid = f"{run_id}/{seq:03d}"
        self.path = os.path.join(store_dir(), run_id, f"{seq:03d}")

    def create(self) -> int:
        sfd = ensure()
        try:
            try:
                os.mkdir(self.run_id, 0o700, dir_fd=sfd)
            except FileExistsError:
                pass
            rfd = os.open(self.run_id, fsutil.DIR_FLAGS, dir_fd=sfd)
            try:
                os.mkdir(f"{self.seq:03d}", 0o700, dir_fd=rfd)
                return os.open(f"{self.seq:03d}", fsutil.DIR_FLAGS, dir_fd=rfd)
            finally:
                os.close(rfd)
        finally:
            os.close(sfd)


def open_entry(qid: str) -> int:
    run, seq = _split_qid(qid)
    return fsutil.open_dir(os.path.join(store_dir(), run, seq))


def _split_qid(qid: str) -> tuple[str, str]:
    parts = qid.split("/")
    if len(parts) != 2 or not all(p and p not in (".", "..") and "\0" not in p for p in parts) \
            or not parts[1].isdigit():
        raise StoreError(f"quarantine_id の形式が不正です: {qid!r}")
    return parts[0], parts[1]


def read_manifest(qid: str) -> tuple[dict, str]:
    efd = open_entry(qid)
    try:
        raw = fsutil.read_file(efd, "manifest.json", limit=1 << 20)
    finally:
        os.close(efd)
    return json.loads(raw.decode("utf-8")), sha256(raw)


def list_entries() -> list[dict]:
    """ストアのすべてのエントリ（読むだけ）。"""
    out = []
    d = store_dir()
    if not os.path.isdir(d):
        return out
    for run in sorted(os.listdir(d)):
        rp = os.path.join(d, run)
        if run in ("journal",) or run == MARKER or not os.path.isdir(rp) or os.path.islink(rp):
            continue
        for seq in sorted(os.listdir(rp)):
            qid = f"{run}/{seq}"
            rec = {"quarantine_id": qid}
            try:
                m, h = read_manifest(qid)
                rec.update(manifest_sha256=h, original_path=m.get("original_path"), kind=m.get("kind"),
                           operation=m.get("operation"), plan_id=m.get("plan_id"), finding_ids=m.get("finding_ids"))
                ep = os.path.join(rp, seq)
                if os.path.lexists(os.path.join(ep, "restored.json")):
                    rec["status"] = "restored"
                elif os.path.lexists(os.path.join(ep, "payload")):
                    rec["status"] = "quarantined"
                else:
                    rec["status"] = "payload_missing"
            except (OSError, ValueError, StoreError, fsutil.FsError) as e:
                rec["status"] = f"unreadable: {e}"
            out.append(rec)
    return out


class Journal:
    """1 回の実行のジャーナル（JSONL、各行を書くたびに fsync）。"""

    def __init__(self, run_id: str, header: dict):
        sfd = ensure()
        try:
            jfd = os.open("journal", fsutil.DIR_FLAGS, dir_fd=sfd)
        finally:
            os.close(sfd)
        try:
            self.fd = os.open(f"{run_id}.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | fsutil.O_NOFOLLOW
                              | fsutil.O_CLOEXEC, 0o600, dir_fd=jfd)
        finally:
            os.close(jfd)
        self.run_id = run_id
        self.write({"event": "begin", "run_id": run_id, **header})

    def write(self, rec: dict) -> None:
        os.write(self.fd, canonical(rec) + b"\n")
        os.fsync(self.fd)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


TERMINAL = ("commit", "rolled_back", "recovered", "dry_run")


def open_journals() -> list[tuple[str, list[dict]]]:
    """終端の記録（commit / rolled_back / recovered）が無いジャーナル。"""
    out = []
    jd = os.path.join(store_dir(), "journal")
    if not os.path.isdir(jd):
        return out
    for n in sorted(os.listdir(jd)):
        if not n.endswith(".jsonl"):
            continue
        p = os.path.join(jd, n)
        if os.path.islink(p) or not stat.S_ISREG(os.lstat(p).st_mode):
            continue
        recs = []
        with open(p, "rb") as f:
            for line in f:
                try:
                    recs.append(json.loads(line))
                except ValueError:
                    break
        if not any(r.get("event") in TERMINAL for r in recs):
            out.append((n[:-len(".jsonl")], recs))
    return out


def append_journal(run_id: str, rec: dict) -> None:
    sfd = ensure()
    try:
        jfd = os.open("journal", fsutil.DIR_FLAGS, dir_fd=sfd)
    finally:
        os.close(sfd)
    try:
        fd = os.open(f"{run_id}.jsonl", os.O_WRONLY | os.O_APPEND | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC, dir_fd=jfd)
    finally:
        os.close(jfd)
    try:
        os.write(fd, canonical(rec) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
