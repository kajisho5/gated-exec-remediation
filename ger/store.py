"""Quarantine store and journal.

Location: GER_QUARANTINE_DIR (when set), otherwise $XDG_STATE_HOME/ger/quarantine, otherwise ~/.local/state/ger/quarantine.
Resolved to a real path once at startup. Owned by the executing user, mode 0700. Holds the marker file .ger-quarantine-store
(ZES 1.1 is planned to skip directories with this marker; docs/design/design.md §11).

Layout:
  <store>/<run_id>/<seq>/payload        the quarantined object (file, tree, link) or the file before the edit (hard link)
  <store>/<run_id>/<seq>/manifest.json  original path, object ID, mode, hash, plan_id and so on (0600). Its SHA-256 goes into the audit log
  <store>/<run_id>/<seq>/restored.json  record of a ger restore
  <store>/journal/<run_id>.jsonl        intent and result of each step (fsync). A run that died halfway is rolled back with ger recover
Names inside the store are sequence numbers only; original names are never used (so nothing is loaded by a .pth or package.json name).
GER deletes nothing from the store (the worker purges by hand; after that, neither restore nor rollback is possible).
"""
from __future__ import annotations

import datetime as dt
import errno
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
    """Prepares the store and returns the fd (O_PATH) of its directory. Checks owner and mode."""
    d = store_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = fsutil.open_dir(d)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid():
        os.close(fd)
        raise StoreError(f"the quarantine store is not owned by the executing user: {d}")
    if st.st_mode & 0o077:
        os.close(fd)
        raise StoreError(f"the quarantine store is readable or writable by group or others (set it to 0700): {d}")
    try:
        os.stat(MARKER, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        mfd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC, 0o600, dir_fd=fd)
        fsutil.write_all(mfd, b"ger quarantine store. ZES: do not scan. Do not import from here.\n")
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
        fsutil.write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha256(data)


class Entry:
    """A store entry for one move (rename)."""

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
        raise StoreError(f"invalid quarantine_id format: {qid!r}")
    return parts[0], parts[1]


def read_manifest(qid: str) -> tuple[dict, str]:
    efd = open_entry(qid)
    try:
        raw = fsutil.read_file(efd, "manifest.json", limit=1 << 20)
    finally:
        os.close(efd)
    return json.loads(raw.decode("utf-8")), sha256(raw)


def list_entries() -> list[dict]:
    """All entries of the store (read only)."""
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


class JournalWriteError(OSError):
    """A journal line could not be written completely and durably (short write, ENOSPC, EIO). The file was cut back to
    its last complete line when possible, so it never ends in a partial record that a later line would be glued to."""


def _append_line(fd: int, size: int, rec: dict) -> int:
    """Appends one record line at offset size (O_APPEND) with fsync and returns the new size. On any failure the file is
    truncated back to size and JournalWriteError is raised; if even that fails, JournalWriteError(dead=True)."""
    data = canonical(rec) + b"\n"
    try:
        fsutil.write_all(fd, data)
        os.fsync(fd)
    except OSError as e:
        err = JournalWriteError(e.errno, f"cannot write the journal ({e.strerror or e})")
        err.dead = False
        try:
            os.ftruncate(fd, size)
            os.fsync(fd)
        except OSError:
            err.dead = True
        raise err from e
    return size + len(data)


class Journal:
    """Journal of one run (JSONL, fsync after every line). Every write is checked (JournalWriteError)."""

    def __init__(self, run_id: str, header: dict):
        sfd = ensure()
        try:
            jfd = os.open("journal", fsutil.DIR_FLAGS, dir_fd=sfd)
        finally:
            os.close(sfd)
        try:
            self.fd = os.open(f"{run_id}.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | fsutil.O_NOFOLLOW
                              | fsutil.O_CLOEXEC, 0o600, dir_fd=jfd)
            self.run_id, self.size, self.dead = run_id, 0, False
            try:
                self.write({"event": "begin", "run_id": run_id, **header})
            except JournalWriteError:
                # Nothing was changed under this journal: remove the empty file GER just created (a journal without a
                #   begin record counts as closed anyway, see read_journal)
                self.close()
                try:
                    os.unlink(f"{run_id}.jsonl", dir_fd=jfd)
                except OSError:
                    pass
                raise
        finally:
            os.close(jfd)

    def write(self, rec: dict) -> None:
        if self.dead:
            raise JournalWriteError(errno.EIO, "cannot write the journal (an earlier write could not be cut back)")
        try:
            self.size = _append_line(self.fd, self.size, rec)
        except JournalWriteError as e:
            self.dead = e.dead
            raise

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


TERMINAL = ("commit", "rolled_back", "recovered", "superseded", "dry_run")


def read_journal(data: bytes) -> tuple[list[dict], int | None]:
    """(records, line number of the first damaged line or None). A last line that does not parse (a write cut off by a
    kill, with or without its newline) is dropped: GER journals every intent before the change, so a lost last line is
    the same as a kill just before it. A line in the middle that does not parse cannot come from a kill (GER cuts a
    failed write back), so it marks the journal as damaged; the records after it are still returned."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    recs, damaged = [], None
    for n, line in enumerate(lines, 1):
        try:
            rec = json.loads(line)
        except (ValueError, RecursionError):
            rec = None
        if not isinstance(rec, dict):
            if n < len(lines) and damaged is None:
                damaged = n
            continue
        recs.append(rec)
    return recs, damaged


def open_journals() -> list[tuple[str, list[dict], int | None]]:
    """(run id, records, damaged line) of the journals without a final record (commit / rolled_back / recovered /
    superseded). A journal with no record at all (empty, or only a cut-off begin line: nothing was changed under it)
    counts as closed. ger recover and G-8 both use this list, so they always agree on what is open."""
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
        with open(p, "rb") as f:
            recs, damaged = read_journal(f.read())
        if not recs and damaged is None:
            continue
        if not any(r.get("event") in TERMINAL for r in recs):
            out.append((n[:-len(".jsonl")], recs, damaged))
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
        _append_line(fd, os.fstat(fd).st_size, rec)
    finally:
        os.close(fd)
