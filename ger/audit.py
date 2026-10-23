"""Append-only audit log (JSONL with a hash chain). Separate file and separate retention from ZES and ZET.

GER_LOG_DIR is resolved to a real path once at startup (configure); every later read and write of the log uses the resolved path.
Even if an intermediate symbolic link is replaced later, a log in another location is never read or written.
Before appending, the link at the end is checked; nothing is appended to a broken chain. The full check is ger verify-log.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

from .core import VERSION, parse_ts


_configured: dict[str, str] = {}
# Audit log results that show an apply got as far as changing targets (they mark the dry-run record as used)
EXECUTED_RESULTS = ("ok", "rolled_back", "rollback_failed", "applied_unlogged")


def _given_dir() -> str:
    d = os.environ.get("GER_LOG_DIR")
    if not d:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        d = os.path.join(base, "ger")
    return d


def configure() -> None:
    """Resolves and fixes GER_LOG_DIR (or the default location) now. Called once when the CLI starts."""
    given = _given_dir()
    _configured.clear()
    _configured.update(raw=given, given=os.path.abspath(given), real=os.path.realpath(given))


def _current() -> dict:
    # If GER_LOG_DIR changes within the same process (tests and so on), resolve again. It does not change within one CLI run
    if _configured.get("raw") != _given_dir():
        configure()
    return _configured


def given_log_dir() -> str:
    """The log directory as given (lexical). Used so that intermediate symbolic links are protected too."""
    return _current()["given"]


def log_dir() -> Path:
    """The log directory as the real path resolved at startup."""
    return Path(_current()["real"])


def log_path() -> Path:
    return log_dir() / "ger-audit.jsonl"


def ensure_writable() -> None:
    d = log_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.stat(d)
    if st.st_uid != os.geteuid():  # In someone else's directory the records could be replaced
        raise PermissionError(f"the audit log directory is not owned by the executing user: {d}")
    if st.st_mode & 0o022:
        raise PermissionError(f"the audit log directory is writable by group or others: {d}")
    if not os.access(d, os.W_OK):
        raise PermissionError(f"cannot write to the audit log: {d}")
    if log_path().is_symlink():
        raise PermissionError(f"the audit log is a symbolic link: {log_path()}")
    try:  # Before doing anything, detect a log that cannot take new records (checked again under the lock when appending)
        fd = os.open(log_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    except OSError as e:
        raise PermissionError(f"cannot open the audit log: {log_path()} ({e.strerror})") from None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PermissionError(f"the audit log is not a regular file: {log_path()}")
        _check_tail([raw for raw in f], log_path())


class BrokenChain(OSError):
    """Nothing is appended because the hash chain of the audit log is broken at the end."""


def _check_tail(raw_lines: list[bytes], p) -> None:
    """Link at the end: the last line is a JSON object ending in a newline, and its prev_hash matches the hash of the line before."""
    lines = [r for r in raw_lines if r.strip()]
    if not lines:
        return
    last = lines[-1]
    prev = lines[-2].rstrip(b"\n") if len(lines) > 1 else None
    rec = _parse(last.rstrip(b"\n"))
    if not last.endswith(b"\n"):
        why = "the last line does not end with a newline (the write may have been cut off)"
    elif rec is None:
        why = "the last line is not a UTF-8 JSON object"
    elif rec.get("prev_hash") != (None if prev is None else _line_hash(prev)):
        why = "the prev_hash of the last line does not match the line before"
    else:
        return
    raise BrokenChain(f"not appending because the hash chain of the audit log is broken at the end ({why}). "
                      f"Check with ger verify-log and move the log aside before running again: {p}")


def _line_hash(line: bytes) -> str:
    return "sha256:" + hashlib.sha256(line).hexdigest()


def _read_lines(p: Path) -> list[bytes]:
    if not p.exists():
        return []
    with open(p, "rb") as f:
        return [raw.rstrip(b"\n") for raw in f if raw.strip()]


def append(record: dict) -> dict:
    ensure_writable()
    p = log_path()
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)  # Symbolic links are rejected
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            raw_lines = list(f)
            _check_tail(raw_lines, p)  # Check again under the lock (never append after a broken end or a cut-off line)
            lines = [raw.rstrip(b"\n") for raw in raw_lines if raw.strip()]
            rec = {"skill": "ger", "version": VERSION, **record,
                   "prev_hash": _line_hash(lines[-1]) if lines else None}
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            f.seek(0, os.SEEK_END)
            f.write(line + b"\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return rec


def _parse(line: bytes) -> dict | None:
    """Interprets one line as a record. A line that is not UTF-8, not JSON or not an object gives None (no exception for any bytes)."""
    try:
        rec = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):  # A line cut off inside a multi-byte character and so on
        return None
    return rec if isinstance(rec, dict) else None


def verify_chain(path: Path | None = None) -> list[str]:
    return scan_chain(path)[1]


def scan_chain(path: Path | None = None) -> tuple[int, list[str]]:
    """(number of records, list of problems). An empty list means intact."""
    p = path or log_path()
    problems: list[str] = []
    prev: bytes | None = None
    n = 0
    if p.exists():
        with open(p, "rb") as f:
            raw = f.read()
        if raw and not raw.endswith(b"\n"):
            problems.append("the last line does not end with a newline (the write may have been cut off)")
    for n, line in enumerate(_read_lines(p), 1):
        rec = _parse(line)
        if rec is None:
            problems.append(f"line {n}: not a JSON object")
            prev = line
            continue
        if rec.get("prev_hash") != (None if prev is None else _line_hash(prev)):
            problems.append(f"line {n}: prev_hash mismatch")
        prev = line
    return n, problems


def find_dry_run(plan_hash: str, input_hash: str, now: dt.datetime, ttl_seconds: int,
                 now_override: bool = False, dry_cmd: str = "dry-run", apply_cmd: str = "apply") -> dict | None:
    """Returns the latest unused, unexpired successful dry-run record for the same plan and the same input.

    - Only records with the same time handling count: an apply without --now uses only dry-runs without --now,
      an apply with --now only dry-runs with --now (an old real-time record cannot be made to look unexpired with --now)
    - A dry-run record is used up by one apply: if an apply of the same plan and input ran after that dry-run
      (result ok / rolled_back / rollback_failed / applied_unlogged), that dry-run no longer counts.
      A rejection at a gate (rejected) and an argument error before any change (error) do not count as use
    """
    found = None
    for line in _read_lines(log_path()):
        rec = _parse(line)
        if rec is None or rec.get("plan_hash") != plan_hash or rec.get("input_hash") != input_hash:
            continue
        if (rec.get("now_override", False) is not False) != now_override:
            continue
        if rec.get("command") == apply_cmd and rec.get("result") in EXECUTED_RESULTS:
            found = None  # Earlier dry-runs are used up
            continue
        if rec.get("command") == dry_cmd and rec.get("result") == "ok":
            try:
                age = (now - parse_ts(rec["finished_at"])).total_seconds()
            except (KeyError, TypeError, ValueError):  # A record that cannot be interpreted is not treated as a valid dry-run
                continue
            if 0 <= age <= ttl_seconds:
                found = rec
    return found


def records() -> list[dict]:
    """All records of the audit log (lines that cannot be interpreted are skipped)."""
    return [r for r in (_parse(line) for line in _read_lines(log_path())) if r is not None]
