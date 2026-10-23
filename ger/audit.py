"""追記専用の監査ログ（JSONL、ハッシュチェーン付き）。ZES・ZET とは別ファイル・別リテンション。"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path

from .core import VERSION, parse_ts


def log_dir() -> Path:
    d = os.environ.get("GER_LOG_DIR")
    if d:
        return Path(d)
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "ger"


def log_path() -> Path:
    return log_dir() / "ger-audit.jsonl"


def ensure_writable() -> None:
    d = log_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not os.access(d, os.W_OK):
        raise PermissionError(f"監査ログに書き込めません: {d}")
    if log_path().is_symlink():
        raise PermissionError(f"監査ログがシンボリックリンクです: {log_path()}")


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
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)  # シンボリックリンクは拒否
    with os.fdopen(fd, "r+b") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            lines = [raw.rstrip(b"\n") for raw in f if raw.strip()]
            rec = {"skill": "ger", "version": VERSION, **record,
                   "prev_hash": _line_hash(lines[-1]) if lines else None}
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            end = f.seek(0, os.SEEK_END)
            torn = end > 0 and os.pread(f.fileno(), 1, end - 1) != b"\n"  # 途中で切れた最終行に連結しない
            f.write((b"\n" if torn else b"") + line + b"\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return rec


def verify_chain(path: Path | None = None) -> list[str]:
    problems: list[str] = []
    prev: bytes | None = None
    for n, line in enumerate(_read_lines(path or log_path()), 1):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"line {n}: JSON ではありません")
            prev = line
            continue
        if rec.get("prev_hash") != (None if prev is None else _line_hash(prev)):
            problems.append(f"line {n}: prev_hash 不一致")
        prev = line
    return problems


def find_dry_run(plan_hash: str, input_hash: str, now: dt.datetime, ttl_seconds: int) -> dict | None:
    """同一計画・同一入力の dry-run 成功記録のうち、有効期限内の最新のものを返す。"""
    found = None
    for line in _read_lines(log_path()):
        rec = json.loads(line)
        if (rec.get("command") == "dry-run" and rec.get("result") == "ok"
                and rec.get("plan_hash") == plan_hash and rec.get("input_hash") == input_hash):
            age = (now - parse_ts(rec["finished_at"])).total_seconds()
            if 0 <= age <= ttl_seconds:
                found = rec
    return found
