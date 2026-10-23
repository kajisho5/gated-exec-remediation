"""追記専用の監査ログ（JSONL、ハッシュチェーン付き）。ZES・ZET とは別ファイル・別リテンション。

GER_LOG_DIR は起動時に一度だけ実パスへ解決し（configure）、以後のログの読み書きはすべて解決後のパスで行う。
途中のシンボリックリンクを後から差し替えられても、別の場所のログを読み書きしない。
追記の前に末尾の連結を確かめ、壊れたチェーンには追記しない。全体の検証は ger verify-log。
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
# apply が対象の変更まで進んだことを示す監査ログの result（dry-run 記録を使用済みにする）
EXECUTED_RESULTS = ("ok", "rolled_back", "rollback_failed", "applied_unlogged")


def _given_dir() -> str:
    d = os.environ.get("GER_LOG_DIR")
    if not d:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        d = os.path.join(base, "ger")
    return d


def configure() -> None:
    """GER_LOG_DIR（または既定の場所）を今の時点で解決して固定する。CLI の起動時に 1 回呼ぶ。"""
    given = _given_dir()
    _configured.clear()
    _configured.update(raw=given, given=os.path.abspath(given), real=os.path.realpath(given))


def _current() -> dict:
    # 同じプロセスで GER_LOG_DIR が変わった場合（テストなど）は解決し直す。CLI の 1 回の実行では変わらない
    if _configured.get("raw") != _given_dir():
        configure()
    return _configured


def given_log_dir() -> str:
    """指定されたままの（字句上の）ログディレクトリ。途中のシンボリックリンクも含めて保護対象にするため。"""
    return _current()["given"]


def log_dir() -> Path:
    """起動時に解決した実パスのログディレクトリ。"""
    return Path(_current()["real"])


def log_path() -> Path:
    return log_dir() / "ger-audit.jsonl"


def ensure_writable() -> None:
    d = log_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.stat(d)
    if st.st_uid != os.geteuid():  # 他人のディレクトリでは記録を差し替えられうる
        raise PermissionError(f"監査ログのディレクトリの所有者が実行ユーザーではありません: {d}")
    if st.st_mode & 0o022:
        raise PermissionError(f"監査ログのディレクトリがグループ・他者から書き込み可能です: {d}")
    if not os.access(d, os.W_OK):
        raise PermissionError(f"監査ログに書き込めません: {d}")
    if log_path().is_symlink():
        raise PermissionError(f"監査ログがシンボリックリンクです: {log_path()}")
    try:  # 何かする前に、記録を足せないログを検出する（追記時にもロックの下で再確認する）
        fd = os.open(log_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    except OSError as e:
        raise PermissionError(f"監査ログを開けません: {log_path()}（{e.strerror}）") from None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PermissionError(f"監査ログが通常ファイルではありません: {log_path()}")
        _check_tail([raw for raw in f], log_path())


class BrokenChain(OSError):
    """監査ログのハッシュチェーンが末尾で壊れているため追記しない。"""


def _check_tail(raw_lines: list[bytes], p) -> None:
    """末尾の連結: 最終行が改行で終わる JSON object で、prev_hash が直前の行のハッシュと一致すること。"""
    lines = [r for r in raw_lines if r.strip()]
    if not lines:
        return
    last = lines[-1]
    prev = lines[-2].rstrip(b"\n") if len(lines) > 1 else None
    rec = _parse(last.rstrip(b"\n"))
    if not last.endswith(b"\n"):
        why = "最終行が改行で終わっていません（書き込みが途中で切れた可能性）"
    elif rec is None:
        why = "最終行が UTF-8 の JSON object ではありません"
    elif rec.get("prev_hash") != (None if prev is None else _line_hash(prev)):
        why = "最終行の prev_hash が直前の行と一致しません"
    else:
        return
    raise BrokenChain(f"監査ログのハッシュチェーンが末尾で壊れているため追記しません（{why}）。"
                      f"ger verify-log で確認し、ログを退避してから実行してください: {p}")


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
            raw_lines = list(f)
            _check_tail(raw_lines, p)  # ロックの下で再確認（壊れた末尾・途中で切れた行の後ろには追記しない）
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
    """1 行を記録として解釈する。UTF-8 でない・JSON でない・object でない行は None（任意のバイト列で例外を出さない）。"""
    try:
        rec = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):  # 多バイト文字の途中で切れた行など
        return None
    return rec if isinstance(rec, dict) else None


def verify_chain(path: Path | None = None) -> list[str]:
    return scan_chain(path)[1]


def scan_chain(path: Path | None = None) -> tuple[int, list[str]]:
    """(レコード数, 破損箇所の一覧)。一覧が空なら健全。"""
    p = path or log_path()
    problems: list[str] = []
    prev: bytes | None = None
    n = 0
    if p.exists():
        with open(p, "rb") as f:
            raw = f.read()
        if raw and not raw.endswith(b"\n"):
            problems.append("最終行が改行で終わっていません（書き込みが途中で切れた可能性）")
    for n, line in enumerate(_read_lines(p), 1):
        rec = _parse(line)
        if rec is None:
            problems.append(f"line {n}: JSON object ではありません")
            prev = line
            continue
        if rec.get("prev_hash") != (None if prev is None else _line_hash(prev)):
            problems.append(f"line {n}: prev_hash 不一致")
        prev = line
    return n, problems


def find_dry_run(plan_hash: str, input_hash: str, now: dt.datetime, ttl_seconds: int,
                 now_override: bool = False) -> dict | None:
    """同一計画・同一入力の dry-run 成功記録のうち、有効期限内で未使用の最新のものを返す。

    - 数えるのは今回と同じ時刻の扱いの記録だけ: --now なしの apply は --now なしの dry-run だけ、
      --now 付きの apply は --now 付きの dry-run だけ（実時刻の古い記録を --now で期限内に見せかけない）
    - dry-run 記録は 1 回の apply で使い切る: 同一計画・同一入力の apply が、その dry-run より後に
      実行された（result が ok / rolled_back / rollback_failed / applied_unlogged）なら、その dry-run はもう数えない。
      ゲートでの拒否（rejected）と、変更を始める前の引数エラー（error）は使用に数えない
    """
    found = None
    for line in _read_lines(log_path()):
        rec = _parse(line)
        if rec is None or rec.get("plan_hash") != plan_hash or rec.get("input_hash") != input_hash:
            continue
        if (rec.get("now_override", False) is not False) != now_override:
            continue
        if rec.get("command") == "apply" and rec.get("result") in EXECUTED_RESULTS:
            found = None  # それまでの dry-run は使用済み
            continue
        if rec.get("command") == "dry-run" and rec.get("result") == "ok":
            try:
                age = (now - parse_ts(rec["finished_at"])).total_seconds()
            except (KeyError, TypeError, ValueError):  # 解釈できない記録は有効な dry-run として扱わない
                continue
            if 0 <= age <= ttl_seconds:
                found = rec
    return found
