"""GER の共通部品: 時刻、正規化 JSON、plan_hash / input_hash、スキーマ、原子的書き出し。

plan_hash の定義は ZET（zet/core.py）と同一でなければならない。テストで ZET が確定した計画の
plan_hash を GER の実装で再計算し、一致することを確認している。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any

from .jsonschema_lite import Validator

VERSION = "0.1.0"
ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
# 外部への副作用・コード実行を起こしうる SkillPact 0.8 の効果（G-6）。ZET（zet/core.py）と同じ集合。
# read（機密ファイルの読み取りを含む。旧 secrets）と write（作業領域外への書き込みを含む。旧 persist）は単独では含めない
RISKY_EFFECTS = ("exec", "network", "spend", "send")


class Rejection:
    __slots__ = ("gate", "message", "finding_id")

    def __init__(self, gate: str, message: str, finding_id: str | None = None):
        self.gate, self.message, self.finding_id = gate, message, finding_id

    def __repr__(self) -> str:
        return f"Rejection({self.gate!r}, {self.message!r}, {self.finding_id!r})"


class Rejected(Exception):
    def __init__(self, rejections: list[Rejection]):
        super().__init__("; ".join(f"{r.gate}: {r.message}" for r in rejections))
        self.rejections = rejections


def parse_ts(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def fmt_ts(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc(override: str | None = None) -> dt.datetime:
    if override:
        return parse_ts(override)
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def plan_hash(plan: dict) -> str:
    return sha256(canonical({k: v for k, v in plan.items() if k != "plan_hash"}))


def input_hash(inp: dict) -> str:
    """dry-run と apply で同じ入力かを判定するハッシュ（mode だけが異なることを許す）。"""
    return sha256(canonical({k: v for k, v in inp.items() if k != "mode"}))


MAX_DEPTH = 64  # 正規の入力は 10 段未満。深い入力で再帰（json / canonical / スキーマ検証）が尽きる前に拒否する


def load_json(path: str) -> Any:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_parse_float,
                         object_pairs_hook=_no_duplicate_keys)
    except RecursionError:
        raise ValueError(f"入れ子が深すぎます（最大 {MAX_DEPTH} 段）") from None
    _check_depth(obj)
    try:
        canonical(obj)  # ハッシュ計算できない文書（孤立サロゲートなど）はここで拒否する
    except UnicodeEncodeError as e:
        raise ValueError(f"UTF-8 に符号化できない文字（孤立サロゲート）を含みます: {e.object[e.start:e.end]!r}") from None
    except RecursionError:
        raise ValueError(f"入れ子が深すぎます（最大 {MAX_DEPTH} 段）") from None
    return obj


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """同じキーが 2 回現れる object は拒否する（後勝ちで黙って上書きされると、読み手により解釈が分かれる）。"""
    obj: dict = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"JSON object のキー {k!r} が重複しています")
        obj[k] = v
    return obj


def _check_depth(obj: Any) -> None:
    stack = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, (dict, list)):
            if depth > MAX_DEPTH:
                raise ValueError(f"入れ子が深すぎます（最大 {MAX_DEPTH} 段）")
            stack.extend((v, depth + 1) for v in (cur.values() if isinstance(cur, dict) else cur))


def _reject_constant(name: str) -> Any:
    raise ValueError(f"非標準の JSON 定数 {name} は受け付けません")


def _parse_float(s: str) -> float:
    f = float(s)
    if not math.isfinite(f):
        raise ValueError(f"有限でない数値 {s} は受け付けません")
    return f


def write_atomic(path: str, obj: Any) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".ger-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


_validators: dict[str, Validator] = {}


def validator(name: str) -> Validator:
    if name not in _validators:
        with open(SCHEMAS / name, encoding="utf-8") as f:
            _validators[name] = Validator(json.load(f))
    return _validators[name]
