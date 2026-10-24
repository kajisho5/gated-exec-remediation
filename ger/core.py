"""Shared parts of GER: time, canonical JSON, plan_hash / input_hash, schemas, atomic writes.

The definition of plan_hash must be identical to ZET's (zet/core.py). The tests recompute the plan_hash of a plan
finalized by ZET with GER's implementation and check that they match.
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
# SkillPact 0.8 effects that can cause external side effects or code execution (G-6). Same set as ZET (zet/core.py).
# read (includes reading sensitive files; formerly secrets) and write (includes writes outside the workspace; formerly persist) are not included on their own
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
    """Hash that tells whether dry-run and apply got the same input (only mode may differ)."""
    return sha256(canonical({k: v for k, v in inp.items() if k != "mode"}))


MAX_DEPTH = 64  # Legitimate input has fewer than 10 levels. Deep input is rejected before recursion (json / canonical / schema validation) runs out


def load_json(path: str) -> Any:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        obj = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant, parse_float=_parse_float,
                         object_pairs_hook=_no_duplicate_keys)
    except RecursionError:
        raise ValueError(f"nesting is too deep (maximum {MAX_DEPTH} levels)") from None
    _check_depth(obj)
    try:
        canonical(obj)  # Documents that cannot be hashed (lone surrogates and so on) are rejected here
    except UnicodeEncodeError as e:
        raise ValueError(f"contains a character that cannot be encoded as UTF-8 (lone surrogate): {e.object[e.start:e.end]!r}") from None
    except RecursionError:
        raise ValueError(f"nesting is too deep (maximum {MAX_DEPTH} levels)") from None
    return obj


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """Rejects an object in which the same key appears twice (if the last one silently wins, readers can disagree on its meaning)."""
    obj: dict = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"duplicate key {k!r} in a JSON object")
        obj[k] = v
    return obj


def _check_depth(obj: Any) -> None:
    stack = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, (dict, list)):
            if depth > MAX_DEPTH:
                raise ValueError(f"nesting is too deep (maximum {MAX_DEPTH} levels)")
            stack.extend((v, depth + 1) for v in (cur.values() if isinstance(cur, dict) else cur))


def _reject_constant(name: str) -> Any:
    raise ValueError(f"the non-standard JSON constant {name} is not accepted")


def _parse_float(s: str) -> float:
    f = float(s)
    if not math.isfinite(f):
        raise ValueError(f"the non-finite number {s} is not accepted")
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


def reason_text(e: BaseException) -> str:
    """The reason shown for a refused item. Text that cannot be encoded (a UnicodeError from a value that is not valid
    Unicode) gets a fixed reason instead of the codec's message."""
    if isinstance(e, UnicodeError):
        return "the target holds text that is not valid Unicode, so GER does not edit it (remove the entry by hand)"
    return str(e)


_validators: dict[str, Validator] = {}


def validator(name: str) -> Validator:
    if name not in _validators:
        with open(SCHEMAS / name, encoding="utf-8") as f:
            _validators[name] = Validator(json.load(f))
    return _validators[name]
