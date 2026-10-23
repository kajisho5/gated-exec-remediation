"""edit_json 操作（JSON と JSONC）— 可逆。

params: {"format": "json"|"jsonc",
         "ops": [{"op": "remove"|"replace_const", "pointer": "/mcpServers/evil", "before_sha256": "<値の正規化 JSON の SHA-256>",
                  "const"?: "default"}],
         "file_sha256", "expected_after_sha256"}
- 各 pointer は GER の表 H（hazards.JSON_H）に一致すること（T-1）。replace_const の値は表 K にあること（T-2）
- 変更後を別の方法でパースし直し、「変更前 − 取り除いた単位 ⊕ K の置き換え」と一致すること（T-3）
- 書式とコメントは残す。キーの重複は拒否する
"""
from __future__ import annotations

from .. import fsutil, hazards, jsonedit
from ..core import canonical, sha256
from . import edit_common
from .base import ActionError, PreviewResult

TYPE = "edit_json"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 0
MAX_OPS = 64


def validate_params(params: dict, allowed_ops=("remove", "replace_const")) -> None:
    if not isinstance(params, dict) or set(params) != {"format", "ops", "file_sha256", "expected_after_sha256"}:
        raise ActionError('params は {"format", "ops", "file_sha256", "expected_after_sha256"} であること（ger preview で作る）')
    if params["format"] not in ("json", "jsonc"):
        raise ActionError("params.format は json / jsonc のいずれか")
    edit_common.check_sha(params["file_sha256"], "file_sha256")
    edit_common.check_sha(params["expected_after_sha256"], "expected_after_sha256")
    ops = params["ops"]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS:
        raise ActionError(f"params.ops は 1〜{MAX_OPS} 件であること")
    for o in ops:
        if not isinstance(o, dict) or o.get("op") not in allowed_ops:
            raise ActionError(f"op は {' / '.join(allowed_ops)} のいずれか")
        want = {"op", "pointer", "before_sha256"} | ({"const"} if o["op"] == "replace_const" else set())
        if set(o) != want or not isinstance(o["pointer"], str) or not o["pointer"].startswith("/"):
            raise ActionError(f"op の項目は {sorted(want)} であること（pointer は / で始まる JSON pointer）")
        edit_common.check_sha(o["before_sha256"], "ops[].before_sha256")


def check_ops(path: str, root, ops: list, allowed_h=None) -> None:
    """T-1 / T-2: 各 op が現在の内容に対して H / K に一致すること（計画の値を信用しない）。"""
    for o in ops:
        try:
            _par, _idx, node = jsonedit.find(root, o["pointer"])
        except jsonedit.JsonEditError as e:
            raise ActionError(str(e)) from None
        val = jsonedit.to_python(node)
        hid = hazards.json_hazard(path, o["pointer"], val, o["op"])
        if hid is None or (allowed_h is not None and hid not in allowed_h):
            raise ActionError(f"pointer {o['pointer']} は GER の危険パターンの表（H）に一致しません。取り除けません（T-1）")
        if sha256(canonical(val)) != o["before_sha256"]:
            raise ActionError(f"pointer {o['pointer']} の値が preview の時から変わっています（before_sha256 と不一致）")
        if o["op"] == "replace_const" and o.get("const") not in hazards.JSON_K.get(hid, ()):
            raise ActionError(f"replace_const の値は定数表（K）にあるものだけです（T-2）: {hid}")


def compute(path: str, data: bytes, fmt: str, ops: list, allowed_h=None) -> bytes:
    text = edit_common.decode_utf8(data)
    try:
        root = jsonedit.parse(text, fmt == "jsonc")
    except jsonedit.JsonEditError as e:
        raise ActionError(f"{fmt} として解析できません: {e}") from None
    check_ops(path, root, ops, allowed_h)
    try:
        new, expected = jsonedit.apply_ops(text, fmt, ops)
        after = jsonedit.reparse(new, fmt)
    except (jsonedit.JsonEditError, ValueError) as e:
        raise ActionError(f"変更後の内容を解析できません（T-3）: {e}") from None
    if canonical(after) != canonical(expected):
        raise ActionError("変更後をパースし直した値が「変更前 − 取り除いた単位」と一致しません（T-3）")
    return new.encode("utf-8")


def prepare(ctx, items):
    fmt = items[0].action["params"]["format"]
    return edit_common.prepare_edit(ctx, items, TYPE, lambda p, d, ops: compute(p, d, fmt, ops))


# --- preview ------------------------------------------------------------------------------------
def _walk(value, ptr="", depth=0):
    yield ptr, value
    if depth >= 6:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, ptr + "/" + jsonedit.escape_token(k), depth + 1)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _walk(v, f"{ptr}/{i}", depth + 1)


def select_ops(path: str, value, hids) -> list[dict]:
    ops = []
    for ptr, v in _walk(value):
        if not ptr:
            continue
        for hid in hids:
            fpred, rx, vpred, auto, hop = hazards.JSON_H[hid]
            if fpred(path) and rx.match(ptr) and vpred(v) and auto(v):
                o = {"op": hop, "pointer": ptr, "before_sha256": sha256(canonical(v))}
                if hop == "replace_const":
                    o["const"] = hazards.JSON_K[hid][0]
                ops.append(o)
    # 入れ子の重複（親を取り除くなら子は不要）を除く
    ptrs = [o["pointer"] for o in ops]
    return [o for o in ops if not any(p != o["pointer"] and o["pointer"].startswith(p + "/") for p in ptrs)]


def preview_compute(ctx, items, hids, allowed_h=None):
    """(params, summary, diff)。params に select（H の id）があれば自動で ops を選ぶ。"""
    target = items[0].action["target"]
    res = ctx.pool.add(fsutil.resolve(target))
    from .base import check_regular
    check_regular(res.st)
    data = fsutil.read_file(res.parent_fd, res.name, res.st, limit=fsutil.EDIT_MAX_BYTES)
    text = edit_common.decode_utf8(data)
    try:
        fmt = jsonedit.detect_format(text)
    except jsonedit.JsonEditError as e:
        raise ActionError(f"JSON / JSONC として解析できません: {e}") from None
    root = jsonedit.parse(text, fmt == "jsonc")
    value = jsonedit.to_python(root)
    ops = []
    for it in items:
        p = it.action["params"]
        if "select" in p:
            sel = p["select"] if isinstance(p["select"], list) else [p["select"]]
            if any(s not in hazards.JSON_H for s in sel):
                raise ActionError(f"params.select は H の id（{', '.join(hazards.JSON_H)}）であること")
            ops += select_ops(target, value, [s for s in sel if s in hids])
        else:
            for o in p.get("ops", []):
                if "pointer" not in o:
                    raise ActionError("ops[].pointer がありません")
                _par, _idx, node = jsonedit.find(root, o["pointer"])
                v = jsonedit.to_python(node)
                n = {"op": o.get("op", "remove"), "pointer": o["pointer"], "before_sha256": sha256(canonical(v))}
                if n["op"] == "replace_const":
                    n["const"] = o.get("const")
                ops.append(n)
    dedup, seen = [], set()
    for o in ops:
        if o["pointer"] not in seen:
            seen.add(o["pointer"])
            dedup.append(o)
    if not dedup:
        raise ActionError("取り除く対象（H に一致する危険な値）が見つかりません")
    new = compute(target, data, fmt, dedup, allowed_h)
    params = {"format": fmt, "ops": dedup, "file_sha256": sha256(data), "expected_after_sha256": sha256(new)}
    summary = f"{fmt}: " + ", ".join(f"{o['op']} {o['pointer']}" for o in dedup)
    return params, summary, edit_common.unified_diff(target, data, new)


def preview(ctx, items) -> PreviewResult:
    params, summary, diff = preview_compute(ctx, items, tuple(hazards.JSON_H))
    validate_params(params)
    return PreviewResult(params, summary, diff)
