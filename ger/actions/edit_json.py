"""edit_json operation (JSON and JSONC) - reversible.

params: {"format": "json"|"jsonc",
         "ops": [{"op": "remove"|"replace_const", "pointer": "/mcpServers/evil", "before_sha256": "<SHA-256 of the canonical JSON of the value>",
                  "const"?: "default"}],
         "file_sha256", "expected_after_sha256"}
- Each pointer must match GER's table H (hazards.JSON_H) (T-1). A replace_const value must be in table K (T-2)
- The result is parsed again by a different method and must equal "before - removed units (+) K replacements" (T-3)
- Formatting and comments are kept. Duplicate keys are rejected
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
        raise ActionError('params must be {"format", "ops", "file_sha256", "expected_after_sha256"} (built by ger preview)')
    if params["format"] not in ("json", "jsonc"):
        raise ActionError("params.format must be json or jsonc")
    edit_common.check_sha(params["file_sha256"], "file_sha256")
    edit_common.check_sha(params["expected_after_sha256"], "expected_after_sha256")
    ops = params["ops"]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS:
        raise ActionError(f"params.ops must have 1-{MAX_OPS} entries")
    for o in ops:
        if not isinstance(o, dict) or o.get("op") not in allowed_ops:
            raise ActionError(f"op must be one of {' / '.join(allowed_ops)}")
        want = {"op", "pointer", "before_sha256"} | ({"const"} if o["op"] == "replace_const" else set())
        if set(o) != want or not isinstance(o["pointer"], str) or not o["pointer"].startswith("/"):
            raise ActionError(f"op fields must be {sorted(want)} (pointer is a JSON pointer starting with /)")
        edit_common.check_sha(o["before_sha256"], "ops[].before_sha256")


def check_ops(path: str, root, ops: list, allowed_h=None) -> None:
    """T-1 / T-2: each op must match H / K against the current content (the plan's values are not trusted)."""
    for o in ops:
        try:
            _par, _idx, node = jsonedit.find(root, o["pointer"])
        except jsonedit.JsonEditError as e:
            raise ActionError(str(e)) from None
        val = jsonedit.to_python(node)
        hid = hazards.json_hazard(path, o["pointer"], val, o["op"])
        if hid is None or (allowed_h is not None and hid not in allowed_h):
            raise ActionError(f"pointer {o['pointer']} does not match GER's hazard table (H); it cannot be removed (T-1)", gate="G-10")
        if sha256(canonical(val)) != o["before_sha256"]:
            raise ActionError(f"the value at pointer {o['pointer']} changed since preview (does not match before_sha256)")
        if o["op"] == "replace_const" and o.get("const") not in hazards.JSON_K.get(hid, ()):
            raise ActionError(f"a replace_const value must be in the constant table (K) (T-2): {hid}", gate="G-10")


def compute(path: str, data: bytes, fmt: str, ops: list, allowed_h=None) -> bytes:
    text = edit_common.decode_utf8(data)
    try:
        root = jsonedit.parse(text, fmt == "jsonc")
    except jsonedit.JsonEditError as e:
        raise ActionError(f"cannot parse as {fmt}: {e}") from None
    check_ops(path, root, ops, allowed_h)
    try:
        new, expected = jsonedit.apply_ops(text, fmt, ops)
        after = jsonedit.reparse(new, fmt)
    except (jsonedit.JsonEditError, ValueError) as e:
        raise ActionError(f"cannot parse the result (T-3): {e}", gate="G-10") from None
    if canonical(after) != canonical(expected):
        raise ActionError("the re-parsed result does not equal \"before - removed units\" (T-3)", gate="G-10")
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


def select_ops(path: str, value, hids, text: str = "") -> list[dict]:
    """The ops automatic selection makes for the H ids hids on the parsed file value (text: the file as read)."""
    ops = []
    for hid in hids:
        fpred, rx, vpred, auto, hop = hazards.JSON_H[hid]
        if not fpred(path):
            continue
        if auto is None:  # Selected by the rule of the id over the whole document (claude.hook: the hooks ZES reports)
            cand = [(p, v) for p, v in ((p, _get(value, p)) for p in hazards.JSON_SELECT[hid](value, text))
                    if rx.match(p) and vpred(v)]
        else:
            cand = [(p, v) for p, v in _walk(value) if p and rx.match(p) and vpred(v) and auto(v)]
        for ptr, v in cand:
            o = {"op": hop, "pointer": ptr, "before_sha256": sha256(canonical(v))}
            if hop == "replace_const":
                o["const"] = hazards.JSON_K[hid][0]
            ops.append(o)
    # Drop nested duplicates (a child is not needed when its parent is removed)
    ptrs = [o["pointer"] for o in ops]
    return [o for o in ops if not any(p != o["pointer"] and o["pointer"].startswith(p + "/") for p in ptrs)]


def _get(value, ptr: str):
    for tok in ptr.split("/")[1:]:
        tok = tok.replace("~1", "/").replace("~0", "~")
        value = value[int(tok)] if isinstance(value, list) else value[tok]
    return value


def preview_compute(ctx, items, hids, allowed_h=None):
    """(params, summary, diff). If params has select (H ids), ops are chosen automatically."""
    target = items[0].action["target"]
    res = ctx.pool.add(fsutil.resolve(target))
    from .base import check_regular
    check_regular(res.st)
    data = fsutil.read_file(res.parent_fd, res.name, res.st, limit=fsutil.EDIT_MAX_BYTES)
    text = edit_common.decode_utf8(data)
    try:
        fmt = jsonedit.detect_format(text)
    except jsonedit.JsonEditError as e:
        # Fail closed: GER edits only a file it parses strictly (no duplicate keys, nesting up to 64, valid Unicode),
        #   even where an agent's own reader is more lenient; such an entry is removed by hand (a checklist)
        raise ActionError(f"cannot parse as JSON / JSONC: {e}. GER edits only files it can parse strictly; "
                          "remove the entry by hand (checklist)") from None
    root = jsonedit.parse(text, fmt == "jsonc")
    value = jsonedit.to_python(root)
    ops = []
    for it in items:
        p = it.action["params"]
        if "select" in p:
            sel = p["select"] if isinstance(p["select"], list) else [p["select"]]
            if any(s not in hazards.JSON_H for s in sel):
                raise ActionError(f"params.select must be H ids ({', '.join(hazards.JSON_H)})")
            ops += select_ops(target, value, [s for s in sel if s in hids], text)
        else:
            for o in p.get("ops", []):
                if "pointer" not in o:
                    raise ActionError("ops[].pointer is missing")
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
        raise ActionError("nothing to remove (no dangerous value matching H)")
    new = compute(target, data, fmt, dedup, allowed_h)
    params = {"format": fmt, "ops": dedup, "file_sha256": sha256(data), "expected_after_sha256": sha256(new)}
    summary = f"{fmt}: " + ", ".join(f"{o['op']} {o['pointer']}" for o in dedup)
    return params, summary, edit_common.unified_diff(target, data, new)


def preview(ctx, items) -> PreviewResult:
    params, summary, diff = preview_compute(ctx, items, tuple(hazards.JSON_H))
    validate_params(params)
    return PreviewResult(params, summary, diff)
