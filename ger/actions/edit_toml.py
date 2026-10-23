"""edit_toml operation (Phase 1 scope) - reversible.

params: {"ops": [{"op": "remove_table", "key_path": ["mcp_servers", "evil"], "before_sha256"}],
         "file_sha256", "expected_after_sha256"}
- Only tables matching H (hazards.toml_hazard: [mcp_servers.<name>] in .codex/config.toml) can be removed (T-1)
- The table must be defined only by standard table headers and their subtables. Dotted keys and inline tables are rejected
- The result is parsed again with tomllib and must equal "before - removed tables" (T-3)
"""
from __future__ import annotations

from .. import fsutil, hazards, tomledit
from ..core import canonical, sha256
from . import edit_common
from .base import ActionError, PreviewResult, check_regular

TYPE = "edit_toml"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 0
MAX_OPS = 64


def validate_params(params: dict) -> None:
    if not isinstance(params, dict) or set(params) != {"ops", "file_sha256", "expected_after_sha256"}:
        raise ActionError('params must be {"ops", "file_sha256", "expected_after_sha256"} (built by ger preview)')
    edit_common.check_sha(params["file_sha256"], "file_sha256")
    edit_common.check_sha(params["expected_after_sha256"], "expected_after_sha256")
    ops = params["ops"]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS:
        raise ActionError(f"params.ops must have 1-{MAX_OPS} entries")
    for o in ops:
        if not isinstance(o, dict) or set(o) != {"op", "key_path", "before_sha256"} or o["op"] != "remove_table":
            raise ActionError('ops[] must be {"op": "remove_table", "key_path", "before_sha256"}')
        kp = o["key_path"]
        if not isinstance(kp, list) or not 1 <= len(kp) <= 8 or not all(isinstance(k, str) and k for k in kp):
            raise ActionError("ops[].key_path must be a non-empty array of strings")
        edit_common.check_sha(o["before_sha256"], "ops[].before_sha256")


def _value(doc, kp):
    cur = doc
    for k in kp:
        if not isinstance(cur, dict) or k not in cur:
            raise ActionError(f"table {'.'.join(kp)} not found")
        cur = cur[k]
    return cur


def compute(path: str, data: bytes, ops: list) -> bytes:
    text = edit_common.decode_utf8(data)
    try:
        doc = tomledit.loads(text)
    except tomledit.TomlEditError as e:
        raise ActionError(str(e)) from None
    for o in ops:
        if hazards.toml_hazard(path, o["key_path"]) is None:
            raise ActionError(f"table {'.'.join(o['key_path'])} does not match GER's hazard table (H) (T-1)", gate="G-10")
        v = _value(doc, o["key_path"])
        if not isinstance(v, dict):
            raise ActionError(f"{'.'.join(o['key_path'])} is not a table")
        if sha256(canonical(tomledit.plain(v))) != o["before_sha256"]:
            raise ActionError(f"the value of table {'.'.join(o['key_path'])} changed since preview (does not match before_sha256)")
    try:
        new, expected = tomledit.remove_tables(text, [tuple(o["key_path"]) for o in ops])
        after = tomledit.loads(new)
    except tomledit.TomlEditError as e:
        raise ActionError(str(e)) from None
    if canonical(tomledit.plain(after)) != canonical(tomledit.plain(expected)):
        raise ActionError("the re-parsed result does not equal \"before - removed tables\" (T-3)", gate="G-10")
    return new.encode("utf-8")


def prepare(ctx, items):
    return edit_common.prepare_edit(ctx, items, TYPE, compute)


def preview_compute(ctx, items):
    from .. import hazards as hz
    target = items[0].action["target"]
    res = ctx.pool.add(fsutil.resolve(target))
    check_regular(res.st)
    data = fsutil.read_file(res.parent_fd, res.name, res.st, limit=fsutil.EDIT_MAX_BYTES)
    text = edit_common.decode_utf8(data)
    try:
        doc = tomledit.loads(text)
    except tomledit.TomlEditError as e:
        raise ActionError(str(e)) from None
    kps = []
    for it in items:
        p = it.action["params"]
        if "select" in p:
            for name, v in (doc.get("mcp_servers") or {}).items():
                if isinstance(v, dict) and hz.dangerous_server(v, toml=True):
                    kps.append(["mcp_servers", name])
        else:
            kps += [list(o["key_path"]) for o in p.get("ops", [])]
    uniq = []
    for k in kps:
        if k not in uniq:
            uniq.append(k)
    if not uniq:
        raise ActionError("nothing to remove (no MCP server table with a dangerous command)")
    ops = [{"op": "remove_table", "key_path": k, "before_sha256": sha256(canonical(tomledit.plain(_value(doc, k))))}
           for k in uniq]
    new = compute(target, data, ops)
    params = {"ops": ops, "file_sha256": sha256(data), "expected_after_sha256": sha256(new)}
    return params, "toml: " + ", ".join("remove_table [" + ".".join(k) + "]" for k in uniq), \
        edit_common.unified_diff(target, data, new)


def preview(ctx, items) -> PreviewResult:
    params, summary, diff = preview_compute(ctx, items)
    validate_params(params)
    return PreviewResult(params, summary, diff)
