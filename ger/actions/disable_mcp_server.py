"""disable_mcp_server operation - a preset of edit_json / edit_toml. Reversible.

Removes only MCP server definitions. For JSON / JSONC the pointer is limited to /mcpServers/<name>, /servers/<name> (VS Code),
/projects/<p>/mcpServers/<name> (~/.claude.json). For TOML (Codex .codex/config.toml) it is limited to [mcp_servers.<name>]
(Phase 1 scope: defined with a standard table header). A removed definition can be restored from the backup (ger restore).

params: {"format": "json"|"jsonc"|"toml", "ops": [...], "file_sha256", "expected_after_sha256"}
  json / jsonc ops: [{"op": "remove", "pointer", "before_sha256"}]
  toml ops: [{"op": "remove_table", "key_path": ["mcp_servers", "<name>"], "before_sha256"}]
"""
from __future__ import annotations

from .. import hazards
from . import edit_common, edit_json, edit_toml
from .base import ActionError, PreviewResult

TYPE = "disable_mcp_server"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 0


def validate_params(params: dict) -> None:
    if not isinstance(params, dict) or params.get("format") not in ("json", "jsonc", "toml"):
        raise ActionError("params.format must be one of json / jsonc / toml")
    if params["format"] == "toml":
        rest = {k: v for k, v in params.items() if k != "format"}
        edit_toml.validate_params(rest)
    else:
        edit_json.validate_params(params, allowed_ops=("remove",))


def _compute(fmt):
    def f(path, data, ops):
        if fmt == "toml":
            for o in ops:
                if hazards.toml_hazard(path, o["key_path"]) != "mcp.server.toml":
                    raise ActionError("disable_mcp_server can remove only [mcp_servers.<name>] (T-1)", gate="G-10")
            return edit_toml.compute(path, data, ops)
        return edit_json.compute(path, data, fmt, ops, allowed_h=hazards.MCP_PRESET)
    return f


def prepare(ctx, items):
    fmt = items[0].action["params"]["format"]
    return edit_common.prepare_edit(ctx, items, TYPE, _compute(fmt))


def preview(ctx, items) -> PreviewResult:
    target = items[0].action["target"]
    if hazards.is_codex_config(target):
        params, summary, diff = edit_toml.preview_compute(ctx, items)
        params = {"format": "toml", **params}
    else:
        for it in items:  # select covers MCP servers only
            if "select" in it.action["params"]:
                it.action["params"]["select"] = "mcp.server"
        params, summary, diff = edit_json.preview_compute(ctx, items, hazards.MCP_PRESET, allowed_h=hazards.MCP_PRESET)
    validate_params(params)
    return PreviewResult(params, summary, diff)
