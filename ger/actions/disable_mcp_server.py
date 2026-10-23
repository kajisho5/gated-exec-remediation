"""disable_mcp_server 操作 — edit_json / edit_toml の preset。可逆。

MCP サーバーの定義だけを取り除く。JSON / JSONC は pointer を /mcpServers/<name>、/servers/<name>（VS Code）、
/projects/<p>/mcpServers/<name>（~/.claude.json）に限る。TOML（Codex の .codex/config.toml）は [mcp_servers.<name>]
（Phase 1 の範囲: 標準のテーブルヘッダで定義されたもの）に限る。取り除いた定義はバックアップから戻せる（ger restore）。

params: {"format": "json"|"jsonc"|"toml", "ops": [...], "file_sha256", "expected_after_sha256"}
  json / jsonc の ops: [{"op": "remove", "pointer", "before_sha256"}]
  toml の ops: [{"op": "remove_table", "key_path": ["mcp_servers", "<name>"], "before_sha256"}]
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
        raise ActionError("params.format は json / jsonc / toml のいずれか")
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
                    raise ActionError("disable_mcp_server が取り除けるのは [mcp_servers.<name>] だけです（T-1）")
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
        for it in items:  # select は MCP サーバーだけ
            if "select" in it.action["params"]:
                it.action["params"]["select"] = "mcp.server"
        params, summary, diff = edit_json.preview_compute(ctx, items, hazards.MCP_PRESET, allowed_h=hazards.MCP_PRESET)
    validate_params(params)
    return PreviewResult(params, summary, diff)
