"""操作レジストリ。ここに登録されていない操作種別は G-5 で拒否する。

削除する操作は無い。どの操作も、変える前の状態を隔離ストアに残す（chmod は元の mode を remediation-log に残す）。
write_config / rotate_secret は登録しない（秘密情報の失効・ローテーションはネットワークと不可逆な操作が要るため、
どの段階でもチェックリストにする）。
"""
from . import checklist, chmod, disable_mcp_server, edit_json, edit_toml, quarantine, remove_line

REGISTRY = {m.TYPE: m for m in (chmod, quarantine, edit_json, edit_toml, remove_line, disable_mcp_server, checklist)}
# ファイルシステムを変える操作（checklist 以外）
FS_CHANGING = frozenset(t for t in REGISTRY if t != checklist.TYPE)
EDIT_TYPES = frozenset({edit_json.TYPE, edit_toml.TYPE, remove_line.TYPE, disable_mcp_server.TYPE})
