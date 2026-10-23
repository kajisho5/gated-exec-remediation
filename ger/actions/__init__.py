"""Operation registry. Operation types not registered here are rejected by G-5.

No operation deletes anything. Every operation keeps the state before the change in the quarantine store (chmod keeps the original mode in remediation-log).
write_config / rotate_secret are not registered (revoking or rotating a secret needs the network and irreversible operations,
so it is a checklist at every stage).
"""
from . import checklist, chmod, disable_mcp_server, edit_json, edit_toml, quarantine, remove_line

REGISTRY = {m.TYPE: m for m in (chmod, quarantine, edit_json, edit_toml, remove_line, disable_mcp_server, checklist)}
# Operations that change the file system (everything except checklist)
FS_CHANGING = frozenset(t for t in REGISTRY if t != checklist.TYPE)
EDIT_TYPES = frozenset({edit_json.TYPE, edit_toml.TYPE, remove_line.TYPE, disable_mcp_server.TYPE})
