"""Closed tables of definition T (narrowing only). Embedded in GER's code, versioned (HAZARD_VERSION).

- H (units that may be removed): JSON pointers / TOML tables / line patterns per file type
- K (constants that may be added): replacement values
Values in the plan are not trusted. Whether a unit to remove matches this table is evaluated by GER itself against the current content.
Anything not in the table (for example permissions.deny in .claude/settings.json, ignore-scripts=true in .npmrc, disable_functions)
cannot be removed (removing it would loosen protection).
"""
from __future__ import annotations

import posixpath
import re

HAZARD_VERSION = "ger-hazards-2"

# --- Dangerous command detection ---------------------------------------------------------------
# For agent hooks (hooks in .claude/settings.json).
DANGEROUS_CMD = re.compile(
    r'(^|[\s"/])(curl|wget)([\s"]|$)|bash -c|sh -c|powershell(\.exe)? .*-(e|enc|encodedcommand)\s|node -e|python[0-9.]* -c|base64')
# For MCP server command + args. Copy of MCP_DANGER_RE from ZES §17 (zes-scan.sh; case-insensitive).
#   If ZES reports HIGH but GER does not match, nothing is found to remove and automatic remediation fails (keep both aligned)
_MCP_OPTS = r'(\s+-\S*)*\s+'
MCP_DANGER = re.compile(
    r'(^|[\s"/])(curl|wget)([\s"]|$)|base64'
    r'|(^|[\s"/])(ba|z|da|k|a|fi)?sh(\.exe)?' + _MCP_OPTS + r'-[a-z]*c[a-z]*(\s|$)'
    r'|(^|[\s"/])(node|nodejs|bun)(\.exe)?' + _MCP_OPTS + r'(-e|--eval|-p|--print)([\s=]|$)'
    r'|(^|[\s"/])deno(\.exe)?\s+eval(\s|$)'
    r'|(^|[\s"/])python[0-9.]*(\.exe)?' + _MCP_OPTS + r'-[a-z]*c(\s|$)'
    r'|(^|[\s"/])(perl|ruby)[0-9.]*(\.exe)?' + _MCP_OPTS + r'-[a-z]*e(\s|$)'
    r'|(^|[\s"/])php[0-9.]*(\.exe)?' + _MCP_OPTS + r'-r(\s|$)'
    r'|(^|[\s"/])(osascript|lua[0-9.]*)' + _MCP_OPTS + r'-e(\s|$)'
    r'|(^|[\s"/])(pwsh|powershell)(\.exe)?(\s+\S+)*\s+[-/](c|command|e|ec|enc|encodedcommand)(\s|$)'
    r'|(^|[\s"/])cmd(\.exe)?\s+/[ck](\s|$)',
    re.IGNORECASE)
# A hook runs a script in the working tree (node .claude/setup.mjs and so on)
LOCAL_SCRIPT = re.compile(r'^\s*(node|deno|bun|python[0-9.]*|bash|sh|zsh|ruby|perl)\s+\.{0,2}/?[\w.@-]+(/[\w.@-]+)*\s*$')


def mcp_cmdline(server) -> str | None:
    """Builds command + args from an MCP server definition (dict) in the same form as ZES. None if there is no command."""
    if not isinstance(server, dict) or "command" not in server:
        return None
    args = server.get("args", [])
    if isinstance(args, list):
        a = " ".join(str(x) for x in args)
    else:
        a = str(args)
    return f"{server['command']} {a}".strip()


def dangerous_server(server) -> bool:
    c = mcp_cmdline(server)
    # Like ZES, match each line of the command split at newlines
    return c is not None and any(MCP_DANGER.search(line) for line in c.split("\n"))


def _commands(obj):
    """Collects every command string in the value (supports nested hooks: hooks[].hooks[].command)."""
    out = []
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if isinstance(cur.get("command"), str):
                out.append(cur["command"])
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


def dangerous_hook(value) -> bool:
    return any(DANGEROUS_CMD.search(c) or LOCAL_SCRIPT.match(c) for c in _commands(value))


# --- JSON H (edit_json / disable_mcp_server) ----------------------------------------------------
MCP_JSON_BASENAMES = {".mcp.json", "mcp.json", "mcp_config.json", ".claude.json", "claude_desktop_config.json"}
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
                 "preuninstall", "uninstall", "postuninstall", "prepublish")


def _is_claude_settings(path: str) -> bool:
    return posixpath.basename(path) in ("settings.json", "settings.local.json") and \
        posixpath.basename(posixpath.dirname(path)) == ".claude"


def _is_vscode_tasks(path: str) -> bool:
    return posixpath.basename(path) == "tasks.json" and posixpath.basename(posixpath.dirname(path)) == ".vscode"


# id -> (file predicate, pointer regular expression, value predicate, auto-selection predicate, operation)
JSON_H = {
    "mcp.server": (lambda p: posixpath.basename(p) in MCP_JSON_BASENAMES,
                   re.compile(r"^(/mcpServers/[^/]+|/servers/[^/]+|/projects/[^/]+/mcpServers/[^/]+)$"),
                   lambda v: isinstance(v, dict), dangerous_server, "remove"),
    "npm.lifecycle": (lambda p: posixpath.basename(p) == "package.json",
                      re.compile(r"^/scripts/(" + "|".join(NPM_LIFECYCLE) + r")$"),
                      lambda v: isinstance(v, str), lambda v: True, "remove"),
    "claude.hook": (_is_claude_settings,
                    re.compile(r"^/hooks/[A-Za-z]+/[0-9]+(/hooks/[0-9]+)?$"),
                    lambda v: isinstance(v, dict), dangerous_hook, "remove"),
    "vscode.task_run_on": (_is_vscode_tasks,
                           re.compile(r"^/tasks/[0-9]+/runOptions/runOn$"),
                           lambda v: v == "folderOpen", lambda v: v == "folderOpen", "replace_const"),
}
# K: values that replace_const may write (per H id)
JSON_K = {"vscode.task_run_on": ("default",)}
# H entries that disable_mcp_server (preset) may use
MCP_PRESET = ("mcp.server",)


def json_hazard(path: str, pointer: str, value, op: str):
    """The H id matching (path, pointer, current value, op). None if nothing matches."""
    for hid, (fpred, ptr, vpred, _auto, hop) in JSON_H.items():
        if hop == op and fpred(path) and ptr.match(pointer) and vpred(value):
            return hid
    return None


# --- TOML H (edit_toml / disable_mcp_server, Phase 1 scope) ---------------------------------------
def is_codex_config(path: str) -> bool:
    return posixpath.basename(path) == "config.toml" and posixpath.basename(posixpath.dirname(path)) == ".codex"


def toml_hazard(path: str, key_path) -> str | None:
    if is_codex_config(path) and isinstance(key_path, (list, tuple)) and len(key_path) == 2 and key_path[0] == "mcp_servers":
        return "mcp.server.toml"
    return None


# --- Line H (remove_line) --------------------------------------------------------------------------
SHELL_RC = {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
            ".kshrc", ".mkshrc", ".envrc"}


def _is_shell_rc(p: str) -> bool:
    return posixpath.basename(p) in SHELL_RC


def _is_git_config(p: str) -> bool:
    return p.endswith("/.git/config") or posixpath.basename(p) == ".gitconfig" or p.endswith("/.config/git/config")


def _is_php_ini(p: str) -> bool:
    b = posixpath.basename(p)
    return b == "php.ini" or (b.endswith(".ini") and posixpath.basename(posixpath.dirname(p)) == "conf.d")


def _is_ld_preload(p: str) -> bool:
    return posixpath.basename(p) == "ld.so.preload"


def _is_cron_d(p: str) -> bool:
    return p.startswith("/etc/cron.d/") and p.count("/") == 3


# id -> (file predicate, line regular expression (must match the whole line), kind of lexical check)
LINE_H = {
    "sh.ld_preload": (_is_shell_rc, re.compile(r"^\s*(export\s+)?LD_PRELOAD=\S+\s*(#.*)?$"), "shell"),
    "sh.curl_pipe_sh": (_is_shell_rc,
                        re.compile(r"^\s*(curl|wget)\s[^;&|#`$()]*\|\s*(sudo\s+)?(ba|z|da|k)?sh(\s+-s?)?\s*(#.*)?$"), "shell"),
    "sh.base64_pipe_sh": (_is_shell_rc,
                          re.compile(r"^\s*(echo|printf)\s[^;&|#`$()]*\|\s*base64\s+(-d|--decode|-D)\s*\|\s*(ba|z|da|k)?sh\s*(#.*)?$"), "shell"),
    "sh.histfile_null": (_is_shell_rc, re.compile(r"^\s*(export\s+)?HISTFILE=/dev/null\s*(#.*)?$"), "shell"),
    "git.exec_key": (_is_git_config, re.compile(r"^\s*(fsmonitor|sshCommand|hooksPath)\s*=.*$", re.IGNORECASE), "plain"),
    "php.auto_prepend": (_is_php_ini, re.compile(r"^\s*auto_(prepend|append)_file\s*=\s*\S.*$"), "plain"),
    "ldso.entry": (_is_ld_preload, re.compile(r"^\s*[^#\s].*$"), "plain"),
    "cron.fetch_exec": (_is_cron_d, re.compile(r"^(?!\s*#).*(\b(curl|wget)\b|/tmp/|/dev/shm/).*$"), "plain"),
}


def line_patterns_for(path: str) -> list[str]:
    return [hid for hid, (fpred, _r, _k) in LINE_H.items() if fpred(path)]


# --- quarantine: no cosmetic remediation (Q-6) ------------------------------------------------------
def metadata_only(path: str, kind: str) -> str | None:
    """For a self quarantine that removes only the metadata ZES uses as evidence and leaves the code, returns the reason."""
    b = posixpath.basename(path)
    parts = path.split("/")
    if b.endswith((".dist-info", ".egg-info")):
        return "quarantining only dist-info / egg-info metadata leaves the code in place (use relation pypi_record)"
    if b == "package.json" and "node_modules" in parts[:-1]:
        return "quarantining only the package.json of a node_modules package leaves the code in place (use relation npm_pkg_dir)"
    if b == "manifest.json" and "Extensions" in parts[:-1]:
        return "quarantining only the manifest.json of an extension leaves the code in place (use relation ext_dir)"
    if b == "skill.contract.json":
        return "quarantining only skill.contract.json leaves the skill's code in place (use relation skill_dir)"
    return None


# --- Protected targets and targets that require root (§4.4) ---------------------------------------
SYSTEM_TOP = ("/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/var", "/opt", "/boot",
              "/dev", "/proc", "/sys", "/run", "/srv", "/root", "/home", "/Users", "/System", "/Library",
              "/Applications", "/private", "/tmp", "/nix", "/snap")
ROOT_PREFIXES = ("/etc/", "/usr/", "/var/", "/opt/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/",
                 "/boot/", "/System/", "/Library/", "/private/etc/", "/private/var/")
ETC_ALLOW = re.compile(r"^/etc/(ld\.so\.preload|hosts|cron\.d/[^/]+)$")


USER_TMP_PREFIXES = ("/var/folders/", "/private/var/folders/", "/var/tmp/")


def root_required_lexical(path: str) -> bool:
    """Targets that lexically require root (under system directories, except the per-user temporary areas of macOS).
    The owner check (owner is not the executing user) is added by GER at run time. Same rule as ZET (zet/remedy.py)."""
    return path.startswith(ROOT_PREFIXES) and not path.startswith(USER_TMP_PREFIXES)
