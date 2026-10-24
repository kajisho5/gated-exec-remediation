"""Closed tables of definition T (narrowing only). Embedded in GER's code, versioned (HAZARD_VERSION).

- H (units that may be removed): JSON pointers / TOML tables / line patterns per file type
- K (constants that may be added): replacement values
Values in the plan are not trusted. Whether a unit to remove matches this table is evaluated by GER itself against the current content.
Anything not in the table (for example permissions.deny in .claude/settings.json, ignore-scripts=true in .npmrc, disable_functions)
cannot be removed (removing it would loosen protection).
"""
from __future__ import annotations

import json
import posixpath
import re

HAZARD_VERSION = "ger-hazards-3"

# --- Dangerous command detection ---------------------------------------------------------------
# Every pattern here is matched in linear time: a file of up to EDIT_MAX_BYTES (1 MB) is read, and its content comes from
#   the scanned (possibly hostile) tree. Python's backtracking takes quadratic time on (\s+-\S*)*\s+ and on .* followed
#   by a fixed tail, so those parts are matched by the token scanners below instead of a regular expression, with the
#   same result as the regular expressions written in the comments (tests/test_hazards.py compares them on a random corpus).
#
# For agent hooks (hooks in .claude/settings.json):
#   DANGEROUS_CMD = (^|[\s"/])(curl|wget)([\s"]|$)|bash -c|sh -c|powershell(\.exe)? .*-(e|enc|encodedcommand)\s|node -e
#                   |python[0-9.]* -c|base64          (case-sensitive, Unicode \s, as before)
_HOOK_SIMPLE = re.compile(r'(^|[\s"/])(curl|wget)([\s"]|$)|bash -c|sh -c|node -e|python[0-9.]* -c|base64')
_HOOK_PS_HEAD = re.compile(r'powershell(\.exe)? ')
_HOOK_PS_FLAG = re.compile(r'-(e|enc|encodedcommand)\s')


def dangerous_cmd(command: str) -> bool:
    """True if a hook command matches DANGEROUS_CMD (above)."""
    if _HOOK_SIMPLE.search(command):
        return True
    # powershell(\.exe)? .*-(e|enc|encodedcommand)\s: . does not match a newline, so the flag must start on the line of
    #   the head (its \s may be that newline). Only the first head of each line matters (a later one sees less of the line)
    line_end = -1
    for h in _HOOK_PS_HEAD.finditer(command):
        if h.start() <= line_end:
            continue
        line_end = command.find("\n", h.end())
        if line_end < 0:
            line_end = len(command)
        if _HOOK_PS_FLAG.search(command, h.end(), line_end + 1):
            return True
    return False


# For MCP server command + args. Copy of MCP_DANGER_RE from ZES §17 (zes-scan.sh; POSIX ERE, case-insensitive, C locale):
#   If ZES reports HIGH but GER does not match, nothing is found to remove and automatic remediation fails (keep both aligned)
#     (^|[\s"/])(curl|wget)([\s"]|$)|base64
#     |(^|[\s"/])(ba|z|da|k|a|fi)?sh(\.exe)?          OPTS -[a-z]*c[a-z]*(\s|$)
#     |(^|[\s"/])(node|nodejs|bun)(\.exe)?           OPTS (-e|--eval|-p|--print)([\s=]|$)
#     |(^|[\s"/])deno(\.exe)?\s+eval(\s|$)
#     |(^|[\s"/])python[0-9.]*(\.exe)?               OPTS -[a-z]*c(\s|$)
#     |(^|[\s"/])(perl|ruby)[0-9.]*(\.exe)?           OPTS -[a-z]*e(\s|$)
#     |(^|[\s"/])php[0-9.]*(\.exe)?                  OPTS -r(\s|$)
#     |(^|[\s"/])(osascript|lua[0-9.]*)              OPTS -e(\s|$)
#     |(^|[\s"/])cmd(\.exe)?\s+/[ck](\s|$)
#     |(^|[\s"/])(pwsh|powershell)(\.exe)?(\s+\S+)*\s+[-/](c|command|e|ec|enc|encodedcommand)(\s|$)
#   where OPTS is (\s+-\S*)*\s+ (zero or more option tokens). re.ASCII: like grep in the C locale, \s is ASCII whitespace
#   only and case folding is ASCII only.
# Matching runs on the line with ASCII letters lowered (the same positions), which is what IGNORECASE does with re.ASCII,
#   so the patterns below are lowercase and need no IGNORECASE. A pattern starts with a literal where it can (the
#   boundary (^|[\s"/]) before it is a negative lookbehind after it), which lets the regex engine skip ahead quickly.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_NB = r'[^\s"/]'  # a character that is not a boundary (a head starts at the line start or after whitespace, " or /)
_MCP_SIMPLE = tuple(re.compile(p, re.ASCII) for p in (
    r'base64',
    r'(?:curl(?<!' + _NB + r'curl)|wget(?<!' + _NB + r'wget))(?=[\s"]|$)',
    r'deno(?<!' + _NB + r'deno)(?:\.exe)?\s+eval(?=\s|$)',
    r'cmd(?<!' + _NB + r'cmd)(?:\.exe)?\s+/[ck](?=\s|$)',
))
# The OPTS branches: (head, flag). A head is followed by whitespace. The option tokens after it form a run of
#   whitespace-separated tokens that start with "-" (\S* cannot stop before the whitespace the next \s+ needs), and the
#   flag is one whole token of that run (node: it may go on with "=" and more). So a branch matches exactly when some
#   head has a flag token inside the maximal run of "-" tokens that follows it. The run is matched possessively, and a
#   head inside the run of an earlier head is skipped (its run ends at the same place and holds fewer tokens), so every
#   branch is a constant number of linear passes. The flag patterns are written so that a long token cannot make them
#   backtrack (a lookahead or a lookbehind instead of [a-z]*c[a-z]*)
_B = r'(?:^|(?<=[\s"/]))'
# A head is searched only where an option token follows it (\s+-): a branch never matches with an empty run
_MCP_OPTS_BRANCHES = tuple((re.compile(_B + h + r'(?=\s+-)', re.ASCII), re.compile(f, re.ASCII)) for h, f in (
    (r'(ba|z|da|k|a|fi)?sh(\.exe)?', r'-(?<=\s-)(?=[a-z]*c)[a-z]++(?=\s|$)'),  # -[a-z]*c[a-z]*(\s|$)
    (r'(node|nodejs|bun)(\.exe)?', r'-(?<=\s-)(e|-eval|p|-print)(?=[\s=]|$)'),
    (r'python[0-9.]*(\.exe)?', r'-(?<=\s-)[a-z]*+(?<=c)(?=\s|$)'),  # -[a-z]*c(\s|$)
    (r'(perl|ruby)[0-9.]*(\.exe)?', r'-(?<=\s-)[a-z]*+(?<=e)(?=\s|$)'),  # -[a-z]*e(\s|$)
    (r'php[0-9.]*(\.exe)?', r'-(?<=\s-)r(?=\s|$)'),
    (r'(osascript|lua[0-9.]*)', r'-(?<=\s-)e(?=\s|$)'),
))
# Literal parts every head of a branch contains (a branch whose literal is missing is not searched)
_MCP_OPTS_LITERALS = (("sh",), ("node", "bun"), ("python",), ("perl", "ruby"), ("php",), ("osascript", "lua"))
_OPT_RUN = re.compile(r'(?:\s+-\S*+)*+', re.ASCII)
# ZES branch (pwsh|powershell)(\.exe)?(\s+\S+)*\s+[-/](c|command|...)(\s|$), split in two: (\s+\S+)*\s+ is any text that starts
#   and ends with whitespace, so the branch matches exactly when the first head followed by whitespace has a flag (with its
#   leading whitespace) after it
_PWSH_HEAD = re.compile(r'(?:pwsh(?<!' + _NB + r'pwsh)|powershell(?<!' + _NB + r'powershell))(\.exe)?(?=\s)', re.ASCII)
_PWSH_FLAG = re.compile(r'\s[-/](c|command|e|ec|enc|encodedcommand)(\s|$)', re.ASCII)


def _mcp_opts_match(low: str) -> bool:
    for (head, flag), lits in zip(_MCP_OPTS_BRANCHES, _MCP_OPTS_LITERALS):
        if not any(x in low for x in lits):
            continue
        run_end = -1
        for h in head.finditer(low):
            if h.start() < run_end:
                continue
            run_end = _OPT_RUN.match(low, h.end()).end()
            if flag.search(low, h.end(), run_end):
                return True
    return False


def mcp_danger(line: str) -> bool:
    """True if one line of an MCP command matches ZES's MCP_DANGER_RE (above)."""
    low = line.translate(_ASCII_LOWER)
    if any(p.search(low) for p in _MCP_SIMPLE) or _mcp_opts_match(low):
        return True
    h = _PWSH_HEAD.search(low)
    return h is not None and _PWSH_FLAG.search(low, h.end()) is not None


# A hook runs a script in the working tree (node .claude/setup.mjs and so on)
LOCAL_SCRIPT = re.compile(r'^\s*(node|deno|bun|python[0-9.]*|bash|sh|zsh|ruby|perl)\s+\.{0,2}/?[\w.@-]+(/[\w.@-]+)*\s*$')


def _jq_tostring(v) -> str:
    """jq's tostring: a string as it is, anything else as compact JSON."""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


_TOML_CTRL = re.compile(r'[\x00-\x1f\x7f]')


def mcp_cmdline(server, toml: bool = False) -> str | None:
    """Builds command + args from an MCP server definition (dict) in the same form as ZES. None if there is no command.

    JSON (ZES: jq): command and every arg through tostring, args that is not an array through tostring, null args as [].
    bash `read` drops NUL characters, so they are removed here too.
    TOML (ZES: codex_toml_mcp_commands): only a string command and string args count; control characters become spaces."""
    if not isinstance(server, dict) or "command" not in server:
        return None
    cmd, args = server["command"], server.get("args")
    if toml:
        if not isinstance(cmd, str) or cmd == "":
            return None
        if isinstance(args, str):
            args = [args]
        a = " ".join(x for x in (args if isinstance(args, list) else []) if isinstance(x, str))
        return _TOML_CTRL.sub(" ", f"{cmd} {a}" if a else cmd)
    if args is None or args is False:
        args = []
    a = " ".join(_jq_tostring(x) for x in args) if isinstance(args, list) else _jq_tostring(args)
    return f"{_jq_tostring(cmd)} {a}".replace("\0", "")


def dangerous_server(server, toml: bool = False) -> bool:
    c = mcp_cmdline(server, toml)
    # Like ZES, match each line of the command split at newlines (TOML has none left)
    return c is not None and any(mcp_danger(line) for line in c.split("\n"))


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
    return any(dangerous_cmd(c) or LOCAL_SCRIPT.match(c) for c in _commands(value))


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
