"""定義 T（絞るだけ）の閉じた表。GER のコードに埋め込み、版を持つ（HAZARD_VERSION）。

- H（取り除いてよい単位）: ファイルの種類ごとの JSON pointer / TOML のテーブル / 行のパターン
- K（足してよい定数）: 置き換え先の値
計画（plan）の値は信用しない。取り除く単位がここに一致するかどうかは、GER が現在の内容に対して自分で評価する。
表に無いもの（例: .claude/settings.json の permissions.deny、.npmrc の ignore-scripts=true、disable_functions）は
取り除けない（取り除くことが緩めることになるため）。
"""
from __future__ import annotations

import posixpath
import re

HAZARD_VERSION = "ger-hazards-2"

# --- 危険なコマンドの判定 ------------------------------------------------------------------------
# エージェントフック（.claude/settings.json の hooks）用。
DANGEROUS_CMD = re.compile(
    r'(^|[\s"/])(curl|wget)([\s"]|$)|bash -c|sh -c|powershell(\.exe)? .*-(e|enc|encodedcommand)\s|node -e|python[0-9.]* -c|base64')
# MCP サーバーの command + args 用。ZES §17 の MCP_DANGER_RE（zes-scan.sh。大文字小文字を区別しない）を写したもの。
#   ZES が HIGH とするのに GER が一致しないと、取り除く対象が見つからず自動の修復ができない（両者を揃えること）
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
# フックが作業ツリー内のスクリプトを実行する（node .claude/setup.mjs など）
LOCAL_SCRIPT = re.compile(r'^\s*(node|deno|bun|python[0-9.]*|bash|sh|zsh|ruby|perl)\s+\.{0,2}/?[\w.@-]+(/[\w.@-]+)*\s*$')


def mcp_cmdline(server) -> str | None:
    """MCP サーバーの定義（dict）から ZES と同じ形の command + args を作る。command が無ければ None。"""
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
    # ZES と同じく、command の改行で分けた行ごとに照合する
    return c is not None and any(MCP_DANGER.search(line) for line in c.split("\n"))


def _commands(obj):
    """値の中の command 文字列をすべて集める（フックの入れ子 hooks[].hooks[].command に対応）。"""
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


# --- JSON の H（edit_json / disable_mcp_server） ---------------------------------------------------
MCP_JSON_BASENAMES = {".mcp.json", "mcp.json", "mcp_config.json", ".claude.json", "claude_desktop_config.json"}
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
                 "preuninstall", "uninstall", "postuninstall", "prepublish")


def _is_claude_settings(path: str) -> bool:
    return posixpath.basename(path) in ("settings.json", "settings.local.json") and \
        posixpath.basename(posixpath.dirname(path)) == ".claude"


def _is_vscode_tasks(path: str) -> bool:
    return posixpath.basename(path) == "tasks.json" and posixpath.basename(posixpath.dirname(path)) == ".vscode"


# id → (ファイルの判定, pointer の正規表現, 値の判定, 自動選択の判定, 操作)
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
# K: replace_const で書いてよい値（H の id ごと）
JSON_K = {"vscode.task_run_on": ("default",)}
# disable_mcp_server（preset）が使ってよい H
MCP_PRESET = ("mcp.server",)


def json_hazard(path: str, pointer: str, value, op: str):
    """(path, pointer, 現在の値, op) が一致する H の id。一致しなければ None。"""
    for hid, (fpred, ptr, vpred, _auto, hop) in JSON_H.items():
        if hop == op and fpred(path) and ptr.match(pointer) and vpred(value):
            return hid
    return None


# --- TOML の H（edit_toml / disable_mcp_server、Phase 1 の範囲） ------------------------------------
def is_codex_config(path: str) -> bool:
    return posixpath.basename(path) == "config.toml" and posixpath.basename(posixpath.dirname(path)) == ".codex"


def toml_hazard(path: str, key_path) -> str | None:
    if is_codex_config(path) and isinstance(key_path, (list, tuple)) and len(key_path) == 2 and key_path[0] == "mcp_servers":
        return "mcp.server.toml"
    return None


# --- 行の H（remove_line） ------------------------------------------------------------------------
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


# id → (ファイルの判定, 行の正規表現（行全体に一致すること）, 字句判定の種類)
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


# --- quarantine: 見かけだけの修復の禁止（Q-6） --------------------------------------------------------
def metadata_only(path: str, kind: str) -> str | None:
    """self の quarantine で、ZES が検知の根拠にしているメタデータだけを取り除き実体を残すものなら理由を返す。"""
    b = posixpath.basename(path)
    parts = path.split("/")
    if b.endswith((".dist-info", ".egg-info")):
        return "dist-info / egg-info のメタデータだけを隔離するとコードが残ります（relation pypi_record を使うこと）"
    if b == "package.json" and "node_modules" in parts[:-1]:
        return "node_modules のパッケージの package.json だけを隔離するとコードが残ります（relation npm_pkg_dir を使うこと）"
    if b == "manifest.json" and "Extensions" in parts[:-1]:
        return "拡張機能の manifest.json だけを隔離するとコードが残ります（relation ext_dir を使うこと）"
    if b == "skill.contract.json":
        return "skill.contract.json だけを隔離するとスキルのコードが残ります（relation skill_dir を使うこと）"
    return None


# --- 保護対象と root が必要な対象（§4.4） ----------------------------------------------------------
SYSTEM_TOP = ("/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/var", "/opt", "/boot",
              "/dev", "/proc", "/sys", "/run", "/srv", "/root", "/home", "/Users", "/System", "/Library",
              "/Applications", "/private", "/tmp", "/nix", "/snap")
ROOT_PREFIXES = ("/etc/", "/usr/", "/var/", "/opt/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/",
                 "/boot/", "/System/", "/Library/", "/private/etc/", "/private/var/")
ETC_ALLOW = re.compile(r"^/etc/(ld\.so\.preload|hosts|cron\.d/[^/]+)$")


USER_TMP_PREFIXES = ("/var/folders/", "/private/var/folders/", "/var/tmp/")


def root_required_lexical(path: str) -> bool:
    """字句上 root が必要な対象（システムのディレクトリの下。macOS の利用者ごとの一時領域は除く）。
    所有者による判定（所有者が実行ユーザーでない）は GER が実行時に足す。ZET（zet/remedy.py）と同じ規則。"""
    return path.startswith(ROOT_PREFIXES) and not path.startswith(USER_TMP_PREFIXES)
