"""remove_line operation - reversible (shell rc files, git config, php.ini, ld.so.preload, /etc/cron.d).

params: {"lines": [{"n": 2, "sha256": "<SHA-256 of that line (without the newline)>", "pattern_id": "sh.ld_preload"}],
         "file_sha256", "expected_after_sha256"}
- The hash of line n must match and the whole line must match the regular expression of pattern_id (hazards.LINE_H) (T-1)
- A line continued with a trailing \\ or following a line ending in \\ is rejected. In shell rc files, lines inside a here-document, a function definition or an if / case /
  for / while block are rejected (rejected whenever GER's simple lexical check cannot tell)
- CRLF and BOM are kept as they are. Checks that no byte other than the removed lines changes (T-3)
Line contents are never written to the plan or the logs; they are handled by hash only.
"""
from __future__ import annotations

import re

from .. import fsutil, hazards
from ..core import sha256
from . import edit_common
from .base import ActionError, PreviewResult, check_regular

TYPE = "remove_line"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 0
MAX_LINES = 64
BOM = b"\xef\xbb\xbf"


def validate_params(params: dict) -> None:
    if not isinstance(params, dict) or set(params) != {"lines", "file_sha256", "expected_after_sha256"}:
        raise ActionError('params must be {"lines", "file_sha256", "expected_after_sha256"} (built by ger preview)')
    edit_common.check_sha(params["file_sha256"], "file_sha256")
    edit_common.check_sha(params["expected_after_sha256"], "expected_after_sha256")
    lines = params["lines"]
    if not isinstance(lines, list) or not 1 <= len(lines) <= MAX_LINES:
        raise ActionError(f"params.lines must have 1-{MAX_LINES} entries")
    for ln in lines:
        if not isinstance(ln, dict) or set(ln) != {"n", "sha256", "pattern_id"}:
            raise ActionError('lines[] must be {"n", "sha256", "pattern_id"}')
        if not isinstance(ln["n"], int) or isinstance(ln["n"], bool) or ln["n"] < 1:
            raise ActionError("lines[].n must be an integer of 1 or more")
        if ln["pattern_id"] not in hazards.LINE_H:
            raise ActionError(f"lines[].pattern_id must be an id from GER's table ({', '.join(hazards.LINE_H)})")
        edit_common.check_sha(ln["sha256"], "lines[].sha256")


def split(data: bytes) -> list[tuple[bytes, bytes]]:
    """[(content (without newline and BOM), whole line (with newline))]. Only \\n separates lines (the \\r of \\r\\n is removed from the content)."""
    out = []
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\n", i)
        full = data[i:] if j < 0 else data[i:j + 1]
        content = full[:-1] if full.endswith(b"\n") else full
        if content.endswith(b"\r"):
            content = content[:-1]
        if i == 0 and content.startswith(BOM):
            content = content[len(BOM):]
        out.append((content, full))
        i = n if j < 0 else j + 1
    return out


_HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_OPEN = {"if", "case", "for", "while", "until", "select"}
_CLOSE = {"fi", "esac", "done"}


def _strip_shell(code: str) -> str:
    """Removes quoted text, parameter expansions, command substitutions and comments (an approximation for the lexical check)."""
    out, q, i = [], None, 0
    while i < len(code):
        c = code[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "'\"":
            q = c
            out.append(" ")
        elif c == "\\":
            i += 2
            out.append(" ")
            continue
        elif c == "#" and (i == 0 or code[i - 1] in " \t;"):
            break
        else:
            out.append(c)
        i += 1
    s = "".join(out)
    s = re.sub(r"\$\{[^}]*\}", " ", s)
    s = re.sub(r"\$\([^)]*\)", " ", s)
    return s


def shell_safe_lines(contents: list[str]) -> list[bool]:
    """Whether each line is "a simple top-level line" (not inside a here-document, a block or a continued line). False when unsure."""
    safe = []
    heredoc = None
    depth = 0
    cont = False
    broken = False
    for s in contents:
        if heredoc is not None:
            word, dash = heredoc
            if (s.lstrip("\t") if dash else s) == word:
                heredoc = None
            safe.append(False)
            continue
        code = _strip_shell(s)
        changed = False
        for seg in re.split(r"[;&|()]", code):
            for w in seg.split():
                if w in ("{",):
                    depth += 1
                    changed = True
                elif w in ("}",):
                    depth -= 1
                    changed = True
            words = seg.split()
            if words:
                w0 = words[0]
                if w0 in ("then", "do", "else", "elif", "!") and len(words) > 1:
                    w0 = words[1]
                if w0 in _OPEN:
                    depth += 1
                    changed = True
                elif w0 in _CLOSE:
                    depth -= 1
                    changed = True
        if depth < 0:
            broken = True
        m = _HEREDOC.search(code) if "<<<" not in code else None
        ends_cont = s.rstrip().endswith("\\")
        safe.append(not broken and depth == 0 and not changed and not cont and not ends_cont and m is None)
        if m:
            heredoc = (m.group(3), m.group(1) == "-")
        cont = ends_cont
    return safe


def plain_safe_lines(contents: list[str]) -> list[bool]:
    safe, cont = [], False
    for s in contents:
        ends = s.rstrip().endswith("\\")
        safe.append(not cont and not ends)
        cont = ends
    return safe


def _contexts(path: str, contents: list[str], pattern_id: str) -> list[bool]:
    kind = hazards.LINE_H[pattern_id][2]
    return shell_safe_lines(contents) if kind == "shell" else plain_safe_lines(contents)


def compute(path: str, data: bytes, lines: list) -> bytes:
    parts = split(data)
    contents = [c.decode("utf-8", "surrogateescape") for c, _ in parts]
    nums = [ln["n"] for ln in lines]
    if len(set(nums)) != len(nums):
        raise ActionError("the same line is given twice")
    for ln in lines:
        n, pid = ln["n"], ln["pattern_id"]
        if n > len(parts):
            raise ActionError(f"line {n} not found")
        fpred, rx, _kind = hazards.LINE_H[pid]
        if not fpred(path):
            raise ActionError(f"pattern {pid} cannot be used for this kind of file (T-1)", gate="G-10")
        if sha256(parts[n - 1][0]) != ln["sha256"]:
            raise ActionError(f"the content of line {n} changed since preview (does not match sha256)")
        if not rx.fullmatch(contents[n - 1]):
            raise ActionError(f"line {n} does not match hazard pattern {pid}; it cannot be removed (T-1)", gate="G-10")
        if not _contexts(path, contents, pid)[n - 1]:
            raise ActionError(f"line {n} cannot be removed: it is inside a continued line, a here-document or a block (or this cannot be determined)")
    drop = set(nums)
    out = bytearray()
    for i, (_c, full) in enumerate(parts, 1):
        if i in drop:
            if i == 1 and full.startswith(BOM):
                out += BOM
            continue
        out += full
    new = bytes(out)
    # T-3: no byte other than the removed lines changes (rebuilt by a separate path and compared)
    chunks = re.split(b"(?<=\n)", data)
    chunks = [c for c in chunks if c]
    alt = b"".join(c for i, c in enumerate(chunks, 1) if i not in drop)
    if 1 in drop and data.startswith(BOM):
        alt = BOM + alt
    if alt != new:
        raise ActionError("content other than the removed lines would change (T-3)", gate="G-10")
    return new


def prepare(ctx, items):
    return edit_common.prepare_edit(ctx, items, TYPE, compute)


def preview(ctx, items) -> PreviewResult:
    target = items[0].action["target"]
    res = ctx.pool.add(fsutil.resolve(target))
    check_regular(res.st)
    data = fsutil.read_file(res.parent_fd, res.name, res.st, limit=fsutil.EDIT_MAX_BYTES)
    parts = split(data)
    contents = [c.decode("utf-8", "surrogateescape") for c, _ in parts]
    pids = hazards.line_patterns_for(target)
    if not pids:
        raise ActionError("this kind of file has no remove_line hazard pattern")
    lines = []
    explicit = [ln for it in items for ln in it.action["params"].get("lines", [])]
    for i, c in enumerate(contents, 1):
        if explicit and i not in {ln.get("n") for ln in explicit}:
            continue
        for pid in pids:
            if hazards.LINE_H[pid][1].fullmatch(c) and _contexts(target, contents, pid)[i - 1]:
                lines.append({"n": i, "sha256": sha256(parts[i - 1][0]), "pattern_id": pid})
                break
    if not lines:
        raise ActionError("no removable line found (a top-level line matching a hazard pattern)")
    new = compute(target, data, lines)
    params = {"lines": lines, "file_sha256": sha256(data), "expected_after_sha256": sha256(new)}
    validate_params(params)
    return PreviewResult(params, "remove lines " + ", ".join(f"{ln['n']}({ln['pattern_id']})" for ln in lines),
                         edit_common.unified_diff(target, data, new))
