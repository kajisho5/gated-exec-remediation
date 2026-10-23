"""A small lexer for JSON / JSONC and partial replacement that keeps formatting and comments (edit_json).

Finds the character positions of every value and member of the syntax tree and cuts out only the ranges to remove. The original formatting (indentation, comments, newlines) is kept.
The result is parsed again by a different method (JSON with json.loads; JSONC with json.loads after removing comments and trailing commas)
and must equal "the value before the change minus the removed units" (definition T-3).
"""
from __future__ import annotations

import copy
import math
import json
import re

MAX_DEPTH = 64
_NUM = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")
_WS = " \t\r\n"


class JsonEditError(Exception):
    pass


class Node:
    __slots__ = ("kind", "start", "end", "value", "entries")

    def __init__(self, kind, start):
        self.kind, self.start, self.end, self.value, self.entries = kind, start, None, None, []


class Entry:
    """An object member (with key) or an array element. start is the start position of the key (of the value for an element)."""
    __slots__ = ("key", "start", "node", "comma")

    def __init__(self, key, start, node):
        self.key, self.start, self.node, self.comma = key, start, node, None


class _Lexer:
    def __init__(self, text: str, jsonc: bool):
        self.s, self.i, self.n, self.jsonc = text, 0, len(text), jsonc
        if text.startswith("﻿"):
            self.i = 1

    def err(self, msg):
        line = self.s.count("\n", 0, self.i) + 1
        raise JsonEditError(f"{msg} (line {line})")

    def skip(self):
        s = self.s
        while self.i < self.n:
            c = s[self.i]
            if c in _WS:
                self.i += 1
            elif self.jsonc and s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = self.n if j < 0 else j + 1
            elif self.jsonc and s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    self.err("unterminated comment")
                self.i = j + 2
            else:
                return

    def string(self) -> tuple[str, int]:
        s, st = self.s, self.i
        j = st + 1
        while True:
            if j >= self.n:
                self.err("unterminated string")
            c = s[j]
            if c == '"':
                break
            if c == "\\":
                j += 2
                continue
            if c < " ":
                self.err("control character in string")
            j += 1
        raw = s[st:j + 1]
        try:
            val = json.loads(raw)
        except ValueError:
            self.err("invalid escape in string")
        self.i = j + 1
        return val, st

    def value(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            self.err("nesting is too deep")
        self.skip()
        if self.i >= self.n:
            self.err("missing value")
        c = self.s[self.i]
        if c == "{":
            return self.container("object", "}", depth)
        if c == "[":
            return self.container("array", "]", depth)
        node = Node("scalar", self.i)
        if c == '"':
            node.value, _ = self.string()
        else:
            m = _NUM.match(self.s, self.i)
            for lit, v in (("true", True), ("false", False), ("null", None)):
                if self.s.startswith(lit, self.i):
                    node.value = v
                    self.i += len(lit)
                    break
            else:
                if not m or m.end() == self.i:
                    self.err("cannot interpret value")
                txt = m.group(0)
                node.value = json.loads(txt)
                if isinstance(node.value, float) and not math.isfinite(node.value):
                    self.err("non-finite number")
                self.i = m.end()
        node.end = self.i
        return node

    def container(self, kind, close, depth) -> Node:
        node = Node(kind, self.i)
        self.i += 1
        keys = set()
        while True:
            self.skip()
            if self.i >= self.n:
                self.err("unterminated " + kind)
            if self.s[self.i] == close:
                if node.entries and node.entries[-1].comma is not None and not self.jsonc:
                    self.err("trailing comma (not allowed in JSON)")
                self.i += 1
                break
            if node.entries and node.entries[-1].comma is None:
                self.err("missing comma")
            if kind == "object":
                if self.s[self.i] != '"':
                    self.err("keys must be strings")
                key, kst = self.string()
                if key in keys:
                    self.err("duplicate key")
                keys.add(key)
                self.skip()
                if self.i >= self.n or self.s[self.i] != ":":
                    self.err("missing :")
                self.i += 1
                v = self.value(depth + 1)
                e = Entry(key, kst, v)
            else:
                v = self.value(depth + 1)
                e = Entry(None, v.start, v)
            node.entries.append(e)
            self.skip()
            if self.i < self.n and self.s[self.i] == ",":
                e.comma = self.i
                self.i += 1
        node.end = self.i
        return node


def parse(text: str, jsonc: bool) -> Node:
    lx = _Lexer(text, jsonc)
    root = lx.value(1)
    lx.skip()
    if lx.i != lx.n:
        lx.err("extra content after the value")
    return root


def to_python(node: Node):
    if node.kind == "scalar":
        return node.value
    if node.kind == "array":
        return [to_python(e.node) for e in node.entries]
    return {e.key: to_python(e.node) for e in node.entries}


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _reject_const(name):
    raise ValueError(f"non-standard constant {name}")


def strip_jsonc(text: str) -> str:
    """Strict JSON text with comments and trailing commas removed (for the T-3 re-parse; built by a path separate from the lexer)."""
    out = []
    i, n = 0, len(text)
    if text.startswith("﻿"):
        i = 1
    pending_comma = None  # The previous comma (dropped if the next non-whitespace is } / ])
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if pending_comma is not None:
                out.append(pending_comma)
                pending_comma = None
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ValueError("unterminated comment")
            i = j + 2
        elif c == ",":
            if pending_comma is not None:
                out.append(pending_comma)
            pending_comma = ","
            i += 1
        elif c in _WS:
            out.append(c)
            i += 1
        else:
            if pending_comma is not None:
                if c not in "]}":
                    out.append(pending_comma)
                pending_comma = None
            out.append(c)
            i += 1
    if pending_comma is not None:
        out.append(pending_comma)
    return "".join(out)


def reparse(text: str, fmt: str):
    """Independent parse for T-3."""
    src = strip_jsonc(text) if fmt == "jsonc" else (text[1:] if text.startswith("﻿") else text)
    return json.loads(src, object_pairs_hook=_no_dup, parse_constant=_reject_const)


def detect_format(text: str) -> str:
    try:
        parse(text, False)
        return "json"
    except JsonEditError:
        parse(text, True)  # JsonEditError if it cannot be read even as JSONC
        return "jsonc"


# --- JSON pointer ---------------------------------------------------------------------------
def split_pointer(ptr: str) -> list[str]:
    if not ptr.startswith("/"):
        raise JsonEditError("pointer must start with /")
    return [p.replace("~1", "/").replace("~0", "~") for p in ptr[1:].split("/")]


def escape_token(t: str) -> str:
    return t.replace("~", "~0").replace("/", "~1")


def find(root: Node, ptr: str) -> tuple[Node | None, int, Node]:
    """(parent container, position in the parent, value node). A pointer to the root is not allowed."""
    toks = split_pointer(ptr)
    parent, idx, cur = None, -1, root
    for t in toks:
        if cur.kind == "object":
            for i, e in enumerate(cur.entries):
                if e.key == t:
                    parent, idx, cur = cur, i, e.node
                    break
            else:
                raise JsonEditError(f"no value at pointer {ptr}")
        elif cur.kind == "array":
            if not re.fullmatch(r"0|[1-9][0-9]*", t) or int(t) >= len(cur.entries):
                raise JsonEditError(f"no value at pointer {ptr}")
            parent, idx, cur = cur, int(t), cur.entries[int(t)].node
        else:
            raise JsonEditError(f"no value at pointer {ptr}")
    return parent, idx, cur


def get_value(value, ptr: str):
    cur = value
    for t in split_pointer(ptr):
        cur = cur[int(t)] if isinstance(cur, list) else cur[t]
    return cur


def remove_value(value, ptr: str):
    toks = split_pointer(ptr)
    cur = value
    for t in toks[:-1]:
        cur = cur[int(t)] if isinstance(cur, list) else cur[t]
    if isinstance(cur, list):
        del cur[int(toks[-1])]
    else:
        del cur[toks[-1]]


def set_value(value, ptr: str, new):
    toks = split_pointer(ptr)
    cur = value
    for t in toks[:-1]:
        cur = cur[int(t)] if isinstance(cur, list) else cur[t]
    if isinstance(cur, list):
        cur[int(toks[-1])] = new
    else:
        cur[toks[-1]] = new


# --- Replacement -------------------------------------------------------------------------------
def _line_start(s: str, i: int) -> int:
    return s.rfind("\n", 0, i) + 1


def _rest_is_blank(s: str, i: int, jsonc: bool) -> int | None:
    """If only whitespace (and JSONC comments) follows i up to the end of the line, the position after the newline; otherwise None."""
    n = len(s)
    while i < n:
        c = s[i]
        if c in " \t\r":
            i += 1
        elif c == "\n":
            return i + 1
        elif jsonc and s.startswith("//", i):
            j = s.find("\n", i)
            return n if j < 0 else j + 1
        elif jsonc and s.startswith("/*", i):
            j = s.find("*/", i + 2)
            if j < 0 or "\n" in s[i:j]:
                return None
            i = j + 2
        else:
            return None
    return n


def removal_span(s: str, parent: Node, idx: int, jsonc: bool) -> tuple[int, int]:
    ents = parent.entries
    e = ents[idx]
    n = len(ents)
    if idx < n - 1:
        after = _rest_is_blank(s, e.comma + 1, jsonc)
        ls = _line_start(s, e.start)
        if after is not None and s[ls:e.start].strip() == "":
            return ls, after
        return e.start, ents[idx + 1].start
    if n > 1:
        prev = ents[idx - 1]
        end = e.node.end if e.comma is None else e.comma + 1
        return prev.comma, end
    end = e.node.end if e.comma is None else e.comma + 1
    ls = _line_start(s, e.start)
    after = _rest_is_blank(s, end, jsonc)
    if after is not None and s[ls:e.start].strip() == "":
        return ls, after
    return e.start, end


def apply_ops(text: str, fmt: str, ops: list[dict]) -> tuple[str, object]:
    """Returns the text with ops applied and the expected value (the value before the change with removals and replacements).
    ops are {"op": "remove"|"replace_const", "pointer", "const"?}. The syntax tree is rebuilt before each op.
    Applied from the last position in the original text backwards (indexes of earlier array elements do not shift)."""
    jsonc = fmt == "jsonc"
    root = parse(text, jsonc)
    expected = copy.deepcopy(to_python(root))
    ptrs = [o["pointer"] for o in ops]
    for a in ptrs:
        for b in ptrs:
            if a != b and (b + "/").startswith(a + "/"):
                raise JsonEditError(f"ops ranges overlap ({a} and {b})")
    if len(set(ptrs)) != len(ptrs):
        raise JsonEditError("ops contains the same pointer twice")
    order = sorted(ops, key=lambda o: find(root, o["pointer"])[2].start, reverse=True)
    for o in order:
        root = parse(text, jsonc)
        parent, idx, node = find(root, o["pointer"])
        if parent is None:
            raise JsonEditError("the root cannot be removed")
        if o["op"] == "remove":
            a, b = removal_span(text, parent, idx, jsonc)
            text = text[:a] + text[b:]
            remove_value(expected, o["pointer"])
        elif o["op"] == "replace_const":
            text = text[:node.start] + json.dumps(o["const"], ensure_ascii=False) + text[node.end:]
            set_value(expected, o["pointer"], o["const"])
        else:
            raise JsonEditError(f"unknown op {o['op']}")
    return text, expected
