"""TOML の Phase 1 の範囲の編集（edit_toml）: 標準のテーブルヘッダで定義されたテーブルを取り除く。

対象のテーブル（例: [mcp_servers.evil]）が、標準のテーブルヘッダ（引用符付き・空白入りは正規化して比べる）と、
そのサブテーブル [mcp_servers.evil.*] だけで定義されている場合に限り、ヘッダから次のヘッダの直前までの行を取り除く。
ドット区切りのキー（mcp_servers.evil.command = …）やインラインテーブルで定義されている場合は、取り除く範囲を
一意に決められないため拒否する（チェックリストにする）。変更後は tomllib でパースし直して T-3 を確かめる。
"""
from __future__ import annotations

import copy
import datetime as dt
import re
import tomllib

_BARE = re.compile(r"[A-Za-z0-9_-]+")


class TomlEditError(Exception):
    pass


class _Scanner:
    def __init__(self, s: str):
        self.s, self.i, self.n = s, 0, len(s)

    def err(self, msg):
        line = self.s.count("\n", 0, self.i) + 1
        raise TomlEditError(f"TOML を字句解析できません: {msg}（{line} 行目）")

    def ws(self):
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1

    def ws_nl_comments(self):
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif c == "#":
                self.to_eol()
            else:
                return

    def to_eol(self):
        j = self.s.find("\n", self.i)
        self.i = self.n if j < 0 else j

    def eol(self):
        self.ws()
        if self.i < self.n and self.s[self.i] == "#":
            self.to_eol()
        if self.i < self.n and self.s[self.i] == "\r":
            self.i += 1
        if self.i < self.n and self.s[self.i] != "\n":
            self.err("行末に余分な内容")

    def basic(self) -> str:
        st = self.i
        self.i += 1
        while True:
            if self.i >= self.n or self.s[self.i] == "\n":
                self.err("閉じていない文字列")
            c = self.s[self.i]
            if c == "\\":
                self.i += 2
                continue
            self.i += 1
            if c == '"':
                break
        try:
            return tomllib.loads("k = " + self.s[st:self.i])["k"]
        except tomllib.TOMLDecodeError:
            self.err("文字列のエスケープが不正")

    def literal(self) -> str:
        j = self.s.find("'", self.i + 1)
        if j < 0 or "\n" in self.s[self.i:j]:
            self.err("閉じていない文字列")
        v = self.s[self.i + 1:j]
        self.i = j + 1
        return v

    def key(self) -> list[str]:
        parts = []
        while True:
            self.ws()
            if self.i >= self.n:
                self.err("キーがありません")
            c = self.s[self.i]
            if c == '"':
                parts.append(self.basic())
            elif c == "'":
                parts.append(self.literal())
            else:
                m = _BARE.match(self.s, self.i)
                if not m:
                    self.err("キーを解釈できません")
                parts.append(m.group(0))
                self.i = m.end()
            self.ws()
            if self.i < self.n and self.s[self.i] == ".":
                self.i += 1
                continue
            return parts

    def value(self, assigns: list, path: tuple, depth: int = 0):
        if depth > 64:
            self.err("入れ子が深すぎます")
        s = self.s
        if s.startswith('"""', self.i):
            j = self.i + 3
            while True:
                if j >= self.n:
                    self.err("閉じていない複数行文字列")
                if s[j] == "\\":
                    j += 2
                    continue
                if s.startswith('"""', j):
                    j += 3
                    while j < self.n and s[j] == '"':
                        j += 1
                    break
                j += 1
            self.i = j
        elif s.startswith("'''", self.i):
            j = s.find("'''", self.i + 3)
            if j < 0:
                self.err("閉じていない複数行文字列")
            j += 3
            while j < self.n and s[j] == "'":
                j += 1
            self.i = j
        elif s[self.i] == '"':
            self.basic()
        elif s[self.i] == "'":
            self.literal()
        elif s[self.i] == "[":
            self.i += 1
            while True:
                self.ws_nl_comments()
                if self.i >= self.n:
                    self.err("閉じていない配列")
                if s[self.i] == "]":
                    self.i += 1
                    return
                self.value(assigns, path, depth + 1)
                self.ws_nl_comments()
                if self.i < self.n and s[self.i] == ",":
                    self.i += 1
                    continue
                self.ws_nl_comments()
                if self.i < self.n and s[self.i] == "]":
                    self.i += 1
                    return
                self.err("配列の区切りが不正")
        elif s[self.i] == "{":
            self.i += 1
            self.ws()
            if self.i < self.n and s[self.i] == "}":
                self.i += 1
                return
            while True:
                k = self.key()
                self.ws()
                if self.i >= self.n or s[self.i] != "=":
                    self.err("インラインテーブルに = がありません")
                self.i += 1
                self.ws()
                assigns.append(path + tuple(k))
                self.value(assigns, path + tuple(k), depth + 1)
                self.ws()
                if self.i < self.n and s[self.i] == ",":
                    self.i += 1
                    continue
                if self.i < self.n and s[self.i] == "}":
                    self.i += 1
                    return
                self.err("インラインテーブルの区切りが不正")
        else:
            st = self.i
            while self.i < self.n and s[self.i] not in "\n#,]}":
                self.i += 1
            if not s[st:self.i].strip():
                self.err("値がありません")


def scan(text: str):
    """(headers, assigns)。headers: [(行頭の位置, キーのタプル, 配列テーブルか)]。
    assigns: [(キーの絶対パス, 属するヘッダの添字（ルートは -1）)]。"""
    sc = _Scanner(text)
    headers: list = []
    assigns: list = []
    table: tuple = ()
    while True:
        sc.ws_nl_comments()
        if sc.i >= sc.n:
            break
        if text[sc.i] == "[":
            ls = text.rfind("\n", 0, sc.i) + 1
            arr = text.startswith("[[", sc.i)
            sc.i += 2 if arr else 1
            k = tuple(sc.key())
            sc.ws()
            close = "]]" if arr else "]"
            if not text.startswith(close, sc.i):
                sc.err("テーブルヘッダが閉じていません")
            sc.i += len(close)
            sc.eol()
            headers.append((ls, k, arr))
            table = k
            continue
        k = tuple(sc.key())
        sc.ws()
        if sc.i >= sc.n or text[sc.i] != "=":
            sc.err("= がありません")
        sc.i += 1
        sc.ws()
        full = table + k
        local: list = []
        sc.value(local, full)
        hi = len(headers) - 1
        assigns.append((full, hi))
        assigns.extend((p, hi) for p in local)
        sc.eol()
    return headers, assigns


def _plain(v):
    """tomllib の値を正規化 JSON にできる形へ（日時は ISO 8601 の文字列）。"""
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, (dt.datetime, dt.date, dt.time)):
        return v.isoformat()
    return v


def loads(text: str):
    try:
        return tomllib.loads(text[1:] if text.startswith("﻿") else text)
    except tomllib.TOMLDecodeError as e:
        raise TomlEditError(f"TOML としてパースできません: {e}") from None


def plain(v):
    return _plain(v)


def remove_tables(text: str, key_paths: list[tuple]) -> tuple[str, object]:
    """key_paths の各テーブルを取り除いたテキストと、期待される値を返す。範囲を一意に決められなければ TomlEditError。"""
    before = loads(text)
    headers, assigns = scan(text)
    remove_idx: set[int] = set()
    for kp in key_paths:
        kp = tuple(kp)
        mine = [i for i, (_ls, k, _a) in enumerate(headers) if k[:len(kp)] == kp]
        if not mine or headers[mine[0]][1] != kp:
            raise TomlEditError(f"テーブル {'.'.join(kp)} は標準のテーブルヘッダ [{'.'.join(kp)}] で定義されていません"
                                "（ドット区切りのキーやインラインテーブルの定義は取り除けません）")
        for p, hi in assigns:
            if (p[:len(kp)] == kp or kp[:len(p)] == p) and hi not in mine:
                raise TomlEditError(f"テーブル {'.'.join(kp)} の一部がヘッダの外（ドット区切りのキー・インラインテーブル）で定義されています")
        remove_idx.update(mine)
    spans = []
    for i in sorted(remove_idx):
        start = headers[i][0]
        end = headers[i + 1][0] if i + 1 < len(headers) else len(text)
        spans.append((start, end))
    out = text
    for a, b in sorted(spans, reverse=True):
        out = out[:a] + out[b:]
    expected = copy.deepcopy(before)
    for kp in key_paths:
        cur = expected
        for t in kp[:-1]:
            cur = cur[t]
        del cur[kp[-1]]
    after = loads(out)
    for kp in key_paths:  # 暗黙に作られていた親テーブルが空になって消えた場合
        if len(kp) >= 2:
            par = expected
            for t in kp[:-2]:
                par = par[t]
            if par.get(kp[-2]) == {} and kp[-2] not in _walk(after, kp[:-2]):
                del par[kp[-2]]
    return out, expected


def _walk(v, path):
    for t in path:
        v = v.get(t, {}) if isinstance(v, dict) else {}
    return v if isinstance(v, dict) else {}
