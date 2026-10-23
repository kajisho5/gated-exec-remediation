"""Validator for a subset of JSON Schema (2020-12). Standard library only.

Only the keywords that ZET / GER use are implemented:
  type, const, enum, pattern, minLength, maxLength, minimum, maximum, minItems, maxItems, uniqueItems,
  required, properties, additionalProperties(false/schema), items, $ref(#/$defs/...),
  if/then/else, not, anyOf, oneOf, allOf
An unsupported keyword in a schema raises an exception (it is never silently ignored).
The tests confirm that the results agree with the reference implementation jsonschema.
"""
from __future__ import annotations

import re
from typing import Any

_SUPPORTED = {
    "$schema", "$id", "$defs", "$comment", "title", "description", "default", "examples",
    "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems",
    "uniqueItems",
    "required", "properties", "additionalProperties", "items", "$ref", "if", "then", "else", "not",
    "anyOf", "oneOf", "allOf",
}
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaError(Exception):
    """The schema itself is invalid or contains an unsupported keyword."""


# Characters a terminal may interpret: C0 controls, DEL, C1 controls (Cc), line and paragraph separators, bidirectional text controls
_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069]")


def safe_text(s: Any) -> str:
    """Make a string from the input printable on a terminal (control characters become \\xNN / \\uNNNN).

    When an error message contains input values such as keys or paths, ESC (OSC / CSI) or C1 controls must not
    change the terminal title, clear the screen and so on. The result has no control characters, so applying it
    again changes nothing (applying it in both the validator and the CLI does not escape twice). Backslashes are kept.
    """
    def esc(m: re.Match) -> str:
        c = ord(m.group())
        return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"
    return _UNSAFE.sub(esc, str(s))


def _ptr(path: list) -> str:
    return "/" + "/".join(safe_text(p) for p in path) if path else "/"


_patterns: dict[str, re.Pattern] = {}


def _compile(pattern: str) -> re.Pattern:
    """Compile pattern with ECMA 262 semantics.

    Python's `$` also matches just before a trailing newline ("alice\\n" passes ^...$), so an unescaped `$`
    outside a character class is replaced with `\\Z`.
    """
    c = _patterns.get(pattern)
    if c is None:
        out, i, in_class = [], 0, False
        while i < len(pattern):
            ch = pattern[i]
            if ch == "\\":
                out.append(pattern[i:i + 2])
                i += 2
                continue
            if in_class:
                in_class = ch != "]"
            elif ch == "[":
                in_class = True
                if pattern[i + 1:i + 2] == "]":  # a leading ] is a literal (as Python reads it)
                    out.append("[]")
                    i += 2
                    continue
            elif ch == "$":
                ch = r"\Z"
            out.append(ch)
            i += 1
        c = _patterns[pattern] = re.compile("".join(out))
    return c


def _eq(a: Any, b: Any) -> bool:
    # JSON equality (bool and numbers are different)
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


class Validator:
    def __init__(self, schema: dict):
        self.root = schema
        self._check_schema(schema)

    def _check_schema(self, s: Any) -> None:
        if isinstance(s, bool):
            return
        if not isinstance(s, dict):
            raise SchemaError("schema must be an object")
        unknown = set(s) - _SUPPORTED
        if unknown:
            raise SchemaError(f"unsupported keywords: {sorted(unknown)}")
        for k in ("properties", "$defs"):
            for sub in s.get(k, {}).values():
                self._check_schema(sub)
        for k in ("items", "if", "then", "else", "not"):
            if k in s:
                self._check_schema(s[k])
        if isinstance(s.get("additionalProperties"), dict):
            self._check_schema(s["additionalProperties"])
        for k in ("anyOf", "oneOf", "allOf"):
            for sub in s.get(k, []):
                self._check_schema(sub)

    def _resolve(self, ref: str) -> dict:
        if not ref.startswith("#/$defs/"):
            raise SchemaError(f"unsupported $ref: {ref}")
        name = ref[len("#/$defs/"):]
        try:
            return self.root["$defs"][name]
        except KeyError as e:
            raise SchemaError(f"unknown $ref: {ref}") from e

    def errors(self, instance: Any) -> list[str]:
        out: list[str] = []
        self._v(self.root, instance, [], out)
        return out

    def is_valid(self, instance: Any) -> bool:
        return not self.errors(instance)

    def _v(self, s: Any, x: Any, path: list, out: list[str]) -> None:
        if s is True:
            return
        if s is False:
            out.append(f"{_ptr(path)}: not allowed")
            return
        if "$ref" in s:
            self._v(self._resolve(s["$ref"]), x, path, out)
        if "type" in s:
            types = s["type"] if isinstance(s["type"], list) else [s["type"]]
            if not any(_TYPES[t](x) for t in types):
                out.append(f"{_ptr(path)}: expected type {types}")
                return
        if "const" in s and not _eq(x, s["const"]):
            out.append(f"{_ptr(path)}: must be {s['const']!r}")
        if "enum" in s and not any(_eq(x, e) for e in s["enum"]):
            out.append(f"{_ptr(path)}: must be one of {s['enum']!r}")
        if isinstance(x, str):
            if "pattern" in s and not _compile(s["pattern"]).search(x):
                out.append(f"{_ptr(path)}: does not match {s['pattern']}")
            if "minLength" in s and len(x) < s["minLength"]:
                out.append(f"{_ptr(path)}: shorter than {s['minLength']}")
            if "maxLength" in s and len(x) > s["maxLength"]:
                out.append(f"{_ptr(path)}: longer than {s['maxLength']}")
        if _TYPES["number"](x):
            if "minimum" in s and x < s["minimum"]:
                out.append(f"{_ptr(path)}: below minimum {s['minimum']}")
            if "maximum" in s and x > s["maximum"]:
                out.append(f"{_ptr(path)}: above maximum {s['maximum']}")
        if isinstance(x, list):
            if "minItems" in s and len(x) < s["minItems"]:
                out.append(f"{_ptr(path)}: fewer than {s['minItems']} items")
            if "maxItems" in s and len(x) > s["maxItems"]:
                out.append(f"{_ptr(path)}: more than {s['maxItems']} items")
            if s.get("uniqueItems"):
                seen: list = []
                for item in x:
                    if any(_eq(item, y) for y in seen):
                        out.append(f"{_ptr(path)}: items are not unique")
                        break
                    seen.append(item)
            if "items" in s:
                for i, item in enumerate(x):
                    self._v(s["items"], item, path + [i], out)
        if isinstance(x, dict):
            for k in s.get("required", []):
                if k not in x:
                    out.append(f"{_ptr(path)}: missing required '{k}'")
            props = s.get("properties", {})
            for k, v in x.items():
                if k in props:
                    self._v(props[k], v, path + [k], out)
                elif "additionalProperties" in s:
                    ap = s["additionalProperties"]
                    if ap is False:
                        out.append(f"{_ptr(path)}: unknown field '{safe_text(k)}'")
                    elif isinstance(ap, dict):
                        self._v(ap, v, path + [k], out)
        if "if" in s:
            if not self._sub_errors(s["if"], x, path):
                if "then" in s:
                    self._v(s["then"], x, path, out)
            elif "else" in s:
                self._v(s["else"], x, path, out)
        if "not" in s and not self._sub_errors(s["not"], x, path):
            out.append(f"{_ptr(path)}: must not match 'not' schema")
        if "allOf" in s:
            for sub in s["allOf"]:
                self._v(sub, x, path, out)
        if "anyOf" in s and all(self._sub_errors(sub, x, path) for sub in s["anyOf"]):
            out.append(f"{_ptr(path)}: does not match anyOf")
        if "oneOf" in s and sum(1 for sub in s["oneOf"] if not self._sub_errors(sub, x, path)) != 1:
            out.append(f"{_ptr(path)}: must match exactly one of oneOf")

    def _sub_errors(self, s: Any, x: Any, path: list) -> list[str]:
        tmp: list[str] = []
        self._v(s, x, path, tmp)
        return tmp
