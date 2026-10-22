"""JSON Schema（2020-12）のサブセット検証器。標準ライブラリのみ。

ZET / GER が使うキーワードだけを実装する:
  type, const, enum, pattern, minLength, minimum, maximum, minItems, uniqueItems,
  required, properties, additionalProperties(false/スキーマ), items, $ref(#/$defs/...),
  if/then/else, not, anyOf, oneOf, allOf
未対応のキーワードがスキーマに現れたら例外にする（黙って通さない）。
テストでは公式実装 jsonschema と判定が一致することを確認している。
"""
from __future__ import annotations

import re
from typing import Any

_SUPPORTED = {
    "$schema", "$id", "$defs", "$comment", "title", "description", "default", "examples",
    "type", "const", "enum", "pattern", "minLength", "minimum", "maximum", "minItems", "uniqueItems",
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
    """スキーマ自体が不正、または未対応キーワードを含む。"""


def _ptr(path: list) -> str:
    return "/" + "/".join(str(p) for p in path) if path else "/"


def _eq(a: Any, b: Any) -> bool:
    # JSON の等価性（bool と数値を区別する）
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
            if "pattern" in s and not re.search(s["pattern"], x):
                out.append(f"{_ptr(path)}: does not match {s['pattern']}")
            if "minLength" in s and len(x) < s["minLength"]:
                out.append(f"{_ptr(path)}: shorter than {s['minLength']}")
        if _TYPES["number"](x):
            if "minimum" in s and x < s["minimum"]:
                out.append(f"{_ptr(path)}: below minimum {s['minimum']}")
            if "maximum" in s and x > s["maximum"]:
                out.append(f"{_ptr(path)}: above maximum {s['maximum']}")
        if isinstance(x, list):
            if "minItems" in s and len(x) < s["minItems"]:
                out.append(f"{_ptr(path)}: fewer than {s['minItems']} items")
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
                        out.append(f"{_ptr(path)}: unknown field '{k}'")
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
