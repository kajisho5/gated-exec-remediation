"""checklist 操作 — GER はファイルを変えない。

params: {"template": "CL-PKG", "steps": [{"id": "s1", "text": "…", "blocking": true}],
         "verify"?: {"kind": "path_absent" | "file_hash_changed" | "self_attested"}}
apply の結果は pending_manual。作業者が ger confirm で手順ごとに確認を記録する（監査ログに追記）。
verify にローカルで確かめられる条件があれば GER が確かめてから記録する。ローテーションのような外部の作業は
「本人が確認した」（self_attested）とだけ記録し、「検証済み」とは呼ばない。target は null を許す。

同じ形の手順（{template, steps}）は、自動修復の action に action.followup として付けられる（必須の後続作業）。
"""
from __future__ import annotations

import re

from .base import ActionError, PreviewResult, Step

TYPE = "checklist"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 3
_TEMPLATE = re.compile(r"^CL-[A-Z0-9-]{1,32}$")
_STEP_ID = re.compile(r"^s[0-9]{1,3}$")
VERIFY_KINDS = ("path_absent", "file_hash_changed", "self_attested")


def validate_steps(obj: dict, label: str = "params") -> None:
    if not isinstance(obj.get("template"), str) or not _TEMPLATE.fullmatch(obj["template"]):
        raise ActionError(f"{label}.template は CL-XXX 形式であること")
    steps = obj.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise ActionError(f"{label}.steps は 1〜64 件であること")
    ids = set()
    for s in steps:
        if not isinstance(s, dict) or set(s) != {"id", "text", "blocking"}:
            raise ActionError(f'{label}.steps[] は {{"id", "text", "blocking"}} であること')
        if not isinstance(s["id"], str) or not _STEP_ID.fullmatch(s["id"]) or s["id"] in ids:
            raise ActionError(f"{label}.steps[].id は s<数字> で重複しないこと")
        ids.add(s["id"])
        if not isinstance(s["text"], str) or not 1 <= len(s["text"]) <= 2000:
            raise ActionError(f"{label}.steps[].text は 1〜2000 文字")
        if not isinstance(s["blocking"], bool):
            raise ActionError(f"{label}.steps[].blocking は真偽値")


def validate_params(params: dict) -> None:
    if not isinstance(params, dict) or not set(params) <= {"template", "steps", "verify"}:
        raise ActionError('params は {"template", "steps", "verify"?} であること')
    validate_steps(params)
    if "verify" in params:
        v = params["verify"]
        if not isinstance(v, dict) or set(v) != {"kind"} or v["kind"] not in VERIFY_KINDS:
            raise ActionError(f"params.verify は {{\"kind\": {' | '.join(VERIFY_KINDS)}}}")


class ChecklistStep(Step):
    type = TYPE
    order = ORDER

    def apply(self, rt):
        pass

    def rollback(self, rt):
        pass

    def result_extra(self):
        return {"template": self.items[0].action["params"]["template"]}


def prepare(ctx, items):
    for it in items:
        validate_params(it.action["params"])
    return ChecklistStep(items, items[0].action["target"])


def preview(ctx, items) -> PreviewResult:
    p = items[0].action["params"]
    validate_params(p)
    return PreviewResult(p, f"checklist {p['template']}（{len(p['steps'])} 手順。GER はファイルを変えない）")
