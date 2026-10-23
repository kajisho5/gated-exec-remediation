"""checklist operation - GER does not change files.

params: {"template": "CL-PKG", "steps": [{"id": "s1", "text": "…", "blocking": true}],
         "verify"?: {"kind": "path_absent" | "file_hash_changed" | "self_attested"}}
The apply result is pending_manual. The worker records each step with ger confirm (appended to the audit log).
If verify has a condition that can be checked locally, GER checks it before recording. External work such as a rotation
is recorded only as "confirmed by the person" (self_attested) and is never called "verified". target may be null.

Steps of the same shape ({template, steps}) can be attached to an automatic remediation action as action.followup (required follow-up work).
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
        raise ActionError(f"{label}.template must have the form CL-XXX")
    steps = obj.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise ActionError(f"{label}.steps must have 1-64 entries")
    ids = set()
    for s in steps:
        if not isinstance(s, dict) or set(s) != {"id", "text", "blocking"}:
            raise ActionError(f'{label}.steps[] must be {{"id", "text", "blocking"}}')
        if not isinstance(s["id"], str) or not _STEP_ID.fullmatch(s["id"]) or s["id"] in ids:
            raise ActionError(f"{label}.steps[].id must be s<digits> and unique")
        ids.add(s["id"])
        if not isinstance(s["text"], str) or not 1 <= len(s["text"]) <= 2000:
            raise ActionError(f"{label}.steps[].text must be 1-2000 characters")
        if not isinstance(s["blocking"], bool):
            raise ActionError(f"{label}.steps[].blocking must be a boolean")


def validate_params(params: dict) -> None:
    if not isinstance(params, dict) or not set(params) <= {"template", "steps", "verify"}:
        raise ActionError('params must be {"template", "steps", "verify"?}')
    validate_steps(params)
    if "verify" in params:
        v = params["verify"]
        if not isinstance(v, dict) or set(v) != {"kind"} or v["kind"] not in VERIFY_KINDS:
            raise ActionError(f"params.verify must be {{\"kind\": {' | '.join(VERIFY_KINDS)}}}")


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
    return PreviewResult(p, f"checklist {p['template']} (steps: {len(p['steps'])}; GER does not change files)")
