"""quarantine operation - reversible. Moves the target into the quarantine store with rename (nothing is deleted).

params:
  self (file)            {"kind": "file", "sha256"}
  self (tree)            {"kind": "tree", "tree_sha256"}
  self (link)            {"kind": "symlink", "link_target"}        moves the link itself; the link target is not followed
  npm_pkg_dir / npm_installed {"kind": "tree", "tree_sha256", "subject": {"name", "version"}}
  pypi_record            {"kind": "tree", "tree_sha256", "record": true}
                         the dist-info and every file listed in RECORD under site-packages (checked against the sha256 in RECORD)
  ext_dir / skill_dir    {"kind": "tree", "tree_sha256"}
Preconditions: the type matches kind. A file must match the SHA-256 of its content and have st_nlink == 1. A tree must match ger-tree-v1.
A link must match the readlink value. The target must be on the same st_dev as the quarantine store (rejected otherwise, because rename would not be atomic).
GER derives the target and its relation again from the current file system (G-9). An operation that removes only the metadata
ZES used as evidence and leaves the code in place (only the dist-info, only manifest.json, and so on) is rejected (Q-6).
After the move, files become 0400 and directories 0500 (the original mode is kept in the manifest and restored on restore).
"""
from __future__ import annotations

import base64
import csv
import io
import json
import posixpath
import re
import stat

from .. import fsutil, hazards, store
from ..core import sha256
from . import base
from .base import ActionError, PreviewResult, Step

TYPE = "quarantine"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 1
RELATIONS = ("self", "npm_pkg_dir", "npm_installed", "pypi_record", "ext_dir", "skill_dir")
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_NPM_REST = re.compile(r"^(?:(?:@[^/@][^/]*/)?[^/@.][^/]*/node_modules/)*(?:@[^/@][^/]*/)?[^/@.][^/]*$")
_EXT = re.compile(r"^(.*/Extensions/[^/]+)(/[^/]+)?/manifest\.json$")


def validate_params(params: dict) -> None:
    if not isinstance(params, dict) or params.get("kind") not in ("file", "tree", "symlink"):
        raise ActionError('params.kind must be one of "file" / "tree" / "symlink" (built by ger preview)')
    k = params["kind"]
    allowed = {"file": {"kind", "sha256"}, "symlink": {"kind", "link_target"},
               "tree": {"kind", "tree_sha256", "subject", "record"}}[k]
    if not set(params) <= allowed:
        raise ActionError(f"params for kind={k} contain fields that cannot be used: {sorted(set(params) - allowed)}")
    if k == "file" and not (isinstance(params.get("sha256"), str) and _SHA.fullmatch(params["sha256"])):
        raise ActionError("params.sha256 must be sha256:<64 hex digits>")
    if k == "tree" and not (isinstance(params.get("tree_sha256"), str) and _SHA.fullmatch(params["tree_sha256"])):
        raise ActionError("params.tree_sha256 must be sha256:<64 hex digits> (ger-tree-v1)")
    if k == "symlink" and not (isinstance(params.get("link_target"), str) and params["link_target"]):
        raise ActionError("params.link_target must be the readlink value (a non-empty string)")
    if "subject" in params:
        s = params["subject"]
        if not isinstance(s, dict) or set(s) != {"name", "version"} or not isinstance(s["name"], str) \
                or not (s["version"] is None or isinstance(s["version"], str)):
            raise ActionError('params.subject must be {"name": str, "version": str|null}')
    if "record" in params and params["record"] is not True:
        raise ActionError("params.record must be true")


# --- Lexical conditions of the relation, and the check on the file system (G-9) ----------------------
def lexical_relation(relation: str, target: str, fp: str | None) -> str | None:
    """A reason if there is a problem. Same conditions as ZET I-4 (GER does not trust the plan and checks by itself)."""
    if relation not in RELATIONS:
        return f"relation {relation} cannot be used for quarantine ({', '.join(RELATIONS)})"
    if fp is None:
        return "the target of a finding whose finding_path is null cannot be quarantined"
    if relation == "self":
        return None if target == fp else "relation self: target must equal finding_path"
    if relation == "npm_pkg_dir":
        par = posixpath.dirname(target)
        ok = fp == target + "/package.json" and (posixpath.basename(par) == "node_modules" or (
            posixpath.basename(par).startswith("@") and posixpath.basename(posixpath.dirname(par)) == "node_modules"))
        return None if ok else "npm_pkg_dir: target must be node_modules/<name> (scoped: node_modules/@scope/<name>) and finding_path its package.json"
    if relation == "npm_installed":
        base_ = posixpath.dirname(fp) + "/node_modules/"
        ok = posixpath.basename(fp) in LOCKFILES and target.startswith(base_) and _NPM_REST.fullmatch(target[len(base_):])
        return None if ok else "npm_installed: the finding must be a lockfile and target the node_modules/<name> next to it"
    if relation == "pypi_record":
        ok = target == fp and posixpath.basename(target).endswith(".dist-info")
        return None if ok else "pypi_record: target must be the *.dist-info directory of finding_path"
    if relation == "ext_dir":
        m = _EXT.match(fp)
        return None if m and m.group(1) == target else "ext_dir: finding_path must be .../Extensions/<id>[/<ver>]/manifest.json and target .../Extensions/<id>"
    if relation == "skill_dir":
        ok = target == fp or (posixpath.basename(fp) == "skill.contract.json" and posixpath.dirname(fp) == target)
        return None if ok else "skill_dir: target must be the skill directory of finding_path"
    return "unknown relation"


def _read_json_in(target: str, rel: str, limit=1 << 20):
    r = fsutil.resolve(target + "/" + rel)
    try:
        base.check_regular(r.st, rel)
        raw = fsutil.read_file(r.parent_fd, r.name, r.st, limit=limit)
    finally:
        r.close()
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ActionError(f"cannot read {rel} as JSON") from None


def _npm_subject(target: str) -> dict:
    pj = _read_json_in(target, "package.json")
    if not isinstance(pj, dict) or not isinstance(pj.get("name"), str):
        raise ActionError("package.json has no name")
    v = pj.get("version")
    return {"name": pj["name"], "version": v if isinstance(v, str) else None}


def _expected_npm_name(target: str) -> str:
    i = target.rfind("/node_modules/")
    return target[i + len("/node_modules/"):]


def record_members(target: str) -> tuple[list[str], list[str], list[str]]:
    """(members to move, members outside site-packages, missing members). ActionError if a hash differs from RECORD."""
    sp = posixpath.dirname(target)
    try:
        r = fsutil.resolve(target + "/RECORD")
    except FileNotFoundError:
        raise ActionError("RECORD is missing. Quarantining only the dist-info would leave the code in place, so it cannot be quarantined"
                          " (rebuild the virtual environment with a checklist; Q-6)") from None
    try:
        base.check_regular(r.st, "RECORD")
        raw = fsutil.read_file(r.parent_fd, r.name, r.st, limit=16 << 20)
    finally:
        r.close()
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error):
        raise ActionError("cannot read RECORD as CSV") from None
    move, outside, missing = [], [], []
    for row in rows:
        if not row or not row[0]:
            continue
        p = row[0]
        h = row[1] if len(row) > 1 else ""
        full = posixpath.normpath(posixpath.join(sp, p))
        if p.startswith("/") or not fsutil.is_under(full, sp) or full == sp:
            outside.append(full)
            continue
        if fsutil.is_under(full, target):
            continue  # Inside the dist-info the whole tree is moved (fixed by the tree hash)
        try:
            m = fsutil.resolve(full)
        except FileNotFoundError:
            missing.append(full)
            continue
        except fsutil.FsError as e:
            raise ActionError(f"RECORD member {full}: {e}") from None
        try:
            base.check_regular(m.st, f"RECORD member {full}")
            if h:
                algo, _, b64 = h.partition("=")
                if algo != "sha256":
                    raise ActionError(f"RECORD hash is not sha256: {full}")
                got = fsutil.hash_file(m.parent_fd, m.name, m.st)[len("sha256:"):]
                want = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).hex()
                if got != want:
                    raise ActionError(f"RECORD member hash does not match: {full}")
            elif not full.endswith(".pyc"):
                raise ActionError(f"RECORD member has no hash: {full}")
        finally:
            m.close()
        move.append(full)
    return move, outside, missing


def check_relation_fs(relation: str, target: str, fp: str, params: dict) -> None:
    if relation in ("npm_pkg_dir", "npm_installed"):
        subj = params.get("subject")
        if not subj:
            raise ActionError(f"{relation} requires params.subject (name / version)")
        cur = _npm_subject(target)
        if cur["name"] != subj["name"] or cur["name"] != _expected_npm_name(target):
            raise ActionError("the name in node_modules/<name>/package.json does not match params.subject.name and the directory name")
        if subj["version"] is not None and cur["version"] != subj["version"]:
            raise ActionError("the version in package.json does not match params.subject.version")
    elif relation == "pypi_record":
        if params.get("record") is not True:
            raise ActionError("pypi_record requires params.record: true")
        record_members(target)
    elif relation == "ext_dir":
        _read_json_in(target, fp[len(target) + 1:])
    elif relation == "skill_dir":
        found = False
        for n in ("skill.contract.json", "SKILL.md"):
            try:
                r = fsutil.resolve(target + "/" + n)
            except FileNotFoundError:
                continue
            try:
                found = found or stat.S_ISREG(r.st.st_mode)
            finally:
                r.close()
        if not found:
            raise ActionError("skill_dir: the directory has neither skill.contract.json nor SKILL.md")


# --- Step ----------------------------------------------------------------------------------------
class QuarantineStep(Step):
    type = TYPE
    order = ORDER

    def __init__(self, items, target, moves, relation, digest, noop=False):
        super().__init__(items, target)
        self.moves = moves  # [(Resolved, kind, ident, digest, TreeInfo|None)]
        self.relation, self.digest, self.noop = relation, digest, noop

    def paths(self):
        return [m[0].path for m in self.moves]

    def before_after(self):
        qids = [u["qid"] for u in self.undo.get("entries", []) if u.get("stage") == "done"]
        return self.digest, ("quarantined:" + qids[0] if qids else None)

    def result_extra(self):
        ents = self.undo.get("entries", [])
        return {"relation": self.relation, "quarantine_ids": [u["qid"] for u in ents],
                "manifest_sha256": [u.get("manifest_sha256") for u in ents]}

    def apply(self, rt):
        self.undo = {"entries": []}
        for res, kind, ident, digest, tree in self.moves:
            base.move_in(rt, res, kind, ident, digest, tree,
                         {"finding_ids": self.finding_ids, "relation": self.relation, "action_target": self.target},
                         self.undo["entries"], rt.step_no)

    def rollback(self, rt):
        errs = []
        for u in reversed(self.undo.get("entries", [])):
            try:
                base.move_out(u)
            except Exception as e:  # Restore the rest even if one entry cannot be restored
                errs.append(f"{u['orig']}: {e}")
        if errs:
            raise ActionError("; ".join(errs))


def _pin_of(params):
    return params.get("sha256") or params.get("tree_sha256") or ("link:" + params.get("link_target", ""))


def _already(target: str, params: dict) -> bool:
    pin = _pin_of(params)
    for e in store.list_entries():
        if e.get("original_path") == target and e.get("status") == "quarantined" and e.get("operation") == "quarantine":
            try:
                m, _h = store.read_manifest(e["quarantine_id"])
            except Exception:
                continue
            if m.get("hash") == pin:
                return True
    return False


def _inspect(ctx, path: str, kind: str):
    res = ctx.pool.add(fsutil.resolve(path))
    st = res.st
    k = fsutil.kind_of(st)
    if k == "special":
        raise ActionError("a FIFO, socket or device cannot be quarantined")
    if k != kind:
        raise ActionError(f"the target type is {k} (params.kind is {kind})")
    if ctx.store_dev is not None and st.st_dev != ctx.store_dev:
        raise ActionError("the target is on a different device (file system) from the quarantine store. It cannot be quarantined because rename would not be atomic"
                          " (set GER_QUARANTINE_DIR to a store on the same device)")
    if ctx.euid != 0 and st.st_uid != ctx.euid and k != "symlink":
        raise ActionError("cannot quarantine: not the owner")
    if k == "tree" and ctx.euid != 0 and not st.st_mode & 0o200:
        raise ActionError("an entry in a directory without write permission cannot be moved elsewhere")
    tree = None
    if k == "file":
        base.check_regular(st)
        digest = fsutil.hash_file(res.parent_fd, res.name, st)
    elif k == "tree":
        tree = fsutil.tree_hash(res.parent_fd, res.name, st.st_dev)
        digest = tree.hash
    else:
        digest = "link:" + fsutil.readlink(res.parent_fd, res.name)
    return res, digest, tree


def _relations(items) -> list[tuple[str, str | None]]:
    """(relation, finding_path) of each item of the group. With findings 1.1, findings with different finding_path values are
    grouped on one target (a skill directory and skill.contract.json, node_modules/<name>/package.json and a lockfile).
    The relation of every item is checked, not only the first (G-9)."""
    out = []
    for it in items:
        a = it.action
        rel, fp = a.get("relation", "self"), a.get("finding_path", a["target"])
        why = lexical_relation(rel, a["target"], fp)
        if why:
            raise ActionError(f"G-9: {why}")
        if (rel, fp) not in out:
            out.append((rel, fp))
    return out


def _check_kind(target: str, rels, kind: str) -> None:
    for rel, _fp in rels:
        if rel == "self":
            why = hazards.metadata_only(target, kind)
            if why:
                raise ActionError(f"Q-6: {why}")
        elif kind != "tree":
            raise ActionError(f"the target of relation {rel} is a directory (kind: tree)")


def prepare(ctx, items):
    a = items[0].action
    params = base.same_group_params(items)
    validate_params(params)
    target = a["target"]
    rels = _relations(items)
    relation = rels[0][0]
    _check_kind(target, rels, params["kind"])
    try:
        fsutil.resolve(target).close()
    except FileNotFoundError:
        if _already(target, params):
            return QuarantineStep(items, target, [], relation, _pin_of(params), noop=True)
        raise
    for rel, fp in rels:
        check_relation_fs(rel, target, fp, params)
    res, digest, tree = _inspect(ctx, target, params["kind"])
    if digest != _pin_of(params):
        raise ActionError("the target content changed since preview (approval) (hash or link target does not match params)")
    moves = []
    if relation == "pypi_record":
        members, _outside, _missing = record_members(target)
        for m in members:
            mres, mdig, _t = _inspect(ctx, m, "file")
            moves.append((mres, "file", fsutil.ident_of(mres.st), mdig, None))
    moves.append((res, params["kind"], fsutil.ident_of(res.st), digest, tree))
    return QuarantineStep(items, target, moves, relation, digest)


def preview(ctx, items) -> PreviewResult:
    a = items[0].action
    target = a["target"]
    rels = _relations(items)
    relation = rels[0][0]
    names = {r for r, _fp in rels}
    res = ctx.pool.add(fsutil.resolve(target))
    kind = fsutil.kind_of(res.st)
    if kind == "special":
        raise ActionError("a FIFO, socket or device cannot be quarantined")
    if "self" in names:
        why = hazards.metadata_only(target, kind)
        if why:
            raise ActionError(f"Q-6: {why}")
    params: dict = {"kind": kind}
    extra = ""
    if names & {"npm_pkg_dir", "npm_installed"}:
        params["subject"] = _npm_subject(target)
        extra = f" {params['subject']['name']}@{params['subject']['version']}"
    if "pypi_record" in names:
        params["record"] = True
    for rel, fp in rels:
        check_relation_fs(rel, target, fp, params)
    _r, digest, tree = _inspect(ctx, target, kind)
    if kind == "file":
        params["sha256"] = digest
        summary = f"file {digest}"
    elif kind == "tree":
        params["tree_sha256"] = digest
        summary = f"tree {tree.entries} entries, {tree.bytes} bytes, {digest}{extra}"
    else:
        params["link_target"] = digest[len("link:"):]
        summary = "symlink → " + params["link_target"]
    if relation == "pypi_record":
        members, outside, missing = record_members(target)
        summary += f"; RECORD: move {len(members)} files"
        if outside:
            summary += f"; outside site-packages (not moved, manual work required): {', '.join(outside)}"
        if missing:
            summary += f"; missing: {len(missing)}"
    validate_params(params)
    return PreviewResult(params, f"{relation}: {target} → store ({summary})")


def touched_paths(step) -> list[str]:
    return step.paths() if isinstance(step, QuarantineStep) else [step.target]


__all__ = ["TYPE", "prepare", "preview", "validate_params", "QuarantineStep", "sha256"]
