"""chmod operation. Uses os.fchmod / os.chmod, no external commands.

- params is only {"mode": "0NNN"} (3 octal digits). setuid / setgid / sticky bits and world-writable cannot be granted
- A chmod that adds a permission missing from the current mode is rejected by G-7 (remediation only narrows permissions)
- Right before applying, checks that the target still matches (st_dev, st_ino, st_ctime_ns) from pre-validation (replacement detection).
  i-node numbers can be reused after delete and re-create, so ctime is part of the identity check
- Not recursive. Does not follow symbolic links
"""
from __future__ import annotations

import os
import re
import stat

from .base import ActionError, PreviewResult, Step

TYPE = "chmod"
REVERSIBLE = True
DESTRUCTIVE = False
ORDER = 2
_MODE = re.compile(r"^0[0-7]{3}$")


def parse_params(params: dict) -> int:
    if set(params) != {"mode"} or not isinstance(params["mode"], str) or not _MODE.fullmatch(params["mode"]):
        raise ActionError('params accepts only {"mode": "0NNN"} (3 octal digits, no special bits)')
    mode = int(params["mode"], 8)
    if mode & 0o002:  # Same as ZET I-4. Rejected statically, separately from "do not add to the current mode" (G-7)
        raise ActionError("a chmod that grants write permission to others (world-writable) is not accepted")
    return mode


def fmt(mode: int) -> str:
    return f"0{mode & 0o777:03o}" if mode & 0o7000 == 0 else f"{mode & 0o7777:04o}"


def inspect(target: str) -> os.stat_result:
    """Pre-validation. Checks that the target is a regular file or a directory and that the owner can change it."""
    st = os.lstat(target)
    if stat.S_ISLNK(st.st_mode):
        raise ActionError("a symbolic link cannot be a target")
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise ActionError("only a regular file or a directory can be a target")
    if os.geteuid() != 0 and st.st_uid != os.geteuid():
        raise ActionError("cannot change permissions: not the owner")
    return st


Ident = tuple[int, int, int]


def ident_of(st: os.stat_result) -> Ident:
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def _same(st: os.stat_result, ident: Ident) -> bool:
    return ident_of(st) == ident


def set_mode(target: str, mode: int, ident: Ident) -> Ident:
    """Sets mode only on the same object as ident and returns the ident after the change (used for checks on rollback)."""
    st = os.lstat(target)
    if stat.S_ISLNK(st.st_mode) or not _same(st, ident):
        raise ActionError("the target was replaced after pre-validation")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if stat.S_ISDIR(st.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(target, flags)
    except PermissionError:
        fd = None  # No read permission (for example 0000). The lstat before/after check is used instead
    if fd is not None:
        try:
            if not _same(os.fstat(fd), ident):
                raise ActionError("the target was replaced after pre-validation")
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    else:
        os.chmod(target, mode)
    # Failures from here on may come after the change (applied=True)
    try:
        after = os.lstat(target)
    except OSError as e:
        raise ActionError(f"cannot check the target after applying: {e}", applied=True) from e
    if stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != ident[:2]:
        raise ActionError("the target was replaced while applying", applied=True)
    if after.st_mode & 0o7777 != mode:
        raise ActionError(f"permissions after applying are {fmt(after.st_mode)} (expected {fmt(mode)})", applied=True)
    return ident_of(after)


def validate_params(params: dict) -> None:
    parse_params(params)


class ChmodStep(Step):
    type = TYPE
    order = ORDER

    def __init__(self, items, target, mode, ident, before):
        super().__init__(items, target)
        self.mode, self.ident, self.before = mode, ident, before
        self.noop = before == mode
        self.applied_ident = None

    def before_after(self):
        return fmt(self.before), fmt(self.mode)

    def apply(self, rt):
        # The intent goes to the journal first: a process killed right after the change can still be rolled back by ger recover
        rt.note(rt.step_no, {"op": "chmod", "stage": "start", "target": self.target, "before": self.before, "mode": self.mode,
                             "ident": list(self.ident)})
        self.applied_ident = set_mode(self.target, self.mode, self.ident)
        self.undo = {"op": "chmod", "stage": "done", "target": self.target, "before": self.before, "mode": self.mode,
                     "ident": list(self.applied_ident)}
        rt.note(rt.step_no, self.undo)

    def rollback(self, rt):
        set_mode(self.target, self.before, self.applied_ident)


def _undo_state(u: dict):
    """(what replaying u does, current lstat): "none" (the change was not made) or "revert". ActionError if the target is
    not in the state this chmod left (replaced, or its mode changed since): replaying it then would not undo GER's change."""
    st = os.lstat(u["target"])
    if stat.S_ISLNK(st.st_mode) or [st.st_dev, st.st_ino] != list(u["ident"][:2]):
        raise ActionError(f"cannot roll back chmod: the target was replaced: {u['target']}")
    if u.get("stage") == "start":  # Killed between the intent and the result: the change may or may not have been made
        cur = st.st_mode & 0o7777
        if cur == u["before"]:
            return "none", st
        if cur != u["mode"]:
            raise ActionError(f"cannot roll back chmod: the mode changed since ({fmt(cur)}): {u['target']}")
        return "revert", st
    if ident_of(st) != tuple(u["ident"]):
        # A rollback killed between set_mode(before) and its step_rolled_back line leaves the same i-node with the mode
        #   from before (and a new ctime): GER's change is already undone
        if st.st_mode & 0o7777 == u["before"]:
            return "none", st
        raise ActionError(f"cannot roll back chmod: the target changed after the chmod: {u['target']}")
    return "revert", st


def check_undo(u: dict) -> None:
    _undo_state(u)


def rollback_undo(u: dict) -> None:
    what, st = _undo_state(u)
    if what == "revert":
        set_mode(u["target"], u["before"], ident_of(st))


def prepare(ctx, items):
    """Pre-validation (G-7 / G-10). chmod cannot add a permission missing from the current mode (narrowing only)."""
    if len(items) != 1:
        raise ActionError("chmod cannot be grouped")
    a = items[0].action
    t = a["target"]
    mode = parse_params(a["params"])
    st = inspect(t)
    if os.path.realpath(t) != t:
        raise ActionError("the path contains a symbolic link")
    before = st.st_mode & 0o7777
    added = mode & ~before
    if added:  # Remediation only narrows permissions, so a tampered plan cannot loosen them either
        raise ActionError(f"chmod {fmt(mode)} adds permissions ({added:04o}) missing from the current mode {fmt(before)}"
                          " (only operations that narrow permissions are accepted)")
    step = ChmodStep(items, t, mode, ident_of(st), before)
    step.st = st
    return step


def preview(ctx, items) -> PreviewResult:
    p = items[0].action["params"]
    parse_params(p)
    return PreviewResult(p, f"chmod {p['mode']}")
