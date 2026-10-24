English | [日本語](design.ja.md)

# GER (Gated-Exec Remediation) detailed design — Step 1

- **Version**: design 0.1 (2026-10-22) / approved 2026-10-22 (C-1 to C-6 adopted), implementation 0.1.0
- **Addendum**: implements Phase 1 of the remediation capability extension, design 0.2 (approved 2026-10-23; Q-1 to Q-6 adopted as recommended) (§10). §1 to §9 were updated for Phase 1
- **Layer**: remediation layer (after ZES -> ZET; the only one of the 3 layers that makes changes)
- **Principle**: Gated-Exec. Only operations that pass every gate are executed, only on the targets written in the plan, idempotently
- **Parent documents**: [ZES skill contracts](https://github.com/kajisho5/zero-exec-shield/blob/main/docs/skill-contracts.md) (§1, §5 to §8), [ZET design](https://github.com/kajisho5/zero-exec-triage/blob/main/docs/design/design.md)

```
[ZET] draft ─▶ [GER] preview (fills params hashes and ops; no change) ─▶ [ZET] finalize
[ZET] remediation-plan.json ─┐
human approval (approval) ───┼─▶ [GER] gates 1 to 10 ─▶ dry-run ─▶ apply ─▶ remediation-log.json
allowed_actions ─────────────┘                                  └─▶ quarantine store (restore moves back) / checklist (recorded with confirm)
```

---

## 1. Requirements

### 1.1 Purpose
Execute a remediation plan finalized by ZET after explicit human approval. The top priority is to stop, **before execution**, every wrong plan, every plan without approval and every change to a target outside the plan; coverage of remediation comes second.

### 1.2 Scope (Phase 1)

| Operation | Phase 1 | Content |
|---|---|---|
| `chmod` | Implemented (since the first version) | Narrows permissions only. ZES §11 (SSH/GPG permissions) |
| `quarantine` | **Implemented** | Moves files, trees and symbolic links into the quarantine store with rename. Relations self / npm_pkg_dir / npm_installed / pypi_record / ext_dir / skill_dir |
| `edit_json` | **Implemented** | Removes JSON / JSONC members matching H, or replaces them with a K constant (keeps formatting and comments) |
| `edit_toml` | **Implemented (Phase 1 scope)** | Removes `[mcp_servers.<name>]` defined with a standard table header. Dotted keys and inline tables are rejected |
| `remove_line` | **Implemented** | Removes one top-level line matching H in shell rc files, git config, php.ini, ld.so.preload, /etc/cron.d |
| `disable_mcp_server` | **Implemented** | Preset of edit_json / edit_toml (MCP server definitions only) |
| `checklist` | **Implemented** | GER does not change files. `pending_manual` on apply, recorded per step with `ger confirm` |
| `ger restore` | **Implemented** | A command outside the plan. Moves back quarantined objects and files from before an edit (2 approvers, dry-run required) |
| `replace_token` / `pin_action` / `pin_digest` / `ensure_line`, relations plist_program / preload_lib / unit_wants | Phase 2 (not implemented; rejected by G-5 / G-9) | |
| `write_config` / `rotate_secret` | Not registered | Revoking or rotating a secret needs the network and irreversible operations, so it is a checklist at every stage |

No operation deletes files. Every operation keeps the state before the change in the quarantine store (chmod keeps the original mode in remediation-log). A plan that contains an unsupported operation is **rejected as a whole by pre-validation, not only that one item** (no partial application).

### 1.3 Functions

| Command | Content | Exit codes |
|---|---|---|
| `ger verify <ger-input.json>` | Validation of gates 1 to 6 only (no change) | 0=OK / 3=rejected / 64=arguments |
| `ger dry-run <ger-input.json>` | Validation + computes before/after of each operation and records it in the log (no change) | 0 / 3 |
| `ger apply <ger-input.json>` | Validation + checks the dry-run record of the same plan, then executes. On failure everything is rolled back | 0 / 3=rejected / 4=failed and rolled back / 5=rollback also failed |
| `ger verify-log [LOG]` | Verifies the hash chain of the audit log (read only; this run is not recorded) | 0=intact / 3=broken / 64=no log or unreadable |
| `ger preview <draft-plan.json> -o OUT [--report R] [--diff]` | Fills the params of the draft actions (hashes, ops, `expected_after_sha256`) from the current content. Changes nothing. Recorded in the audit log as `preview` but not counted as a dry-run | 0 / 3=some rejected (per-item reasons in `--report`) |
| `ger confirm <ger-input.json> --item FID --step CL-XXX:sN` | Appends the confirmation of a checklist / followup step to the audit log (after the successful apply record; the worker must not be an approver) | 0 / 3 |
| `ger restore <restore-request.json> -o OUT` | Moves quarantine store entries back (§10.5) | 0 / 3 / 4 / 5 |
| `ger recover <ger-input.json> -o OUT` | Rolls back an unfinished apply left in the journal (applies G-1 to G-4) | 0 / 3 / 5 |
| `ger quarantine-list [--json] [--plan-id ID]` | Lists the quarantine store and verifies the manifests (read only) | 0 |

`ger-input.json` is contract §5 (`schema_version` / `plan` / `approval` / `mode` / `allowed_actions`). A `mode` that does not match the subcommand is rejected.

### 1.4 Non-functional requirements
- **Zero dependencies**: Python 3.11 or later, standard library only. Started with `python3 -I -S` (site is not loaded, so `.pth` files in site-packages are not executed either)
- **No external processes and no network**: `chmod` uses `os.fchmod`, moves `os.rename`, backups `os.link`; no shell, no external commands. The tests check the execve calls and network system calls of every command with strace
- **fail-closed**: if any gate fails, nothing is changed
- **Idempotent**: already in the target state -> `skipped` (`reason: "already_compliant"`)

---

## 2. Gates (all checks before execution)

| # | Gate | Rejection condition | Basis |
|---|---|---|---|
| G-1 | Schema | Input or plan does not match the strict schema, `schema_version` mismatch, the input has a `findings` key. Action params do not match `schemas/actions.schema.json` and the meaning checks of the operation. A plan 1.0 has an operation other than chmod. A plan 1.1 action has no relation / finding_path / evidence, or has a null target without being a checklist. Violates a ZET invariant that can be evaluated from the plan alone (uniqueness of I-1, I-3, the action shape and target path shape of I-4, I-5 / I-6 / I-7 against `items[].skillpact` and consistency of `skillpact_effects`, 2 approvers for a remediate with risky effects, the order of dates of I-9, existing dates and times of I-11, partial and held of I-12) | No skipping a layer, pinned versions, the approval token only shows integrity (§4) |
| G-2 | Plan state | `plan.status` other than `ok`/`partial` (`draft` and `error` are rejected). A plan with `now_override: true` (made by ZET with `--now`) while `GER_ALLOW_NOW_OVERRIDE` is not `1`. The current time is past the latest remediate `due_at` | Failure propagation (ZET A-1); test plans and expired plans are not executed |
| G-3 | Approval | `approval.plan_id != plan.plan_id`, `approval_token != plan_hash`, empty `approved_by`, `approved_at` in the future, before the plan was created, or older than `GER_APPROVAL_MAX_AGE` (default 7 days) | No execution without approval (§3), no reuse of old approvals |
| G-4 | No self-approval | `approval.approved_by` contains `--operator` | Chain of approval |
| G-5 | Allowlist | `action.type` outside `allowed_actions`, or not supported by GER | Allowlist approach |
| G-6 | Two approvers | `action.reversible == false`, a destructive operation (none in Phase 1) or a target that requires root with fewer than 2 in `approval.approved_by` (plan 1.1 also requires 2 in the item's `approved_by`). `action.skillpact_effects` contains exec/network/spend/send (SkillPact 0.8) but the operation is not listed explicitly in `allowed_actions`, or `approval.approved_by` has fewer than 2 (ZET I-6 also requires 2 in the item's `approved_by`) | `reversible: false`, SkillPact invariants |
| G-7 | Pre-validation of targets (all) | The target does not exist / is not a normalized absolute path / has a symbolic link as an intermediate element (walked from `/` one element at a time with `O_PATH\|O_NOFOLLOW\|O_DIRECTORY`) / the audit log, the quarantine store or a directory above them / more than one operation on the same target outside a group, or one target above another / an operation-specific check fails (chmod: adds a permission bit missing from the current mode. quarantine: type, hash, `st_nlink`, FIFO, different device. edits: over 1 MiB, xattr, mismatch of `file_sha256` and `expected_after_sha256`) / `action.evidence` (`evidence_hash` in 1.0) does not match the current finding_path | Limited targets, no partial application, binds the dry-run result to apply |
| G-9 | Scope and relation | For operations that change files (other than chmod): no `plan.scope`, or a target outside `scope.roots` and `scope.home` / the quarantine store under scope.roots, site-packages, node_modules or PATH / a protected target (§10.6) / outside the `/etc` allowlist / a target that requires root (under a system directory, or owner is not the executing user) with fewer than 2 approvers, or targets that require root and targets that do not in the same plan / `action.relation` does not hold lexically or on the file system (§10.3) | GER derives the relation between target and finding again by itself |
| G-10 | Definition T (narrowing only) | A removed unit does not match GER's table H (T-1), an added value is not in table K (T-2), the result re-parsed after the change does not equal "before - removed units (+) K replacements" (T-3), cosmetic remediation (Q-6) | A tampered plan still cannot make a loosening change |
| G-8 | dry-run record and unfinished journals | apply: the audit log has no unused successful dry-run record with the same `plan_hash`, `input_hash` and the same `--now` handling, or it is older than `GER_DRYRUN_TTL` (default 24 hours). A record is used up by the start record (`result: "started"`) that an apply appends before its first change, so also by an apply that was killed (§3.1). verify / dry-run / apply: the quarantine store holds an unfinished journal (an apply that was killed or whose rollback failed); run `ger recover` first | No apply without a dry-run; one dry-run for one apply; never an apply on top of an unfinished one |

`held[]` is not read. Only `items[]` with `decision == "remediate"` are executed (`exception` / `defer` are `skipped`).

---

## 3. Execution and rollback

In Phase 1, items with the same `action.group` form one step (transaction), and the steps run in the order
(1) edits that remove references (edit_json / edit_toml / remove_line / disable_mcp_server) -> (2) quarantine -> (3) chmod -> (4) checklist
(within one kind, in plan order). Results are reported per item (items of a group have `reason: "group:<id>"`).
Steps that change files write undo information to the journal (`journal/<run_id>.jsonl` in the quarantine store, with fsync) before and after each stage.
A failure by exception rolls everything back in reverse order (exit code 4); if the rollback also fails, the journal is left open (exit code 5).
An open journal, including one left by a process that died halfway, is rolled back with `ger recover`. The rules below date from the first version (chmod):

```
all items G-1 to G-8 -> OK
  └─ for item in items(remediate):
        before = record the current state (chmod: st_mode & 0o7777 from lstat)
        if before == after: skipped(already_compliant); continue
        apply -> check after with lstat again right away (TOCTOU: st_ino / st_dev must match before and after)
        failure -> stop and put the applied items back to before in reverse order (rolled_back)
```

### 3.1 Crash, retry and recover

An apply that is killed (SIGKILL, power loss) writes no final audit record and leaves its journal open. Two rules keep a retry and a later `ger recover` from undoing a committed remediation:

1. **The dry-run record is used up before the first change.** After the gates pass, apply appends a start record (`command: "apply"`, `result: "started"`, with the `run_id` of its journal) to the audit log under the log lock, after checking again under that lock that an unused dry-run record exists. Only then does it change anything. A second apply with the same dry-run is rejected by G-8 even if the first one was killed; the final record carries the same `run_id`.
2. **Nothing runs on top of an unfinished journal.** verify, dry-run and apply are rejected by G-8 while the quarantine store holds an open journal, with the run id and plan id of that journal; the operator runs `ger recover` with that plan's input first. A journal that recover cannot close (its rollback fails again) needs manual resolution; after that, the journal file is moved out of `<store>/journal/` by hand.

`ger recover` replays an open journal only when that is safe:

- **Superseded journals are not replayed.** If the audit log shows another apply (started or executed) or a restore after the start record of the journal's run, the journal is closed with the event `superseded` and nothing is rolled back: the later run changed or confirmed (`already_compliant`) the same targets, and replaying the old journal would undo them. The targets keep their current state; dry-run and apply finish the plan. A journal written by an earlier GER has no start record; then every record from the second of its run id on counts as later (except an apply `rollback_failed` record of the same plan and input without `run_id`, which can be its own final record).
- **All or nothing.** Before undoing anything, recover checks every step it would undo: a quarantined object must still be in the store and its original location free; an edited file must still hold exactly the bytes GER wrote (`after_sha256`) with the backup in place; a chmod target must be the same i-node with GER's mode. If any step fails the check, nothing is undone, the journal stays open and the exit code is 5.
- **Kill points between a change and its journal line.** A stage is journaled before the change it announces. When the process dies right after the change, recover reads the state from the file system: a move noted at stage `entry` whose payload is already in the store counts as moved; an edit noted at `linked` whose temporary file is gone and whose target is a new i-node with the expected content counts as replaced; a chmod intent (`stage: "start"`, journaled before the change) is undone only if the mode is GER's. A backup hard link made just before the kill (the target unchanged) is removed from the store so the target is not left with `st_nlink` 2; the content stays at the target. A step already undone by an interrupted rollback is recognized and skipped.

The test `TestKillPoints` kills apply with SIGKILL right after each of its file-system changes and fsyncs (77 points for a plan of quarantines, a tree, MCP edits, a line removal and chmods), retries apply (rejected), runs recover, and checks that the tree is either fully remediated or fully restored, that a new dry-run and apply then finish the plan, and that the audit log is a valid hash chain.

- If even one item is `failed`, the rest is not executed (contract §7)
- If the rollback itself fails: exit code 5; every target and its state is recorded in the log and manual action is requested
- `chmod` `params`: `{"mode": "0600"}` (only octal strings are accepted; granting setuid/setgid/sticky bits or world-writable is rejected). Not applied recursively to directories (no reaching up to parents or down to children)
- chmod only narrows permissions: rejected if the new mode has even one bit missing from the current mode (the value from `lstat` in G-7) (`mode & ~before != 0`). A rollback goes back to the recorded `before`, so it does not pass through this gate
- If there is an `action.evidence_hash` (ZET A-8), G-7 compares it with the current file. Same rule as ZES: for a regular file up to 100MB the SHA-256 of the content, above 100MB the SHA-256 of `path|size|mtime (seconds)`. Directories are not compared because ZES hashes the finding's detail for them. A regular file that cannot be read cannot be checked and is rejected

---

## 4. Approval token

The format of `approval_token` is not defined in the contract, so GER requires it to equal **the SHA-256 of the canonical JSON of the plan body (keys sorted, separators `,`/`:`, UTF-8) = `plan_hash`** (ZET A-6). Approvers approve the hash of the finalized plan, so replacing the plan after approval is stopped by G-3.

**Limit**: `plan_hash` shows only integrity (no change since the hash was computed), not authenticity (that ZET made it and the approvers saw that content). If the plan is rewritten after finalize and `plan_hash` and `approval_token` are recomputed, this cannot be detected cryptographically. GER therefore uses these layers of defense:

- Checks again in G-1 the ZET invariants that can be evaluated from the plan alone (also I-5 / I-6 / I-7 if there is `items[].skillpact` (ZET A-9))
- chmod only narrows permissions (G-7). Even a rewritten plan cannot loosen permissions
- Approval expiry (`GER_APPROVAL_MAX_AGE`, default 7 days) and rejection of plans past the latest remediate `due_at`
- "The target is the finding's path" (ZET I-4) cannot be checked without findings. A rewritten plan can narrow the permissions of another file owned by the operator

Possible future hardening (outside the first version): a signature per approver (SSH signatures with `ssh-keygen -Y verify` and so on). It involves starting an external command, so adopting it needs to be reconciled with the Zero-Exec policy.

---

## 5. Audit log (append only)

- Default path: `$GER_LOG_DIR/ger-audit.jsonl` (default `~/.local/state/ger/`; separate file and separate retention from ZES and ZET)
- One record per line: `skill` ("ger") / `version` / `command` / `plan_id` / `plan_hash` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator` / `result` / `gate_failed` (when rejected)
- The output `remediation-log.json` (contract §6) is written to a separate file per run, and its hash is kept in the audit log
- It has a hash chain (`prev_hash`) (same method as ZET B-2). If the chain of the audit log is broken, G-8 does not trust dry-run records and rejects
- Before appending, the link at the end (the last line is a JSON object ending in a newline, and `prev_hash` matches the line before) is checked under an exclusive lock; if it is broken, nothing is appended (nothing runs; exit code 64). The full check is `ger verify-log`
- `GER_LOG_DIR` is resolved to a real path once at startup, and every log read and write uses the resolved path. G-7 protects the directories above both the unresolved (lexical) and the resolved path. The directories above both forms of the parent of -o are likewise excluded from plan targets (a chmod 0000 on a directory holding an intermediate symbolic link would make writes through that path impossible)

---

## 6. Layout (updated to match the implementation)

```
gated-exec-remediation/
├── SKILL.md                          # Steps for agents (never approve on anyone's behalf, always dry-run before apply)
├── bin/ger                           # Launcher (resolves paths with bash builtins only, starts python3 -I -S)
├── ger/
│   ├── __main__.py / cli.py          # Arguments, exit codes, mandatory --operator, audit log records
│   ├── gates.py                      # G-1 to G-8 (changes nothing)
│   ├── executor.py                   # dry-run / apply / full rollback
│   ├── actions/{__init__.py, chmod.py}   # Operation registry (unregistered types are rejected by G-5)
│   ├── audit.py                      # Append-only log + hash chain + dry-run record lookup
│   ├── core.py                       # Canonical JSON, plan_hash / input_hash, atomic writes
│   └── jsonschema_lite.py            # The same validator as ZET (version pinned in VENDOR.json)
├── schemas/{ger-input, remediation-log}.schema.json
├── schemas/vendor/{remediation-plan.schema.json, VENDOR.json}
├── tests/{run.py, run-tests.sh, test_ger.py, fixtures/zet-final-plan.json}
├── docs/design/{design.md, design.ja.md, flow.svg, flow.ja.svg}
├── README.md / README.ja.md
└── CHANGELOG.md
```

Changes made during implementation:
- Object identity was strengthened from `(st_dev, st_ino)` to `(st_dev, st_ino, st_ctime_ns)`, because a test showed that i-node numbers are reused after delete and re-create and a replacement could not be detected
- `input_hash` is the SHA-256 of the canonical JSON of the input without `mode` (to tell whether dry-run and apply got the same input)
- `mode` and `plan_hash` were added to remediation-log (an addition to contract §6, to identify which run of which plan)

Operations are added through a common interface (`validate_params` / `prepare(ctx, items) -> Step` / `preview(ctx, items)`; a Step has `apply(rt)` / `rollback(rt)` and an undo that can be JSON) (`ger/actions/base.py`). `write_config` / `rotate_secret` are not registered.

Files added in Phase 1: `ger/fsutil.py` (fd-based target resolution, tree hash), `ger/hazards.py` (tables H / K, protected targets),
`ger/jsonedit.py` (JSON / JSONC lexer and replacement), `ger/tomledit.py` (ranges of TOML table headers), `ger/store.py` (quarantine store and journal),
`ger/restore.py`, `ger/actions/{base, quarantine, edit_common, edit_json, edit_toml, remove_line, disable_mcp_server, checklist}.py`,
`schemas/{actions, restore-request}.schema.json`, `tests/{test_remediation.py, zero_exec.py, e2e_zes.py, run-e2e.sh}`.

---

## 7. Edge cases

| Case | Handling |
|---|---|
| The target was deleted or replaced after the dry-run | Fails at G-7 and the st_ino check during apply -> full rollback |
| The target is a symbolic link | Rejected (the link target is never changed) |
| Two chmods on the same target | Rejected as a contradiction in the plan |
| Owned by root, insufficient permission | Rejected by pre-validation (decided by owner and effective UID, not `os.access`) |
| `mode` is `"600"` (no leading 0) or `0o600` | Only the string `^0[0-7]{3}$` is accepted |
| The log directory is not writable | Nothing runs; rejected (no operation that cannot be recorded) |
| The end of the audit log is broken (a cut-off line and so on) | Nothing is appended and nothing runs (64). Check with `ger verify-log`, move the log aside and run again |
| A second apply with the same dry-run | Rejected by G-8 (a dry-run record is used up once, by the start record appended before the first change) |
| apply was killed, then apply is run again | Rejected by G-8 (dry-run record used up, unfinished journal). Run `ger recover`, then dry-run and apply (§3.1) |
| `ger recover` after another apply ran over a stale journal (earlier GER) | The journal is closed as `superseded` and not replayed (§3.1) |
| Making a dry-run expired in real time look unexpired with `--now` | Rejected by G-8 (an apply with `--now` counts only dry-runs with `--now`) |

---

## 8. Test approach
- At least one pass / reject pair per gate (G-1 to G-8)
- chmod: before/after in a temporary directory, idempotence (second run skipped), rollback (failure injected halfway)
- Replacing the plan after approval is detected by G-3
- Rejection of apply without dry-run, of an expired dry-run, and when the hash chain is broken
- Zero external processes: `strace -f -e trace=execve` shows no execve other than `python3`

---

## 9. Items requiring approval

| ID | Content | Recommendation |
|---|---|---|
| C-1 | The first version is `chmod` only; any other operation rejects the whole plan | Adopt |
| C-2 | `approval_token = plan_hash` (§4) | Adopt |
| C-3 | dry-run validity of 24 hours (G-8) | Adopt |
| C-4 | apply exit codes 4 (rolled back) / 5 (rollback failed) | Adopt |
| C-5 | Python 3.11+ standard library only, no external commands | Adopt |
| C-6 | Depends on ZET design A-4 (`reversible` / `skillpact_effects` received in the plan) | Approve together with ZET |


---

## 10. Phase 1 remediation operations (implementation of the remediation capability extension, design 0.2)

### 10.1 Flow

1. ZES detects (findings 1.0; ZES has not implemented the 1.1 fields)
2. `zet draft` attaches proposals to each finding (`constraints.suggested_actions`: `auto` and `checklist`). The decider adopts them
3. `ger preview` fills the params of the adopted actions from the current files (quarantine hashes and type; edit ops, `before_sha256`, `file_sha256`, `expected_after_sha256`). Rejected ones (a dist-info without RECORD, dotted TOML keys and so on) get their reason in `--report`. The decider switches them to checklist
4. `zet finalize` -> approval (`approval_token = plan_hash`) -> `ger dry-run` -> `ger apply`
5. The worker does the remaining manual work (checklists and followups) and records it with `ger confirm`. Rescan with ZES
6. If something must be moved back, `ger restore` (2 approvers)

Approvers approve "the exact bytes after the change" (`expected_after_sha256`) and "the exact hash of what is quarantined". apply stops if its recomputed result differs from these.

### 10.2 Tables of definition T (narrowing only) (`ger/hazards.py`, version `ger-hazards-3`)

| Operation | H (units that may be removed, per file type) | K (constants that may be added) |
|---|---|---|
| edit_json / disable_mcp_server | `mcp.server`: `/mcpServers/<name>`, `/servers/<name>`, `/projects/<p>/mcpServers/<name>` (value is an object) in MCP settings (`.mcp.json` / `mcp.json` / `mcp_config.json` / `.claude.json` / `claude_desktop_config.json`). Automatic selection in preview takes only servers matching `MCP_DANGER`, a copy of `MCP_DANGER_RE` from ZES §17 (case-insensitive; each line of the command split at newlines) (ger-hazards-2. -1 covered only shell -c, node -e, python -c and powershell -enc, so it could not automatically remove ZES round 3's `cmd /c`, `deno eval`, `node --eval`, `bash --norc -c`, `-xc`, `perl -e`, `ruby -e`, `pwsh -Command`. ger-hazards-3: ASCII-only `\s` and case folding like grep in the C locale, the pwsh branch in linear time, command / args built like ZES (jq `tostring` for non-strings, NUL dropped; in TOML only strings, control characters as spaces)) | — |
| edit_json | `npm.lifecycle`: `/scripts/(preinstall\|install\|postinstall\|prepare\|…)` in `package.json` | — |
| edit_json | `claude.hook`: `/hooks/<Event>/<i>` (and `/hooks/<Event>/<i>/hooks/<j>`) in `.claude/settings(.local).json` | — |
| edit_json | `vscode.task_run_on`: `/tasks/<i>/runOptions/runOn` in `.vscode/tasks.json` (value `folderOpen`) | `"default"` |
| edit_toml / disable_mcp_server | `mcp.server.toml`: `[mcp_servers.<name>]` in `.codex/config.toml` | — |
| remove_line | `sh.ld_preload` / `sh.curl_pipe_sh` / `sh.base64_pipe_sh` / `sh.histfile_null` (shell rc), `git.exec_key` (`fsmonitor` / `sshCommand` / `hooksPath`), `php.auto_prepend`, `ldso.entry`, `cron.fetch_exec` (`/etc/cron.d/*`). The whole line must match | — |
| quarantine | The finding's target itself, or a target derived by a relation of §10.3 | — |

`MCP_DANGER` and the hook pattern `DANGEROUS_CMD` are matched by linear-time scanners (`hazards.mcp_danger` / `hazards.dangerous_cmd`; round 5), since a file of up to 1 MB from the scanned tree is matched: a head, the maximal run of `-` tokens after it (possessive), and flags written so they cannot backtrack. They give the same result as the regular expressions (kept in the comments and in `tests/test_hazards.py`, which compares them on a random corpus), so the table version does not change.

Anything not in the table (`permissions.deny`, `ignore-scripts=true` in `.npmrc`, `disable_functions` and so on) cannot be removed. T-3 is checked with `json.loads` for JSON, with `json.loads` after removing comments and trailing commas by a separate path for JSONC, with `tomllib` for TOML, and for text by checking that the bytes other than the removed lines match. It is checked on both dry-run and apply.

### 10.3 Relations and G-9

| relation | Lexical condition (same as ZET I-4) | What GER checks on the file system |
|---|---|---|
| `self` | target == finding_path. Quarantining only a dist-info / egg-info, `node_modules/**/package.json`, `Extensions/**/manifest.json` or `skill.contract.json` is rejected (Q-6) | Type and hash |
| `npm_pkg_dir` | finding_path == target + `/package.json`, the parent of target is `node_modules` (the grandparent for scoped packages) | name / version in `package.json` match `params.subject`, and name matches the directory name |
| `npm_installed` | The finding is a lockfile, and target is the `node_modules/<name>` next to it (including nested ones) | Same as above |
| `pypi_record` | target == finding_path (`*.dist-info`) | RECORD exists. Each member under site-packages is a regular file matching the sha256 in RECORD (a member other than .pyc without a hash is rejected). Members outside site-packages are not moved and are listed in preview |
| `ext_dir` | finding_path is `…/Extensions/<id>[/<ver>]/manifest.json`, target is `…/Extensions/<id>` | manifest.json parses as JSON |
| `skill_dir` | target == finding_path, or finding_path is the `skill.contract.json` of target | `skill.contract.json` or `SKILL.md` exists |
| `none` | target is null (checklist only) | — |

In a group (several findings on the same target), the relation of every item is checked lexically and on the file system, not only the first (items with different finding_path values are mixed).

### 10.4 Quarantine store (Q-2)

- Location: `GER_QUARANTINE_DIR`, otherwise `$XDG_STATE_HOME/ger/quarantine`, otherwise `~/.local/state/ger/quarantine`. Resolved to a real path at startup. Owned by the executing user, mode 0700, marker `.ger-quarantine-store`
- Layout: `<store>/<run_id>/<seq>/{payload, manifest.json[, restored.json, rolled_back.json, replaced]}` and `<store>/journal/<run_id>.jsonl`. Names inside are sequence numbers only (nothing is loaded by a name such as `.pth`)
- quarantine: `os.rename(name, "payload", src_dir_fd, dst_dir_fd)` after checking identity. After the move, files become 0400 and directories 0500 (the original mode is kept in the manifest). The manifest (0600) holds the original path, `(dev, ino)`, mode, uid / gid, mtime, hash (also the hash after locking), plan_id / plan_hash, finding_ids and relation; its SHA-256 goes into the audit log
- Edits: a temporary file is created in the same directory with `O_CREAT|O_EXCL|O_NOFOLLOW`, written with the original mode (and uid / gid as root) and fsynced -> the original file is `os.link`ed into the store (backup; the original i-node is kept as it is) -> rename after checking identity. After applying, the SHA-256 must match `expected_after_sha256` (V)
- A target on a different device is rejected (rename / link would not be atomic). **Deviation**: per-device stores (`GER_QUARANTINE_DIRS`) are not implemented in Phase 1. Set one store on the same device with `GER_QUARANTINE_DIR`
- GER deletes nothing from the store. Deletion (purge) is done by hand by the worker after checking with `ger quarantine-list`. After that, neither restore nor rollback is possible
- Excluding the store from ZES scans needs a change on the ZES side (do not scan directories with `.ger-quarantine-store`; not implemented). Until then, place the store outside ZES's `--root` (G-9 rejects a store under `scope.roots`)

### 10.5 restore (Q-4)

`restore-request.json` (`schemas/restore-request.schema.json`) has `restore_id`, `entries[{quarantine_id, manifest_sha256}]` and `approval{approved_by (2 or more), approved_at, approval_token}`. `approval_token` is the SHA-256 of the canonical JSON without approval and mode. A successful dry-run record is required and is used up by one apply (the audit log commands are `restore-dry-run` / `restore-apply`). Preconditions: the SHA-256 of the manifest matches, the store content (hash after locking, object ID) matches the manifest, the original path of a quarantined object is free, and for an edit the current file is still the content GER wrote (`after_sha256`). The edited file before restoring is kept in the store as `replaced`. If something fails halfway, restored objects are quarantined again.

### 10.6 Protected targets and approvers

- Never a target, nor a directory above a target: `/` and the top-level system directories, `$HOME` itself, the GER installation directory (nothing inside either), the Python standard library (except site-packages; nothing inside either), the audit log, the quarantine store and the directories above them
- Under `/etc`, only `/etc/ld.so.preload`, `/etc/hosts` and `/etc/cron.d/*`. Targets that require root need 2 approvers, and plans are split into root plans and the rest
- Number of approvers: 1 for checklist, self quarantine, edits and chmod; 2 for restore, targets that require root, irreversible or destructive operations (none in Phase 1), diff_anomaly and risky effects

### 10.7 checklist and followup

`checklist` params are `{template, steps[{id, text, blocking}], verify?}`. An automatic remediation action carries required follow-up work (CL-IR, CL-SECRET, CL-LAUNCHD, CL-EXT and so on) in `action.followup` (an array of the same shape). ZET decides from the finding which ones are required and does not finalize when one is missing (ZET I-13) (GER does not read findings, so it does not judge whether one is required; it carries them as they are, shows them and records them). `ger confirm` can record only after the successful apply record, and checks that the worker is not an approver (G-4) and that the same step is not recorded twice. When `verify.kind` is `path_absent` / `file_hash_changed`, GER checks before recording (`verified:…`); external work (rotations and so on) is recorded only as `self_attested`.

### 10.8 Tree hash ger-tree-v1 (definition shared with ZES)

Entries (including the root itself as `.`) are sorted in ascending order of the relative path bytes, and the lines
`type \0 relpath \0 mode(4 octal digits, masked with 0o7777) \0 (f: size \0 sha256hex / l: the readlink value / d: empty) \n`
(type is `f` / `l` / `d`) are concatenated; the SHA-256 is written as `sha256:<hex>`. mtime / ctime / uid are not included. A tree with more than 50,000 entries, more than 2 GiB in total, a FIFO, socket or device, a different `st_dev`, or a regular file with `st_nlink > 1` is rejected. The test vector is `TestTreeHashVector` in `tests/test_remediation.py` (`sha256:a0330bed2509e447a89682699b271f59ea236c52316ec21f0e546620de17958e` on Linux).

### 10.9 Deviations from design 0.2

| Item | Design | Implementation | Reason |
|---|---|---|---|
| Scan scope | `ger-input.scope.roots` | `plan.scope` (`roots` and `home`) | To bind it with the approval token (plan_hash). ZET builds it from `policy.scope` of the triage-input (from `scan_roots` of findings in 1.1) |
| Findings whose evidence is detail | Neither quarantine nor edit | Compared with the preview hash fixed in params (part of the approval) and executed | In findings 1.0 the evidence of directories and links is always detail (aligned with "1.0 directories use the preview hash" in design §3.0) |
| evidence.hash match within a group | Required | Required only between items with the same `finding_path`, and only for content-based evidence (file / tree / symlink). Not compared between items with different `finding_path` values. The evidence of every item is derived again from its own `finding_path` and compared (G-7, per item, all items). The relation of each item of a group is also checked one by one (G-9) | detail evidence is a hash of each finding's wording and does not match. In findings 1.1, findings on different files are grouped on one target (skill_dir: the directory tree and the `skill.contract.json` file; npm: `node_modules/<name>/package.json` and a lockfile). Hashes of different files cannot match, and requiring a match guarantees nothing. The guarantee (unchanged since detection) is kept by the per-item check |
| edit_toml | Phase 2 | Implemented within Phase 1 scope (standard table headers) | Owner's instruction |
| Journal | All operations | quarantine and edits (a chmod-only plan creates no journal and rolls back in process as before) | So that chmod-only users do not get a quarantine store |
| Per-device stores | `GER_QUARANTINE_DIRS` | Not implemented (a different device is rejected) | Rejection is enough for Phase 1 |
| params checks | G-7 | G-1 (`actions.schema.json` and the meaning checks of the operation) | Aligned with the G-1 row of design §4.3 |
| INFO deadline | — | The `due_at` of an INFO item put into a quarantine group uses the LOW deadline | Policies often have no INFO deadline |

### 10.10 ZES findings and their Phase 1 handling (E2E results)

For the result of copying ZES's `tests/fixtures` (`origin/main` 98ee340) and running ZES -> ZET -> GER -> ZES end to end, see the "E2E" table in the README (`tests/run-e2e.sh`).

### 10.11 Changes on the ZES side (findings 1.1; not applied)

ZES was not changed this time. ZET and GER work with findings 1.0 and accept the 1.1 fields as optional. Changes to apply to ZES:

1. `schemas/findings.schema.json`: copy ZET's `schemas/vendor/findings-1.1-draft.schema.json` (ZET 2ab7a53) as the master (restore `$id`, title and description to ZES's). The differences are `schema_version` `"1.1"`, `scan_roots` at the top level (array of the real paths of `--root`), and optional `kind`, `subject`, `locators`, `related`, `evidence` on findings
2. `tests/run-tests.sh`: add `scan_roots` to `REQUIRED_TOP`. Compare finding keys as `(keys - ["skillpact","kind","subject","locators","related","evidence"])`
3. `emit()` (`zes-scan.sh` 230-260): an optional sixth argument (a JSON fragment) adds kind / subject / locators / related. The id formula (`module|campaign|path|detail`) and `evidence_hash` do not change (keeps the comparison with `tests/expected`). Always emit `evidence`: `file` for regular files (`large_file` above 100MB) with the same value as the current `evidence_hash`, `symlink` for symbolic links with the SHA-256 of the readlink value (bytes), `tree` for directories with ger-tree-v1 (§10.8; add the test vector `sha256:a0330bed…958e` to ZES's tests too), `detail` otherwise
4. Per module (those used in Phase 1):
   - §15 (768-801): `kind` = `pkg.compromised` (compromised package) / `pkg.vulnerable` (vulnerable version) / `pkg.lockfile_compromised` (compromised version in a lockfile), `subject` = `{ecosystem, package, version, safe_version, fixed_versions}`. A lockfile finding gets `related: [{relation: "npm_installed", path: "<dir>/node_modules/<name>"}]` if the `node_modules/<name>/package.json` next to it exists
   - §17 (2043-2068): `kind` = `mcp.dangerous_command` / `mcp.unpinned`, `locators` = `{format: json|jsonc|toml, pointer: "/mcpServers/<name>"}` per matching server (`"/mcp_servers/<name>"` for TOML; problems of the same kind in the same file are currently one finding, so locators lists several). SymJack has `evidence.kind = symlink`
   - §7 (1601-1612): hooks get `locators: [{format: json, pointer: "/hooks/<Event>/<i>"}]`, `runOn` gets `"/tasks/<i>/runOptions/runOn"`
   - php.ini in §10 / §31 / §26 / §4: `locators: [{format: text, line, line_sha256}]` (the line SHA-256 is over the bytes without the newline, CR and the BOM of line 1; same as GER's remove_line)
   - §24: `related: [{relation: "ext_dir", path: "…/Extensions/<id>"}]` (**change from design 0.2**: if the evidence were the tree hash of ext_dir, it would not match because GER compares it as the evidence of finding_path (manifest.json). The evidence stays the manifest file, and the tree is fixed by `tree_sha256` in preview)
   - §49: a divergence (path is the skill directory) gets `evidence.kind = tree`; a `skill.contract.json` finding gets `related: [{relation: "skill_dir", path: <dir>}]`
   - §21 / §22 / §28 / §47 / §3 §5 §6 §16 §37 §41: `kind` (`gha.pwn_request`, `gha.unpinned`, `secret.token`, `runtime.cve`). ZET I-13 narrows the operations by this kind
5. Do not scan the quarantine store: prune directories with `.ger-quarantine-store` in every `find`
6. Change "no reaching up to parent directories" in `docs/skill-contracts.md:156` to "only targets that can be derived by a `relation`; nothing else is reached" (the principle of not outputting file contents in `:184` does not change)
7. When ZES emits 1.1: replace ZET's `schemas/vendor/findings-1.1-draft.schema.json` with a copy of ZES's `schemas/findings.schema.json`, remove `status: draft` from VENDOR.json and fill in `source_commit` (GER does not read findings, so no change is needed in GER)
