<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/ger-logo-dark.svg">
    <img src="brand/logo/ger-logo-light.svg" alt="gated-exec remediation" height="72">
  </picture>
</p>

English | [日本語](README.ja.md)

# gated-exec-remediation (GER)

**Gated-Exec Remediation** is the remediation layer of [Zero-Exec Shield (ZES)](https://github.com/kajisho5/zero-exec-shield). It executes a remediation plan finalized by [ZET (zero-exec-triage)](https://github.com/kajisho5/zero-exec-triage) only when every gate passes. It is the only one of the three layers that makes changes.

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER] remediation-log.json
        検知（実行なし）        判断（実行なし）              修復（ゲート付き実行）
```

(Detection, no execution → decision, no execution → remediation, gated execution.)

- **Gates G-1 to G-10**: if any single gate fails, nothing is changed
- **Approval is bound to the plan's content**: `approval_token` is the finalized plan's `plan_hash`. Changing the plan after approval stops execution (this proves integrity, not authenticity; see [Approval](#approval))
- **dry-run is mandatory**: apply is refused unless there is an unused successful dry-run record for the same input (within 24 hours by default); each dry-run record authorizes one apply
- **Remediation only tightens** (definition T): a removal must match GER's own closed table of hazard patterns, evaluated by GER against the current file; additions may only come from a closed table of constants; and the edited file is re-parsed and must equal "before minus the removed units". A chmod may not add any permission bit
- **Nothing is ever deleted**: quarantined files and the pre-edit version of every edited file stay in a private quarantine store and can be put back with `ger restore`
- **Full rollback**: if even one item fails, the remaining items are not executed and those already applied are reverted in reverse order; a journal lets `ger recover` undo a run that crashed half-way
- **No external processes, no network**: moves are `os.rename`, backups `os.link`, chmod `os.fchmod`. Python 3.11+ standard library only; the tests check every command with strace
- **Phase 1 actions**: `quarantine`, `edit_json` (JSON / JSONC), `edit_toml` (Phase 1 subset), `remove_line`, `disable_mcp_server`, `checklist` and `chmod`, plus `ger restore`. A plan containing anything else (`write_config`, `rotate_secret`, `replace_token`, …) is rejected as a whole

## What GER fixes, and what it does not

Being honest about this matters more than the count. "Auto" below means GER makes the change and the ZES finding goes away on a re-scan. It does **not** mean the incident is over: every auto fix of a malware indicator carries mandatory follow-up checklist items (incident response, secret rotation, `launchctl bootout`, …) that a person must do and record with `ger confirm`.

| | What | How |
|---|---|---|
| **Auto** | Malicious payloads, droppers, `.pth` startup hooks, IoC files, malicious git hooks, SymJack symlinks, poisoned MCP tool definitions, eBPF/LD_PRELOAD scripts | `quarantine` (the file, tree or link itself) |
| **Auto** | Compromised packages installed under `node_modules/<name>`; browser extensions (`Extensions/<id>`, all versions); skills with a SkillPact divergence or diff anomaly; a compromised `*.dist-info` **only when it has a RECORD** (GER then moves every file the RECORD lists under site-packages) | `quarantine` with a relation (`npm_pkg_dir`, `npm_installed`, `ext_dir`, `skill_dir`, `pypi_record`) |
| **Auto** | Dangerous MCP servers in `.mcp.json`, VS Code `mcp.json` (JSONC), `~/.claude.json`, Cursor/Windsurf; Codex `.codex/config.toml` servers defined with standard table headers | `disable_mcp_server` |
| **Auto** | `package.json` install lifecycle scripts; Claude Code `hooks` entries that run a local script or a download; VS Code `runOn: folderOpen` (set to `default`) | `edit_json` |
| **Auto** | Shell-rc lines (`LD_PRELOAD=`, `curl … \| sh`, `base64 -d \| sh`, `HISTFILE=/dev/null`), git `fsmonitor` / `sshCommand` / `hooksPath`, php.ini `auto_prepend_file`, `ld.so.preload` entries, `/etc/cron.d` fetch-and-run lines | `remove_line` (top-level single lines only) |
| **Auto** | LaunchAgent/LaunchDaemon plists, systemd user units | `quarantine` of the file — **plus** the CL-LAUNCHD / CL-SYSTEMD checklist, because the job that is already loaded keeps running until someone runs `launchctl bootout` / `systemctl stop` |
| **Checklist** | Lock files and requirements files (compromised or vulnerable versions), `*.egg-info` and RECORD-less `*.dist-info`, server/runtime/CVE upgrades (GitLab, TeamCity, Jenkins, PHP, Node.js, CA bundles…), GitHub Actions pwn requests and unpinned actions/images, `npx`/`uvx` unpinned MCP servers, Codex TOML servers defined with dotted keys or inline tables, crontab, environment variables, `.env` files, secrets and tokens, shell history, build hooks, `trust_remote_code`, cosign flags, SBOMs | `checklist` with concrete steps (CL-PKG, CL-VENV, CL-UPGRADE, CL-PHP, CL-PWN, CL-PIN, CL-MCP-PIN, CL-CRON, CL-ENV, CL-SECRET, CL-IR, CL-REVIEW…) |
| **Never automated** | Hand-editing lock files; resolving tags to SHAs or versions to digests over the network; installing/upgrading packages, OS updates, image rebuilds; revoking or rotating secrets; `launchctl` / `systemctl` / `crontab` / `bpftool` / `rmmod` and killing processes; rewriting git history, pushing, disabling workflows on GitHub; purging the quarantine store; code-semantic fixes; editing shell history (it is evidence) | Out of scope by design: these need external processes, the network, or a human decision, or cannot be undone |

Run on ZES's own fixtures (53 fixture trees, 331 findings including the shared test home), Phase 1 removes 80 findings automatically; the remaining 251 are exactly the planned checklist (185), defer / exception (47) and held (19) items, and `ger restore` brings all 331 back (see [End to end](#end-to-end-zes--zet--ger--zes)).

## Usage

```bash
bin/ger verify  ger-input.json --operator ops
bin/ger dry-run ger-input.json --operator ops -o dry-run-log.json
bin/ger apply   ger-input.apply.json --operator ops -o apply-log.json   # mode だけ "apply" に変えた入力
bin/ger verify-log

# Phase 1
bin/ger preview draft-plan.json --operator alice -o previewed-plan.json --report preview-report.json [--diff]
bin/ger confirm ger-input.apply.json --operator ops --item <finding_id> --step CL-IR:s1
bin/ger quarantine-list [--json] [--plan-id ID]
bin/ger restore restore-request.json --operator ops -o restore-log.json      # mode "dry-run" first, then "apply"
bin/ger recover ger-input.apply.json --operator ops -o recover-log.json
```

The Phase 1 flow is: `zet draft` (suggests an auto action and a checklist per finding) → the decider adopts suggestions → `ger preview` fills in the exact hashes, ops and `expected_after_sha256` from the current files (read-only; anything it cannot do safely is reported with the reason, and the decider switches that finding to its checklist) → `zet finalize` → approval → `ger dry-run` → `ger apply` → re-scan with ZES. The approvers therefore approve the exact bytes after the change. `--diff` prints unified diffs to the terminal only; diffs and removed lines are never written to any log.

(`ger-input.apply.json` is the same input with only `mode` changed to `"apply"`. `verify-log [LOG]` verifies the audit log's hash chain: exit code `0` intact, `3` broken, `64` missing or unreadable; it is read-only and not itself logged.)

Input ([schemas/ger-input.schema.json](schemas/ger-input.schema.json)):

```json
{
  "schema_version": "1.0",
  "plan": { "...": "ZET の確定 remediation-plan.json" },
  "approval": {
    "plan_id": "<plan.plan_id>",
    "approved_by": ["security-lead"],
    "approved_at": "2026-10-22T11:00:00Z",
    "approval_token": "<plan.plan_hash>"
  },
  "mode": "dry-run",
  "allowed_actions": ["chmod"]
}
```

(`plan` holds ZET's finalized remediation-plan.json.)

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 3 | Rejected by a gate (nothing changed) |
| 4 | Failed during execution; everything rolled back |
| 5 | Rollback could not be completed either, or changes were applied but the remediation-log could not be written (manual action required) |
| 64 / 70 | Usage or environment error / internal error |

Environment variables: `GER_QUARANTINE_DIR` (quarantine store, default `$XDG_STATE_HOME/ger/quarantine` or `~/.local/state/ger/quarantine`), `GER_LOG_DIR` (audit log, default `$XDG_STATE_HOME/ger/`, or `~/.local/state/ger/` when `XDG_STATE_HOME` is unset; resolved to its real path once at startup, and all log I/O goes through the resolved path), `GER_DRYRUN_TTL` (validity of a dry-run record in seconds, default 86400, maximum 604800), `GER_APPROVAL_MAX_AGE` (validity of an approval in seconds from `approved_at`, default 604800 = 7 days, maximum 31622400).
`--now` (overrides the current time) is test-only and is accepted only when `GER_ALLOW_NOW_OVERRIDE=1` is set (otherwise exit code 64). A run with `--now` is recorded in the audit log with `now_override: true`. G-8 counts only dry-run records made the same way: an apply without `--now` counts only dry-runs without `--now`, and an apply with `--now` counts only dry-runs with `--now` (so an expired real record cannot be brought back into its TTL with `--now`). A plan that ZET drafted or finalized with `--now` carries `now_override: true` and is refused (G-2) unless `GER_ALLOW_NOW_OVERRIDE=1`.

The `-o` destination is checked before any change begins: it must not be empty or end with `/`, its parent directory (taken from the path as given) must exist and be writable, if it already exists it must be a regular file (a directory, FIFO, socket, device such as `/dev/null`, or symbolic link is refused; a symbolic link is refused rather than followed because the log is written by atomic rename, which would replace the link itself), and it must not be the same file as the audit log, a file inside the audit log directory, an input file, or any target of the plan, and no target of the plan may be its parent directory or any ancestor of it, taken both from the path as given (including a directory that holds a symbolic link on the way) and from its real path (otherwise the remediation-log could not be written after apply). Because the comparison uses the real path and, for existing files, `st_dev`/`st_ino`, it is rejected even via symbolic links in the parent path or via hard links. A violation yields exit code 64; a collision with the plan's targets is only discovered after the input has been read, so it is recorded in the audit log as `result: "error"` with the reason. The remediation-log is written before the audit log, and if it cannot be written the run is not recorded as a success and any earlier file at the `-o` path is removed so that it is not mistaken for this run's log (exit code 5 when apply may have left changes in place; the audit log records `result: "applied_unlogged"` when every change was applied and no rollback was attempted, and `rollback_failed` only when a rollback failed).

## Approval

`approval_token` must equal the finalized plan's `plan_hash` (the SHA-256 of its canonical JSON), and `approval.plan_id` must match the plan. This proves **integrity only, not authenticity**: it shows that the plan has not changed since someone computed the hash, not that ZET produced it or that the approvers saw it. A plan edited after `zet finalize` and re-hashed (with `approval_token` updated to match) is **not detected cryptographically**. Detecting that needs approvers' signatures over the plan, which is future work.

To limit what such a plan can do, GER re-checks every ZET invariant that can be evaluated from the plan alone (G-1: the I-4 action shape and target form, I-5 / I-6 / I-7 against the `skillpact` summary ZET copies into each item, approver counts, self-approval, date ordering and more; see the G-1 row), only lets a chmod remove permission bits compared with the target's current mode (G-7), checks `evidence` / `evidence_hash` against the current file when present (G-7), evaluates its own hazard tables and the re-parse check on the current content rather than trusting the plan (G-10), and re-derives each relation from the filesystem and keeps every target inside the approved `plan.scope` and away from protected paths (G-9). What GER cannot check without the findings is that `finding_path` really is a path ZES reported; so a tampered, re-hashed plan can still pick a different target inside the scope, but it can only remove units that match GER's hazard tables (or tighten permissions), every such change is kept in the quarantine store and can be restored, and it can never add a command, URL or path. An approval also expires `GER_APPROVAL_MAX_AGE` seconds after `approved_at` (default 7 days), and a plan is refused once the current time is past the largest `due_at` of its remediate items.

## Actions (Phase 1)

| Action | params (filled by `ger preview`) | Notes |
|---|---|---|
| `quarantine` | `{kind: file, sha256}` / `{kind: tree, tree_sha256}` / `{kind: symlink, link_target}`; `subject` for npm relations, `record: true` for `pypi_record` | Moved with `os.rename` into the store; files become 0400 and directories 0500 there (original modes are in the manifest). Refused for hard-linked files, FIFOs/sockets/devices, a target on another device than the store, or a metadata-only target (a `.dist-info` alone, a `node_modules/*/package.json` alone, …) |
| `edit_json` | `{format: json\|jsonc, ops: [{op: remove\|replace_const, pointer, before_sha256, const?}], file_sha256, expected_after_sha256}` | GER's own lexer keeps formatting and comments. Duplicate keys are refused |
| `edit_toml` | `{ops: [{op: remove_table, key_path, before_sha256}], file_sha256, expected_after_sha256}` | Phase 1 subset: only `[mcp_servers.<name>]` tables defined by standard headers (and their sub-tables). Dotted keys and inline tables are refused |
| `remove_line` | `{lines: [{n, sha256, pattern_id}], file_sha256, expected_after_sha256}` | The whole line must match the pattern. Refused inside heredocs, functions, `if`/`case`/loops, or continued lines. CRLF and BOM are preserved |
| `disable_mcp_server` | as `edit_json` (`format` json / jsonc) or `edit_toml` (`format: toml`) | Only MCP server definitions can be removed |
| `checklist` | `{template, steps: [{id, text, blocking}], verify?: {kind}}` | No file is changed; the result is `pending_manual`. `target` may be null (crontab, environment variables) |
| `chmod` | `{mode: "0NNN"}` | Unchanged from 0.1 |

Several findings on the same file (for example the §2 and §15 findings on one `package.json`) share an `action.group` and are applied as one transaction with a single write. Steps run in this order: edits that remove references → quarantine → chmod → checklist.

**Relations** (`action.relation`): `self`, `npm_pkg_dir`, `npm_installed`, `pypi_record`, `ext_dir`, `skill_dir`, or `none` (checklist without a target). ZET checks the lexical condition; GER re-derives the relation from the filesystem (for example `node_modules/<name>/package.json` must name the package in `params.subject`, and every RECORD member must match its sha256).

**Quarantine store**: `~/.local/state/ger/quarantine` (0700, marker file `.ger-quarantine-store`), laid out as `<run_id>/<seq>/{payload, manifest.json}` plus `journal/<run_id>.jsonl`. GER never deletes anything from it; purging is a manual step, after which restore and rollback are impossible. Until ZES learns to skip the marker, keep the store outside ZES's `--root` (GER refuses a store under `plan.scope.roots`).

**Restore** (`ger restore`, outside the plan): a restore-request lists `quarantine_id` and `manifest_sha256` for each entry (from `ger quarantine-list --json`) and needs **2 approvers**, a dry-run first, and a token over its content. GER checks that the stored payload still matches its manifest, that the original path is free (or, for an edit, that the file is still exactly what GER wrote), and puts things back; the version it replaces is kept in the store.

**Checklists**: `ger apply` prints the remaining manual steps. `ger confirm` records one step at a time in the audit log, only after a successful apply, never by an approver; where a local check is possible (`verify: path_absent` / `file_hash_changed`) GER performs it, otherwise the record says `self_attested`, never "verified".

**Approvers**: 1 for checklist, `self` quarantine, edits and chmod; **2** for `restore`, targets that need root (system directories, or files not owned by the running user; such plans must not mix root and non-root targets), irreversible or destructive actions (none exist in Phase 1), SkillPact diff anomalies and skills declaring risky effects.

## Gates

| # | Rejected when |
|---|---|
| G-1 | Schema mismatch (strict and version-pinned for both input and plan; `params` must match [schemas/actions.schema.json](schemas/actions.schema.json) and the action's own checks; a plan 1.0 may only contain chmod; a plan 1.1 action needs `relation`, `finding_path` and `evidence`, and only a checklist may have a null target; `skillpact_effects` may hold only the six SkillPact 0.8 effects), the input contains `findings`, mode does not match the command, a remediate item has a duplicate `finding_id` (results could not be mapped one-to-one to items), `approved_at` / `created_at` / any item timestamp is a nonexistent date-time (February 30, hour 25, etc.), or an object in the input JSON has duplicate keys or nesting deeper than 64 levels. Also the ZET invariants that need no findings or policy (messages say `ZET I-n 相当`): a finding_id appears more than once across items and held (I-1); an exception without exception_type / reason / recheck_at or without an approver, exception_type on a non-exception, a non-INFO defer without reason / recheck_at, or the decider among the item's approvers (I-3); a remediate without owner / due_at / action, an action on a non-remediate, or a target that is not a normalized absolute path (no `.`, `..` or repeated `/`, including a leading `//`) (I-4); a divergence finding as an exception (I-5), duplicate item approvers, fewer than 2 item approvers for a diff_anomaly finding or for a remediate whose skill declares exec / network / spend / send (I-6), a signed finding with a divergence below CRITICAL (I-7), or `skillpact_effects` differing from the item's `skillpact.declared_effects`; decided_at before created_at or in the future, or due_at / recheck_at before decided_at (I-9); a partial plan with an empty held (I-12) |
| G-2 | plan.status is anything other than ok / partial (draft, error); the plan carries `now_override: true` (made by ZET with `--now`) and `GER_ALLOW_NOW_OVERRIDE` is not `1`; or the current time is past the largest `due_at` of the remediate items (the plan has expired; triage again in ZET) |
| G-3 | plan_hash does not match the body, approval.plan_id does not match, approval_token ≠ plan_hash, approved_at is in the future or before the plan was created, or the approval is older than `GER_APPROVAL_MAX_AGE` seconds (default 7 days) |
| G-4 | `--operator` is among the approvers (names are compared case-insensitively) |
| G-5 | The action is not in allowed_actions, or GER does not support it |
| G-6 | A target that needs root, or an irreversible or destructive action, has fewer than 2 approvers (plan 1.1 requires 2 on the item too). reversible / skillpact_effects ([SkillPact](https://github.com/kajisho5/skillpact) effects) is missing (not finalized by ZET), reversible does not match the nature of the action, an irreversible action has fewer than 2 approvers, or an action on a skill that declares a risky effect (exec / network / spend / send) is not listed in allowed_actions or has fewer than 2 approvers (approvers are `approval.approved_by`; names differing only in case count as the same person). ZET's I-6 requires the same 2 approvers on the item |
| G-7 | The target is not a normalized absolute path, does not exist, has a symbolic link or non-directory as an intermediate component (GER walks the path from `/` one component at a time with `O_PATH\|O_NOFOLLOW\|O_DIRECTORY` and keeps the parent fd until apply), is not what `ger preview` saw (`sha256` / `tree_sha256` / `link_target` / `file_sha256` / `before_sha256`, or the recomputed result differs from `expected_after_sha256`), overlaps another item's target outside a group, is on another device than the quarantine store, is a symbolic link where a file is expected, is not a regular file/directory, is not owned by the user, is the audit log, the audit log directory or any of their ancestors (both the ancestors of `GER_LOG_DIR` as given, including directories holding a symbolic link on the way, and those of its real path; changing them would stop GER from recording the run), or is duplicated within the plan (including hard links to the same underlying file); the chmod mode does not match `^0[0-7]{3}$`, is world-writable, or adds any permission bit compared with the target's current mode (remediation may only tighten); or `action.evidence_hash` is present and does not match the current file (computed with the ZES rule: the SHA-256 of the content for a regular file up to 100 MB, of `path\|size\|mtime` above 100 MB; not compared for a directory, for which ZES hashes the finding's detail) |
| G-9 | Scope and relation: a file-changing action other than chmod without `plan.scope`, or a target outside `scope.roots` / `scope.home`; the quarantine store under a scope root, site-packages, node_modules or a `PATH` directory; a protected target (`/` and top-level system directories, `$HOME` itself, GER's own installation, the Python standard library, the audit log, the store, or an ancestor of any of these; under `/etc` only `ld.so.preload`, `hosts` and `cron.d/*`); a root-only target with fewer than 2 approvers, or root-only and normal targets in one plan; or the `relation` does not hold lexically or on the filesystem |
| G-10 | Definition T: a removed unit is not in GER's hazard table H (T-1), an added value is not in the constant table K (T-2), the re-parsed result differs from "before minus removed units" (T-3), or the fix would remove only the metadata ZES detects while leaving the code (Q-6) |
| G-8 | On apply, there is no unexpired, unused successful dry-run record with the same plan_hash, the same input (apart from mode) and the same use of `--now`, or the audit log's hash chain is broken (a line that is not a UTF-8 JSON object also counts as broken). A dry-run record is used up by the first later apply of the same plan and input that went ahead (result `ok`, `rolled_back`, `rollback_failed` or `applied_unlogged`); a rejection or a usage error before any change does not use it |

During execution, a change is made only if the object's identity matches the one captured during pre-validation (`st_dev`, `st_ino`, `st_ctime_ns`). Because inode numbers can be reused after deletion and re-creation, ctime is included to determine that it is the same object.

## Schemas

| File | Owner | Description |
|---|---|---|
| [schemas/remediation-log.schema.json](schemas/remediation-log.schema.json) | **GER** | Output contract (adds `mode` and `plan_hash` to contract §6; 1.1 adds `pending_manual`, `group`, `quarantine_ids`, `followup`) |
| [schemas/ger-input.schema.json](schemas/ger-input.schema.json) | GER | Input |
| [schemas/actions.schema.json](schemas/actions.schema.json) | **GER** | The params of each action. ZET vendors it |
| [schemas/restore-request.schema.json](schemas/restore-request.schema.json) | GER | Input of `ger restore` |
| [schemas/vendor/remediation-plan.schema.json](schemas/vendor/remediation-plan.schema.json) | ZET | Version-pinned copy (source commit and SHA-256 in `schemas/vendor/VENDOR.json`) |

## Audit log

`$GER_LOG_DIR/ger-audit.jsonl`. One record per line (command / operator / plan_id / plan_hash / input_hash / output_hash / started_at / finished_at / result / gate_failed / now_override / prev_hash; an apply also records, per item, the type, target, relation, hashes before and after, ops digest, quarantine ids and manifest hashes; a confirm records the finding, step, operator and verification result). File contents, diffs and removed lines are never logged, only hashes, line numbers and pointers. Rejections are logged too. `bin/ger verify-log` verifies the whole hash chain. Before appending, GER checks the tail link (the last line must end with a newline, be a JSON object and carry the hash of the line before it) and refuses to append to a broken chain, so nothing is executed (exit code 64; inspect with `verify-log` and move the log aside before running again). If the log cannot be written, nothing is executed. Nothing is executed either if the existing log directory is not owned by the running user or is writable by group or others (exit code 64).

## Tests

```bash
tests/run-tests.sh   # 単体テスト＋ strace による外部プロセス・ネットワークゼロ検証
ZES_HOME=/path/to/zero-exec-shield ZET_HOME=/path/to/zero-exec-triage tests/run-e2e.sh   # E2E（ZES が無ければ SKIP）
```

`run-tests.sh` runs the unit tests (every action on real files in a temporary directory: accept and reject cases, rollback after a mid-plan failure, a failed rollback followed by `ger recover`, a crash followed by `ger recover`, restore round trips, tampered plans re-hashed after approval, swapped targets and symlinked parents, a tampered quarantine store, and a fixed test vector for the `ger-tree-v1` tree hash) plus an strace run of every command over a plan with every action type, which must show no `execve` other than bash/python3 and no network system call.

When run as root, the "unreadable file" test is SKIPped (as a regular user it runs too). Schema and plan_hash compatibility are also checked against actual plans finalized by ZET: `tests/fixtures/zet-final-plan.json` (from a ZET release before round 3, without the new optional fields) and `tests/fixtures/zet-final-plan-r3.json` (with `items[].skillpact` and `action.evidence_hash`, which must also pass the ZET invariants GER re-checks in G-1), and `tests/fixtures/zet-final-plan-11.json` (a ZET 0.2 plan 1.1 from the chaindrop E2E, with groups, follow-ups, checklists and the params `ger preview` filled in).

## End to end (ZES → ZET → GER → ZES)

`tests/run-e2e.sh` copies each ZES fixture tree (and its home) to a temporary directory, scans it with `zes-scan.sh` (read-only use of the ZES checkout), runs `zet draft`, adopts the suggestions (auto where possible, otherwise the checklist; `ger preview` rejections fall back to the checklist), `ger preview`, `zet finalize`, approval, `ger dry-run`, `ger apply`, re-scans, then `ger restore` of everything in the store and a third scan. A fixture passes when the re-scan leaves exactly the checklist, defer, exception and held items, and the scan after restore equals the first scan (same finding ids).

Result with ZES v0.4.0 (92be8b7, findings 1.1) and ZET `main` 9792941 (counts are findings; "Auto" are findings whose item GER fixed with a file-changing action, all of which disappeared on the re-scan; "Checklist" are `pending_manual` items; "Held" are findings of modules that ZES reported as errors: §6 skipped offline, and modules that hit a deliberately unparseable input such as a YAML alias in §21, `bun.lockb` in §15 or a malformed `skill.contract.json` in §49):

| Fixture | Before | Auto | Checklist | Defer / exc. | Held | After apply | After restore | Result |
|---|---|---|---|---|---|---|---|---|
| browser-ext | 6 | 4 | 1 | 1 | 0 | 2 | 6 | ok |
| build-hooks | 5 | 0 | 4 | 1 | 0 | 5 | 5 | ok |
| chaindrop | 9 | 5 | 3 | 1 | 0 | 4 | 9 | ok |
| codex-toml | 12 | 7 | 4 | 1 | 0 | 5 | 12 | ok |
| codex-toml-broken | 2 | 0 | 1 | 1 | 0 | 2 | 2 | ok |
| cosign | 3 | 0 | 2 | 1 | 0 | 3 | 3 | ok |
| ebpf | 3 | 1 | 1 | 1 | 0 | 2 | 3 | ok |
| github-actions | 14 | 0 | 13 | 1 | 0 | 14 | 14 | ok |
| gitlab | 12 | 0 | 11 | 1 | 0 | 12 | 12 | ok |
| hf | 6 | 0 | 5 | 1 | 0 | 6 | 6 | ok |
| history | 5 | 0 | 5 | 0 | 0 | 5 | 5 | ok |
| host-paths-home | 8 | 5 | 3 | 0 | 0 | 3 | 8 | ok |
| host-paths-safe | 2 | 0 | 1 | 1 | 0 | 2 | 2 | ok |
| intel-2026q3 | 32 | 3 | 23 | 2 | 4 | 29 | 32 | ok |
| intel-2026q3-safe | 5 | 0 | 3 | 2 | 0 | 5 | 5 | ok |
| ioc-corrections | 14 | 2 | 11 | 1 | 0 | 12 | 14 | ok |
| ioc-corrections-safe | 5 | 0 | 4 | 1 | 0 | 5 | 5 | ok |
| linux | 4 | 2 | 1 | 1 | 0 | 2 | 4 | ok |
| litellm | 10 | 5 | 3 | 1 | 1 | 5 | 10 | ok |
| lockfile-formats | 10 | 0 | 9 | 1 | 0 | 10 | 10 | ok |
| lockfile-installed | 4 | 1 | 2 | 1 | 0 | 3 | 4 | ok |
| macos | 4 | 2 | 1 | 1 | 0 | 2 | 4 | ok |
| mcp | 4 | 1 | 2 | 1 | 0 | 3 | 4 | ok |
| mcp-registry | 4 | 2 | 1 | 1 | 0 | 2 | 4 | ok |
| parser-evasion | 19 | 7 | 11 | 1 | 0 | 12 | 19 | ok |
| php | 8 | 1 | 6 | 1 | 0 | 7 | 8 | ok |
| php2shell | 11 | 0 | 8 | 3 | 0 | 11 | 11 | ok |
| r3-actions | 19 | 0 | 10 | 1 | 8 | 19 | 19 | ok |
| r3-ai-instr | 10 | 0 | 9 | 1 | 0 | 10 | 10 | ok |
| r3-archive | 2 | 0 | 1 | 1 | 0 | 2 | 2 | ok |
| r3-crlf-toolversions | 4 | 0 | 2 | 1 | 1 | 4 | 4 | ok |
| r3-dpkg | 3 | 0 | 1 | 1 | 1 | 3 | 3 | ok |
| r3-hosts-space | 3 | 0 | 2 | 1 | 0 | 3 | 3 | ok |
| r3-ioc-case | 3 | 1 | 1 | 1 | 0 | 2 | 3 | ok |
| r3-lockfiles | 4 | 0 | 1 | 1 | 2 | 4 | 4 | ok |
| r3-mcp-evasion | 11 | 9 | 1 | 1 | 0 | 2 | 11 | ok |
| r3-nul | 4 | 1 | 2 | 1 | 0 | 3 | 4 | ok |
| r3-pkgjson | 6 | 4 | 1 | 1 | 0 | 2 | 6 | ok |
| r3-pth | 5 | 3 | 1 | 1 | 0 | 2 | 5 | ok |
| r3-skillpact-script | 6 | 4 | 1 | 1 | 0 | 2 | 6 | ok |
| r3-symlink-config | 4 | 0 | 3 | 1 | 0 | 4 | 4 | ok |
| r3-vcs-nested | 5 | 3 | 1 | 1 | 0 | 2 | 5 | ok |
| sbom | 5 | 0 | 4 | 1 | 0 | 5 | 5 | ok |
| skillpact-clean | 0 | 0 | 0 | 0 | 0 | 0 | 0 | ok |
| skillpact-diff-anomaly | 1 | 1 | 0 | 0 | 0 | 0 | 1 | ok |
| skillpact-divergence | 3 | 3 | 0 | 0 | 0 | 0 | 3 | ok |
| skillpact-invalid | 2 | 0 | 2 | 0 | 0 | 2 | 2 | ok |
| skillpact-malformed | 2 | 0 | 0 | 0 | 2 | 2 | 2 | ok |
| skillpact-policy | 1 | 0 | 1 | 0 | 0 | 1 | 1 | ok |
| skillpact-signed-divergence | 2 | 2 | 0 | 0 | 0 | 0 | 2 | ok |
| skillpact-undeclared | 1 | 0 | 0 | 1 | 0 | 1 | 1 | ok |
| skillpact-version | 1 | 0 | 1 | 0 | 0 | 1 | 1 | ok |
| symjack | 3 | 1 | 1 | 1 | 0 | 2 | 3 | ok |
| **Total** | **331** | **80** | **185** | **47** | **19** | **251** | **331** | **53/53** |

`ger preview` refused, and the run fell back to the checklist for: Codex `a-dotted-top`, `d-dotted-under-table` and `i-inline-nested` (servers defined with dotted keys or inline tables), litellm's `litellm-1.107.0.dist-info` (no RECORD, so quarantining the metadata alone would leave the code; Q-6), and r3-symlink-config's `ev/.vscode/tasks.json` and `ev/.mcp.json` (the target is a symbolic link; GER does not edit through links).


## License

[Apache License 2.0](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).
