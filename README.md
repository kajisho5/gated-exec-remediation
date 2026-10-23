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

- **Gates G-1 to G-8**: if any single gate fails, nothing is changed
- **Approval is bound to the plan's content**: `approval_token` is the finalized plan's `plan_hash`. Changing the plan after approval stops execution (this proves integrity, not authenticity; see [Approval](#approval))
- **dry-run is mandatory**: apply is refused unless there is an unused successful dry-run record for the same input (within 24 hours by default); each dry-run record authorizes one apply
- **Remediation only tightens**: a chmod may not add any permission bit compared with the target's current mode
- **Full rollback**: if even one item fails, the remaining items are not executed and those already applied are reverted in reverse order
- **No external processes**: even chmod is done with `os.fchmod`. Python 3.11+ standard library only
- **The initial release supports chmod only**: a plan containing `write_config` / `rotate_secret` is rejected as a whole

## Usage

```bash
bin/ger verify  ger-input.json --operator ops
bin/ger dry-run ger-input.json --operator ops -o dry-run-log.json
bin/ger apply   ger-input.apply.json --operator ops -o apply-log.json   # mode だけ "apply" に変えた入力
bin/ger verify-log
```

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

Environment variables: `GER_LOG_DIR` (audit log, default `$XDG_STATE_HOME/ger/`, or `~/.local/state/ger/` when `XDG_STATE_HOME` is unset; resolved to its real path once at startup, and all log I/O goes through the resolved path), `GER_DRYRUN_TTL` (validity of a dry-run record in seconds, default 86400, maximum 604800), `GER_APPROVAL_MAX_AGE` (validity of an approval in seconds from `approved_at`, default 604800 = 7 days, maximum 31622400).
`--now` (overrides the current time) is test-only and is accepted only when `GER_ALLOW_NOW_OVERRIDE=1` is set (otherwise exit code 64). A run with `--now` is recorded in the audit log with `now_override: true`. G-8 counts only dry-run records made the same way: an apply without `--now` counts only dry-runs without `--now`, and an apply with `--now` counts only dry-runs with `--now` (so an expired real record cannot be brought back into its TTL with `--now`). A plan that ZET drafted or finalized with `--now` carries `now_override: true` and is refused (G-2) unless `GER_ALLOW_NOW_OVERRIDE=1`.

The `-o` destination is checked before any change begins: it must not be empty or end with `/`, its parent directory (taken from the path as given) must exist and be writable, if it already exists it must be a regular file (a directory, FIFO, socket, device such as `/dev/null`, or symbolic link is refused; a symbolic link is refused rather than followed because the log is written by atomic rename, which would replace the link itself), and it must not be the same file as the audit log, a file inside the audit log directory, an input file, or any target of the plan, and no target of the plan may be its parent directory or any ancestor of it, taken both from the path as given (including a directory that holds a symbolic link on the way) and from its real path (otherwise the remediation-log could not be written after apply). Because the comparison uses the real path and, for existing files, `st_dev`/`st_ino`, it is rejected even via symbolic links in the parent path or via hard links. A violation yields exit code 64; a collision with the plan's targets is only discovered after the input has been read, so it is recorded in the audit log as `result: "error"` with the reason. The remediation-log is written before the audit log, and if it cannot be written the run is not recorded as a success and any earlier file at the `-o` path is removed so that it is not mistaken for this run's log (exit code 5 when apply may have left changes in place; the audit log records `result: "applied_unlogged"` when every change was applied and no rollback was attempted, and `rollback_failed` only when a rollback failed).

## Approval

`approval_token` must equal the finalized plan's `plan_hash` (the SHA-256 of its canonical JSON), and `approval.plan_id` must match the plan. This proves **integrity only, not authenticity**: it shows that the plan has not changed since someone computed the hash, not that ZET produced it or that the approvers saw it. A plan edited after `zet finalize` and re-hashed (with `approval_token` updated to match) is **not detected cryptographically**. Detecting that needs approvers' signatures over the plan, which is future work.

To limit what such a plan can do, GER re-checks every ZET invariant that can be evaluated from the plan alone (G-1: the I-4 action shape and target form, I-5 / I-6 / I-7 against the `skillpact` summary ZET copies into each item, approver counts, self-approval, date ordering and more; see the G-1 row), only lets a chmod remove permission bits compared with the target's current mode (G-7), and checks `evidence_hash` against the current file when present (G-7). What GER cannot check without the findings is that the target is the path a finding names (ZET's I-4); so a tampered, re-hashed plan can still pick a different target, but can only tighten permissions on a file the operator owns, never loosen them. An approval also expires `GER_APPROVAL_MAX_AGE` seconds after `approved_at` (default 7 days), and a plan is refused once the current time is past the largest `due_at` of its remediate items.

## Gates

| # | Rejected when |
|---|---|
| G-1 | Schema mismatch (strict and version-pinned for both input and plan; `skillpact_effects` may hold only the six SkillPact 0.8 effects), the input contains `findings`, mode does not match the command, a remediate item has a duplicate `finding_id` (results could not be mapped one-to-one to items), `approved_at` / `created_at` / any item timestamp is a nonexistent date-time (February 30, hour 25, etc.), or an object in the input JSON has duplicate keys or nesting deeper than 64 levels. Also the ZET invariants that need no findings or policy (messages say `ZET I-n 相当`): a finding_id appears more than once across items and held (I-1); an exception without exception_type / reason / recheck_at or without an approver, exception_type on a non-exception, a non-INFO defer without reason / recheck_at, or the decider among the item's approvers (I-3); a remediate without owner / due_at / action, an action on a non-remediate, or a target that is not a normalized absolute path (no `.`, `..` or repeated `/`, including a leading `//`) (I-4); a divergence finding as an exception (I-5), duplicate item approvers, fewer than 2 item approvers for a diff_anomaly finding or for a remediate whose skill declares exec / network / spend / send (I-6), a signed finding with a divergence below CRITICAL (I-7), or `skillpact_effects` differing from the item's `skillpact.declared_effects`; decided_at before created_at or in the future, or due_at / recheck_at before decided_at (I-9); a partial plan with an empty held (I-12) |
| G-2 | plan.status is anything other than ok / partial (draft, error); the plan carries `now_override: true` (made by ZET with `--now`) and `GER_ALLOW_NOW_OVERRIDE` is not `1`; or the current time is past the largest `due_at` of the remediate items (the plan has expired; triage again in ZET) |
| G-3 | plan_hash does not match the body, approval.plan_id does not match, approval_token ≠ plan_hash, approved_at is in the future or before the plan was created, or the approval is older than `GER_APPROVAL_MAX_AGE` seconds (default 7 days) |
| G-4 | `--operator` is among the approvers (names are compared case-insensitively) |
| G-5 | The action is not in allowed_actions, or GER does not support it |
| G-6 | reversible / skillpact_effects ([SkillPact](https://github.com/kajisho5/skillpact) effects) is missing (not finalized by ZET), reversible does not match the nature of the action, an irreversible action has fewer than 2 approvers, or an action on a skill that declares a risky effect (exec / network / spend / send) is not listed in allowed_actions or has fewer than 2 approvers (approvers are `approval.approved_by`; names differing only in case count as the same person). ZET's I-6 requires the same 2 approvers on the item |
| G-7 | The target is not a normalized absolute path, does not exist, is a symbolic link (including any intermediate path component), is not a regular file/directory, is not owned by the user, is the audit log, the audit log directory or any of their ancestors (both the ancestors of `GER_LOG_DIR` as given, including directories holding a symbolic link on the way, and those of its real path; changing them would stop GER from recording the run), or is duplicated within the plan (including hard links to the same underlying file); the chmod mode does not match `^0[0-7]{3}$`, is world-writable, or adds any permission bit compared with the target's current mode (remediation may only tighten); or `action.evidence_hash` is present and does not match the current file (computed with the ZES rule: the SHA-256 of the content for a regular file up to 100 MB, of `path\|size\|mtime` above 100 MB; not compared for a directory, for which ZES hashes the finding's detail) |
| G-8 | On apply, there is no unexpired, unused successful dry-run record with the same plan_hash, the same input (apart from mode) and the same use of `--now`, or the audit log's hash chain is broken (a line that is not a UTF-8 JSON object also counts as broken). A dry-run record is used up by the first later apply of the same plan and input that went ahead (result `ok`, `rolled_back`, `rollback_failed` or `applied_unlogged`); a rejection or a usage error before any change does not use it |

During execution, a change is made only if the object's identity matches the one captured during pre-validation (`st_dev`, `st_ino`, `st_ctime_ns`). Because inode numbers can be reused after deletion and re-creation, ctime is included to determine that it is the same object.

## Schemas

| File | Owner | Description |
|---|---|---|
| [schemas/remediation-log.schema.json](schemas/remediation-log.schema.json) | **GER** | Output contract (adds `mode` and `plan_hash` to contract §6) |
| [schemas/ger-input.schema.json](schemas/ger-input.schema.json) | GER | Input |
| [schemas/vendor/remediation-plan.schema.json](schemas/vendor/remediation-plan.schema.json) | ZET | Version-pinned copy (source commit and SHA-256 in `schemas/vendor/VENDOR.json`) |

## Audit log

`$GER_LOG_DIR/ger-audit.jsonl`. One record per line (command / operator / plan_id / plan_hash / input_hash / output_hash / started_at / finished_at / result / gate_failed / now_override / prev_hash). Rejections are logged too. `bin/ger verify-log` verifies the whole hash chain. Before appending, GER checks the tail link (the last line must end with a newline, be a JSON object and carry the hash of the line before it) and refuses to append to a broken chain, so nothing is executed (exit code 64; inspect with `verify-log` and move the log aside before running again). If the log cannot be written, nothing is executed. Nothing is executed either if the existing log directory is not owned by the running user or is writable by group or others (exit code 64).

## Tests

```bash
tests/run-tests.sh   # 単体テスト（一時ディレクトリの実ファイルで chmod・ロールバック・差し替え検出を検証）＋ strace による外部プロセスゼロ検証
```

This runs the unit tests (chmod, rollback and swap detection are verified on real files in a temporary directory) plus strace-based verification that no external process is launched.

When run as root, the "unreadable file" test is SKIPped (as a regular user it runs too). Schema and plan_hash compatibility are also checked against actual plans finalized by ZET: `tests/fixtures/zet-final-plan.json` (from a ZET release before round 3, without the new optional fields) and `tests/fixtures/zet-final-plan-r3.json` (with `items[].skillpact` and `action.evidence_hash`, which must also pass the ZET invariants GER re-checks in G-1).

## License

[Apache License 2.0](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).
