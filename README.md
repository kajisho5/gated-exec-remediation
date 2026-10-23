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
- **Approval is bound to the plan's content**: `approval_token` is the finalized plan's `plan_hash`. Changing the plan after approval stops execution
- **dry-run is mandatory**: apply is refused unless there is a successful dry-run record for the same input (within 24 hours by default)
- **Full rollback**: if even one item fails, the remaining items are not executed and those already applied are reverted in reverse order
- **No external processes**: even chmod is done with `os.fchmod`. Python 3.11+ standard library only
- **The initial release supports chmod only**: a plan containing `write_config` / `rotate_secret` is rejected as a whole

## Usage

```bash
bin/ger verify  ger-input.json --operator ops
bin/ger dry-run ger-input.json --operator ops -o dry-run-log.json
bin/ger apply   ger-input.apply.json --operator ops -o apply-log.json   # mode だけ "apply" に変えた入力
```

(`ger-input.apply.json` is the same input with only `mode` changed to `"apply"`.)

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
| 5 | Rollback could not be completed either (manual action required) |
| 64 / 70 | Usage or environment error / internal error |

Environment variables: `GER_LOG_DIR` (audit log, default `$XDG_STATE_HOME/ger/`, or `~/.local/state/ger/` when `XDG_STATE_HOME` is unset), `GER_DRYRUN_TTL` (validity of a dry-run record in seconds, default 86400, maximum 604800).
`--now` (overrides the current time) is test-only and is accepted only when `GER_ALLOW_NOW_OVERRIDE=1` is set (otherwise exit code 64). A run with `--now` is recorded in the audit log with `now_override: true`, and such a dry-run record does not count towards G-8 for an apply run without `--now`.

The `-o` destination is checked before any change begins: its parent directory must exist and be writable, it must not be an existing directory, and it must not be the same file as the audit log, a file inside the audit log directory, an input file, or any target of the plan. Because the comparison uses the real path and, for existing files, `st_dev`/`st_ino`, it is rejected even via symbolic or hard links. A violation yields exit code 64; a collision with a plan target is only discovered after the input has been read, so it is recorded in the audit log as `result: "error"` with the reason. The remediation-log is written before the audit log, and if it cannot be written the run is not recorded as a success (exit code 5 when apply may have left changes in place).

## Gates

| # | Rejected when |
|---|---|
| G-1 | Schema mismatch (strict and version-pinned for both input and plan), the input contains `findings`, mode does not match the command, a remediate item has a duplicate `finding_id` (results could not be mapped one-to-one to items), `approved_at` / `created_at` is a nonexistent date-time (February 30, hour 25, etc.), or an object in the input JSON has duplicate keys or nesting deeper than 64 levels |
| G-2 | plan.status is anything other than ok / partial (draft, error) |
| G-3 | plan_hash does not match the body, approval.plan_id does not match, approval_token ≠ plan_hash, or approved_at is in the future or before the plan was created |
| G-4 | `--operator` is among the approvers (names are compared case-insensitively) |
| G-5 | The action is not in allowed_actions, or GER does not support it |
| G-6 | reversible / skillpact_effects ([SkillPact](https://github.com/kajisho5/skillpact) effects) is missing (not finalized by ZET), reversible does not match the nature of the action, or an irreversible action has fewer than 2 approvers (names differing only in case count as the same person) |
| G-7 | The target is not a normalized absolute path, does not exist, is a symbolic link (including any intermediate path component), is not a regular file/directory, is not owned by the user, or is duplicated within the plan (including hard links to the same underlying file); or the chmod mode does not match `^0[0-7]{3}$` |
| G-8 | On apply, there is no unexpired successful dry-run record with the same plan_hash and the same input (apart from mode), or the audit log's hash chain is broken (a line that is not a UTF-8 JSON object, such as a torn last line, also counts as broken) |

During execution, a change is made only if the object's identity matches the one captured during pre-validation (`st_dev`, `st_ino`, `st_ctime_ns`). Because inode numbers can be reused after deletion and re-creation, ctime is included to determine that it is the same object.

## Schemas

| File | Owner | Description |
|---|---|---|
| [schemas/remediation-log.schema.json](schemas/remediation-log.schema.json) | **GER** | Output contract (adds `mode` and `plan_hash` to contract §6) |
| [schemas/ger-input.schema.json](schemas/ger-input.schema.json) | GER | Input |
| [schemas/vendor/remediation-plan.schema.json](schemas/vendor/remediation-plan.schema.json) | ZET | Version-pinned copy (source commit and SHA-256 in `schemas/vendor/VENDOR.json`) |

## Audit log

`$GER_LOG_DIR/ger-audit.jsonl`. One record per line (command / operator / plan_id / plan_hash / input_hash / output_hash / started_at / finished_at / result / gate_failed / now_override / prev_hash). Rejections are logged too. If the log cannot be written, nothing is executed. Nothing is executed either if the existing log directory is not owned by the running user or is writable by group or others (exit code 64).

## Tests

```bash
tests/run-tests.sh   # 単体テスト（43 件。一時ディレクトリの実ファイルで chmod・ロールバック・差し替え検出を検証）＋ strace による外部プロセスゼロ検証
```

This runs the unit tests (44; chmod, rollback and swap detection are verified on real files in a temporary directory) plus strace-based verification that no external process is launched.

When run as root, the "unreadable file (0000)" test is SKIPped (as a regular user all 44 tests run). Schema and plan_hash compatibility are also checked against an actual plan finalized by ZET (`tests/fixtures/zet-final-plan.json`).

## License

[Apache License 2.0](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).
