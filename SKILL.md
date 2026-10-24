---
name: gated-exec-remediation
description: Remediation-layer skill of GER (Gated-Exec Remediation). Executes a remediation plan finalized by ZET (remediation-plan.json) only when it passes gates G-1 to G-10 (explicit human approval, dry-run, allowlist). Phase 1 operations are quarantine (move into the quarantine store; nothing is deleted), edit_json / edit_toml / remove_line / disable_mcp_server (remove only what matches GER's hazard tables), checklist (record manual work) and chmod. On failure everything is rolled back, and quarantined objects can be moved back with ger restore. It never approves on anyone's behalf, skips a dry-run, makes changes outside the plan, deletes from the quarantine store, rewrites lockfiles or rotates secrets.
---

# GER remediation skill (gated-exec-remediation)

**Language**: this file is in English, but answer the user in the language they use (for example, reply in Japanese to a user who writes in Japanese). Keep identifiers, paths, JSON keys, gate codes (G-1 to G-10) and command output as they are.

```
[ZET] remediation-plan.json ─┐
human approval (approval) ───┼─▶ [GER] G-1 to G-8 ─▶ dry-run ─▶ apply ─▶ remediation-log.json
allowed_actions ─────────────┘
```

## Absolute rules

1. **Never approve on anyone's behalf**: use only an `approval.approved_by` and `approval_token` that a human gave after looking at the `plan_hash` of the finalized plan. The AI never writes its own name as an approver.
2. **The operator is not an approver**: do not use an approver's name for `--operator` (G-4 rejects it).
3. **Always dry-run before apply**: run a successful dry-run with the same input (except mode), show the result (before / after) to a human, then apply.
4. **Never rewrite the plan**: changing even one character of the plan changes `plan_hash` and invalidates the approval (G-3). If a change is needed, start again in ZET. Recomputing `plan_hash` and asking for a new approval is also forbidden (the approval token only shows integrity and cannot detect a rewrite cryptographically; GER checks again the ZET invariants that can be evaluated from the plan alone and accepts only chmod operations that narrow permissions, but do not rely on that).
5. **Never read or pass findings.json**: the only input of the remediation layer is the finalized plan (G-1).
6. **Never get around a gate**: when rejected, report the reason (the G number) as it is. Do not try to pass by changing the log directory, the TTL or the location of the quarantine store.
7. **A preview rejection becomes a checklist**: do not try to pass an automatic remediation rejected by `ger preview` (a dist-info without RECORD, dotted TOML keys, a JSON file GER cannot parse strictly such as one with a duplicate key or a lone `\ud800` escape, an edit that does not remove what its finding reports, and so on) by writing params by hand. Switch to the checklist of ZET's proposal.
8. **Never delete from the quarantine store**: do not delete or rewrite the contents of `~/.local/state/ger/quarantine` (restore and rollback would become impossible and evidence would be lost). Deletion is a human decision.
9. **restore also needs human approval**: the AI never writes the approvers (2 or more) of a restore-request.
10. **Never fake a checklist confirmation**: record `ger confirm` only after the step was actually done, under the name of the worker who did it. For external work such as a rotation, state in the report that GER cannot verify it and records it as `self_attested`.
11. **Never run what is not automated**: rewriting lockfiles by hand, running `launchctl` / `systemctl` / `crontab`, revoking secrets and rewriting git history are outside GER's scope. Hand them to a human as checklist steps.

## Steps

```bash
# 1. Build the input (a human fills in approval after checking plan_hash)
#    {schema_version:"1.0", plan:<plan finalized by ZET>, mode:"dry-run", allowed_actions:["chmod"],
#     approval:{plan_id, approved_by:[...], approved_at, approval_token:<plan.plan_hash>}}
# 0. Fill the params of the draft actions (changes nothing; rejected ones become checklists)
bin/ger preview draft-plan.json --operator <name> -o previewed-plan.json --report preview-report.json --diff
#    -> zet finalize -> a human approves plan_hash
bin/ger verify  ger-input.json --operator <name>
bin/ger dry-run ger-input.json --operator <name> -o dry-run-log.json
# 2. Have a human check before / after in dry-run-log.json
# 3. Change mode in the input to "apply" and run (change nothing else)
bin/ger apply   ger-input.apply.json --operator <name> -o apply-log.json
# Check the hash chain of the audit log
bin/ger verify-log
# 4. A human does the remaining manual work (the [manual] lines printed by apply), and the person who did it records it
bin/ger confirm ger-input.apply.json --operator <worker> --item <finding_id> --step CL-IR:s1
# 5. Rescan with ZES. If something must be moved back (restore-request with 2 approvers; dry-run -> apply)
bin/ger quarantine-list --json
bin/ger restore restore-request.json --operator <name> -o restore-log.json
# If apply ended with exit code 5 or died halfway
bin/ger recover ger-input.apply.json --operator <name> -o recover-log.json
```

- A dry-run record is used up by one apply, even one that was killed. To apply again, start again from the dry-run
- After an apply was killed or ended with exit code 5, run `ger recover` before anything else: dry-run and apply are refused (G-8) while its journal is open. `ger recover` is accepted after the plan's due date and after the approval expired (it only undoes the interrupted apply), so run it even when dry-run reports G-2. If recover cannot close the journal (exit code 5), hand it to a human with design §3.1 "Closing a journal by hand" (bring each target in the journal back to a consistent state, then move the journal file out of `<store>/journal/` and keep it); do not move journal files yourself An apply that stops because its journal could not be written ("the journal could not be written", exit code 5) has already rolled back; free space (ask a human), then run `ger recover` with the same input. A killed `ger restore` is retried with the same restore-request
- An approval expires 7 days after `approved_at` (`GER_APPROVAL_MAX_AGE`), and a plan past the latest remediate `due_at` is not executed either. Redo ZET and the approval (recover is the exception, see above)
- G-8 "another ger apply / restore / recover is running": wait until that run has finished, then run the command again (nothing was changed). Do not remove the lock files
- Exit code 5 with "GER failed after its changes were made": the remediation is in place and recorded as `applied_unverified`; report it to a human with the message, and do not apply again
- A plan made by ZET with `--now` (`now_override: true`) is not executed (for tests only)

## Exit codes and reporting

| Code | Meaning | What to report |
|---|---|---|
| 0 | Success | Counts of applied / skipped |
| 3 | Rejected by a gate (nothing changed) | The rejecting G numbers and reasons |
| 4 | Failed during execution; everything rolled back | The failed target and the reason |
| 5 | The rollback could not be completed either, the journal could not be written, or GER failed after its changes were made | **Contact a human immediately.** Pass on the targets and states in remediation-log as they are |

## Gates

G-1 schema, pinned versions, no findings, the ZET invariants that can be evaluated from the plan alone, params per operation / G-2 finalized plans only; plans with now_override and expired plans are not allowed / G-3 binding of the approval to plan_hash, approval expiry / G-4 no self-approval / G-5 only operations in allowed_actions that GER supports (a plan with an unsupported one is rejected as a whole) / G-6 irreversible operations and operations on skills that declare exec / network / spend / send need 2 or more approvers (the latter also an explicit allowed_actions entry) / G-7 pre-validation of every target (absolute path, no symbolic links, owner, no duplicates, chmod that adds no permission, evidence_hash matches) / G-8 an unexpired, unused dry-run record of the same input (apply only), and no unfinished journal (run ger recover first) / G-9 the approved scan scope (plan.scope), protected targets, 2 approvers for targets that require root, GER derives the relation between target and finding again from the file system / G-10 definition T (remove only what matches GER's table H, add only values from the constant table K, the re-parsed result must match)
