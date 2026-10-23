English | [日本語](SECURITY.ja.md)

# Security policy

Please report vulnerabilities in GER (gated-exec-remediation) itself through GitHub's private reporting, not through a public issue.

1. Open the repository's **Security** tab
2. Choose **Report a vulnerability**

## Scope

- The latest main branch (fixes are not made to past versions)

What we want reported (examples):

- A change can be executed by getting around gates G-1 to G-8 (forged approval, skipped dry-run, and so on)
- Targets or permissions outside the plan are changed, or a rollback is incomplete

What we accept as public issues:

- Bugs that are not vulnerabilities (wrong decisions, better error messages, and so on)

## Response

This project is maintained by one person, so responses are made as far as possible. There is no guaranteed response time. After a fix is published, the report and the fix are recorded in the CHANGELOG (the reporter's name is included if they wish).
