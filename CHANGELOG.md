# Changelog

## 0.1.0 — 2026-10-22

- `bin/ger`（verify / dry-run / apply）、ゲート G-1〜G-8、chmod 操作（os.fchmod、特殊ビット不可、差し替え検出）
- 失敗時の全件ロールバック（終了コード 4 / 5）、追記専用の監査ログ（ハッシュチェーン）、dry-run 記録の有効期限
- `schemas/remediation-log.schema.json`（GER 所有。契約 §6 に mode / plan_hash を追加）、`schemas/ger-input.schema.json`
- `schemas/vendor/remediation-plan.schema.json`（ZET から版固定で取り込み）
- テスト 22 件（ZET 確定計画との互換性、公式 jsonschema との判定一致、外部プロセスゼロ検証を含む）
