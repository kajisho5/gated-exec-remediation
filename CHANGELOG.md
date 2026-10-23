# Changelog

## Unreleased

- `RISKY_EFFECTS`（G-6）を SkillPact 0.8 の効果名に合わせて `("exec", "network", "spend", "send")` に変更（ZES `7b75e78` の findings スキーマ変更に追従。旧 `secrets` は機密ファイルの `read`、旧 `persist` は作業領域外への `write` に統合され、`longrun` は廃止。ZET と同じ集合）
- `tests/fixtures/zet-final-plan.json` を、ZES main の実出力から作った ZET の findings で ZET finalize により再生成。G-6 の効果ごとのテストを追加

## 0.1.0 — 2026-10-22

- `bin/ger`（verify / dry-run / apply）、ゲート G-1〜G-8、chmod 操作（os.fchmod、特殊ビット不可、差し替え検出）
- 失敗時の全件ロールバック（終了コード 4 / 5）、追記専用の監査ログ（ハッシュチェーン）、dry-run 記録の有効期限
- `schemas/remediation-log.schema.json`（GER 所有。契約 §6 に mode / plan_hash を追加）、`schemas/ger-input.schema.json`
- `schemas/vendor/remediation-plan.schema.json`（ZET から版固定で取り込み）
- テスト 22 件（ZET 確定計画との互換性、公式 jsonschema との判定一致、外部プロセスゼロ検証を含む）

### リリース

- main の CHANGELOG 先頭の版に対応するタグと GitHub Release を、GitHub Actions（`.github/workflows/release.yml`）が自動で作成する
