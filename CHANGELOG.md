# Changelog

## Unreleased

### round 3 の修正

- **承認トークンの限界を明記し、plan だけで評価できる ZET の不変条件を再検査**（F1）: `approval_token` = `plan_hash` は完全性しか示さず、finalize 後に書き換えて再ハッシュした plan は暗号的には検出できない（承認者の署名は将来の課題）。G-1 で I-1 / I-3 / I-4（action の形・対象パスの形）/ I-5 / I-6 / I-7（`items[].skillpact` に対して）/ I-9（日付の前後関係）/ I-11 / I-12 を再検査する
- **chmod は権限を絞るだけ**（F7）: G-7 で、現在の mode に無い権限ビットを足す chmod を拒否する。world-writable の mode も拒否
- **監査ログ・-o の親の保護を字句上の上位にも広げる**（F2 / F3）: `GER_LOG_DIR` と `-o` の親ディレクトリについて、与えられたパスの字句上の上位（途中のシンボリックリンクを置いたディレクトリを含む）と実パスの上位の和集合を保護する。`GER_LOG_DIR` は起動時に一度だけ実パスへ解決し、ログの読み書きはすべて解決後のパスで行う
- **dry-run 記録は 1 回の apply で使い切る**（F5）: 同じ計画・同じ入力の apply が実行まで進む（result が ok / rolled_back / rollback_failed / applied_unlogged）と、それ以前の dry-run 記録は数えない
- **承認の有効期限**（F5）: `approved_at` から `GER_APPROVAL_MAX_AGE` 秒（既定 604800 = 7 日）を過ぎた承認は G-3 で拒否。remediate の `due_at` の最大値を過ぎた計画は G-2 で拒否
- **`now_override: true` の計画を既定で拒否**（F5）: ZET が `--now` で作った計画は `GER_ALLOW_NOW_OVERRIDE=1` のときだけ受理する（G-2）
- **`--now` 付きの apply は `--now` 付きの dry-run だけを数える**（F6）: 期限切れの実時刻の dry-run 記録を `--now` で期限内に見せかけられない
- **危険な効果には承認者 2 名**（F10）: exec / network / spend / send を宣言したスキルへの操作は、allowed_actions の明示に加えて `approval.approved_by` が 2 名以上必要（G-6）。`skillpact_effects` は SkillPact 0.8 の 6 効果だけ（スキーマ）
- **evidence_hash の確認**（F14）: `action.evidence_hash` があれば G-7 で現在のファイルと比べ、不一致なら拒否（ZES と同じ規則。100MB 超はパス・サイズ・mtime のハッシュ、ディレクトリは比べない）
- **`ger verify-log [LOG]`**（F15）: 監査ログのハッシュチェーンを検証する。追記の前に末尾の連結を確かめ、壊れたチェーン（途中で切れた最終行を含む）には追記しない（終了コード 64）
- **端末制御文字のエスケープ**（F8）: 拒否理由・`-o` と計画の対象の衝突・内部エラーを含む標準エラー出力のすべてのメッセージで、C0 / DEL / C1 制御文字・行区切り・双方向テキスト制御文字を `\xNN` / `\uNNNN` で表示する
- `schemas/vendor/remediation-plan.schema.json` を ZET `64bb2eb`（`now_override` / `evidence_hash` / `items[].skillpact` の追加、効果名の列挙）に、`ger/jsonschema_lite.py` を ZET `20c0a18`（`safe_text`）に更新
- README からテスト件数の記載を削除（F9）。`tests/run-tests.sh` の外部プロセスゼロ検証の入力は実行時刻からの相対時刻にした（承認の有効期限と due_at のため）

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
