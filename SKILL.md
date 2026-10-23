---
name: gated-exec-remediation
description: GER（Gated-Exec Remediation）修復層スキル。ZET が確定した修復計画（remediation-plan.json）を、人間の明示承認・dry-run・許可リストのゲート G-1〜G-10 を通過した場合にだけ実行する。Phase 1 の操作は quarantine（隔離ストアへ移す。削除しない）・edit_json / edit_toml / remove_line / disable_mcp_server（GER の危険パターンの表に一致するものを取り除くだけ）・checklist（手作業の記録）・chmod。失敗時は全件ロールバックし、隔離したものは ger restore で戻せる。承認の代行・dry-run の省略・計画外の変更・隔離ストアの削除・ロックファイルの書き換え・秘密情報のローテーションは行わない。
---

# GER 修復スキル（gated-exec-remediation）

```
[ZET] remediation-plan.json ─┐
人間の承認（approval）───────┼─▶ [GER] G-1〜G-8 ─▶ dry-run ─▶ apply ─▶ remediation-log.json
allowed_actions ─────────────┘
```

## 絶対ルール

1. **承認を代行しない**: `approval.approved_by` と `approval_token` は人間が確定 plan の `plan_hash` を見て承認したものだけを使う。AI が承認者として名前を書かない。
2. **実行者は承認者ではない**: `--operator` に承認者と同じ名前を使わない（G-4 で拒否される）。
3. **apply の前に必ず dry-run**: 同じ入力（mode 以外）で dry-run を成功させ、結果（before / after）を人間に見せてから apply する。
4. **計画を書き換えない**: plan を 1 文字でも変えると `plan_hash` が変わり、承認が無効になる（G-3）。変更が必要なら ZET でやり直す。`plan_hash` を計算し直して承認をやり直させるのも禁止（承認トークンは完全性しか示さず、書き換えを暗号的には検出できない。GER は plan だけで評価できる ZET の不変条件を再検査し、chmod は権限を絞る操作しか受け付けないが、それに頼らない）。
5. **findings.json を読まない・渡さない**: 修復層の入力は確定 plan だけ（G-1）。
6. **ゲートを回避しない**: 拒否されたら理由（G-番号）をそのまま報告する。ログディレクトリや TTL・隔離ストアの場所を変えて通そうとしない。
7. **preview の拒否は checklist にする**: `ger preview` が拒否した自動修復（RECORD の無い dist-info、ドット区切りの TOML など）を、params を手で作って通そうとしない。ZET の提案の checklist に切り替える。
8. **隔離ストアから削除しない**: `~/.local/state/ger/quarantine` の中身を消さない・書き換えない（restore とロールバックができなくなり、証拠も失う）。削除は人間が判断する。
9. **restore も人間の承認**: restore-request の承認者（2 名以上）を AI が書かない。
10. **checklist の確認を偽らない**: `ger confirm` は、その手順を実際に行った作業者の名前で、行った後にだけ記録する。ローテーションなど外部の作業は GER が検証できず `self_attested` と記録されることを報告に書く。
11. **自動化しないものを実行しない**: ロックファイルの手での書き換え、`launchctl` / `systemctl` / `crontab` の実行、秘密情報の失効、git 履歴の書き換えは GER の範囲外。チェックリストの手順として人間に渡す。

## 手順

```bash
# 1. 入力を組み立てる（approval は人間が plan_hash を確認して記入）
#    {schema_version:"1.0", plan:<ZET 確定 plan>, mode:"dry-run", allowed_actions:["chmod"],
#     approval:{plan_id, approved_by:[...], approved_at, approval_token:<plan.plan_hash>}}
# 0. 下書きの action の params を埋める（変更しない。拒否されたものはチェックリストに）
bin/ger preview draft-plan.json --operator <name> -o previewed-plan.json --report preview-report.json --diff
#    → zet finalize → 人間が plan_hash を承認
bin/ger verify  ger-input.json --operator <name>
bin/ger dry-run ger-input.json --operator <name> -o dry-run-log.json
# 2. dry-run-log.json の before / after を人間に確認してもらう
# 3. 入力の mode を "apply" に変えて実行（他は一切変えない）
bin/ger apply   ger-input.apply.json --operator <name> -o apply-log.json
# 監査ログのハッシュチェーンの確認
bin/ger verify-log
# 4. 残った手作業（apply が表示する [手作業]）を人間が行い、行った人が記録する
bin/ger confirm ger-input.apply.json --operator <作業者> --item <finding_id> --step CL-IR:s1
# 5. ZES で再スキャンする。戻す必要があれば（承認者 2 名の restore-request で dry-run → apply）
bin/ger quarantine-list --json
bin/ger restore restore-request.json --operator <name> -o restore-log.json
# apply が終了コード 5 で終わった・途中で落ちた場合
bin/ger recover ger-input.apply.json --operator <name> -o recover-log.json
```

- dry-run 記録は 1 回の apply で使い切る。もう一度 apply するには dry-run からやり直す
- 承認は `approved_at` から 7 日（`GER_APPROVAL_MAX_AGE`）で失効し、remediate の `due_at` の最大値を過ぎた計画も実行しない。ZET と承認をやり直す
- ZET が `--now` で作った計画（`now_override: true`）は実行しない（テスト専用）

## 終了コードと報告

| コード | 意味 | 報告すること |
|---|---|---|
| 0 | 成功 | applied / skipped の件数 |
| 3 | ゲートで拒否（何も変更していない） | 拒否した G-番号と理由 |
| 4 | 実行中に失敗し、全件ロールバック済み | 失敗した対象と理由 |
| 5 | ロールバックも完了できなかった | **至急人間に連絡**。remediation-log の対象と状態をそのまま伝える |

## ゲート

G-1 スキーマ・版固定・findings 禁止・plan だけで評価できる ZET の不変条件・操作ごとの params / G-2 確定 plan のみ・now_override の計画と期限切れの計画は不可 / G-3 承認と plan_hash の束縛・承認の有効期限 / G-4 自己承認防止 / G-5 allowed_actions かつ GER 対応の操作のみ（未対応を含む計画は全体を拒否） / G-6 不可逆操作と、exec / network / spend / send を宣言したスキルへの操作は承認者 2 名以上（後者は allowed_actions の明示も） / G-7 対象の全件事前検証（絶対パス・シンボリックリンク不可・所有者・重複なし・権限を足さない chmod・evidence_hash の一致） / G-8 有効期限内で未使用の同一 dry-run 記録（apply のみ） / G-9 承認された検査範囲（plan.scope）・保護対象・root が必要な対象は承認者 2 名・対象と finding の関係を GER がファイルシステムから導き直す / G-10 定義 T（取り除くのは GER の表 H に一致するものだけ、足すのは定数表 K の値だけ、パースし直して一致）
