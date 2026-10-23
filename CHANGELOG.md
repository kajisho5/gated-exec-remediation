# Changelog

## Unreleased

### findings 1.1: group の evidence の照合（G-7）と relation の確認（G-9）

- **原因**: G-7 が、同じ `action.group` のすべての item に内容に基づく evidence（file / tree / symlink）の `hash` の一致を求めていた。findings 1.1 では 1 つの対象に別のファイルの finding がまとまる（skill_dir: スキルのディレクトリの `tree` と `skill.contract.json` の `file`。npm: `node_modules/<name>/package.json` とロックファイル）ため、正しい計画を拒否していた（E2E の skillpact-signed-divergence と lockfile-installed）
- **規則の変更**: evidence.hash の一致は同じ `finding_path` の item どうしだけに求める。`finding_path` が違う item の間では比べない。保証は変わらない: どの item の evidence も、それぞれの `finding_path`（ファイル・ツリー・シンボリックリンク）から GER が導き直して照合する（item ごと・全件）。別のファイルのハッシュの一致は何も保証しない
- **G-9**: quarantine の group で、1 件目だけでなく全件の relation を字句上・ファイルシステム上で確かめる（finding_path の違う item が混ざるため。たとえばロックファイルでない finding_path の npm_installed を拒否する）
- テスト: 種類の違う evidence の group（skill_dir、npm_pkg_dir + npm_installed）が通ること、group の一部の改ざん（ファイルの内容・ツリーの中身・計画の evidence・ロックファイル）が G-7 で止まること、同じ finding_path で hash が違えば拒否、2 件目以降の relation の誤りが G-9 で止まること
- 設計 §10.3・§10.9 を更新
- E2E: ZES 0.4.0（findings 1.1）と ZET（ロックファイルの finding を checklist にする修正）で 53/53


### 修復能力の拡張 Phase 1（設計 0.2。Q-1〜Q-6 を推奨どおり採用）

- **新しい操作**: `quarantine`（ファイル・ツリー・シンボリックリンクを隔離ストアへ rename で移す。関係 self / npm_pkg_dir / npm_installed / pypi_record / ext_dir / skill_dir）、`edit_json`（JSON / JSONC。書式とコメントを保つ）、`edit_toml`（Phase 1 の範囲: 標準のテーブルヘッダの `[mcp_servers.<name>]`）、`remove_line`、`disable_mcp_server`（preset）、`checklist`（ファイルを変えない。結果は `pending_manual`）。`chmod` は従来どおり。ファイルを削除する操作は無い
- **新しいコマンド**: `ger preview`（下書きの params を現在の内容から埋める。変更しない）、`ger restore`（計画の外。承認者 2 名・dry-run 必須）、`ger confirm`（checklist / followup の手順の記録）、`ger recover`（ジャーナルからの巻き戻し）、`ger quarantine-list`
- **定義 T（絞るだけ）の一般化**（G-10）: 取り除けるのは GER の危険パターンの閉じた表 H（`ger/hazards.py`）に一致する単位だけで、GER が現在の内容に対して評価する。足せるのは定数表 K の値だけ。変更後をパースし直して「変更前 − 取り除いた単位」と一致することを確かめる（T-3）。dist-info だけ・manifest.json だけのような見かけだけの修復は拒否（Q-6）
- **範囲と関係**（G-9）: `plan.scope`（承認された検査範囲）の外・保護対象（`/`、システムのディレクトリ、`$HOME` そのもの、GER のインストール先、Python の標準ライブラリ、監査ログ・隔離ストアとその上位。`/etc` は許可リストだけ）を拒否。relation を GER がファイルシステムから導き直す
- **対象の解決**: `/` から 1 要素ずつ `O_PATH|O_NOFOLLOW|O_DIRECTORY` でたどり、親ディレクトリの fd を apply まで保持する。同一性 `(st_dev, st_ino, st_ctime_ns)` を適用の直前に照合する
- **dry-run の結果を apply に縛る**: 編集は `expected_after_sha256`、隔離は `sha256` / `tree_sha256`（ツリーハッシュ ger-tree-v1）/ `link_target` を計画に持ち、承認者は変更後の正確なバイト列を承認する。適用後に照合する（V）
- **隔離ストア**（Q-2）: `~/.local/state/ger/quarantine`（`GER_QUARANTINE_DIR` で変更可）、0700、マーカー `.ger-quarantine-store`、マニフェスト（0600）、移した後はファイル 0400・ディレクトリ 0500。別のデバイスにある対象は拒否。GER は何も削除しない
- **group**: 同じファイルへの複数の finding を `action.group` で 1 つのトランザクション（書き込み 1 回）にまとめる。実行順は 編集 → quarantine → chmod → checklist
- **承認者の人数**（Q-3）: restore・root が必要な対象・不可逆・破壊的な操作は 2 名（plan 1.1 では item の approved_by にも 2 名）
- **ジャーナル**: quarantine と編集の各段階を fsync 付きでジャーナルに書く。ロールバックに失敗した実行・途中で落ちた実行は `ger recover` で巻き戻す
- **remediation-log 1.1**: `result` に `pending_manual`・`confirmed`、results に `group`・`quarantine_ids`・`followup`、mode に restore 系と `recover`。監査ログの apply の記録に item ごとのハッシュ・隔離 ID・マニフェストのハッシュ（内容・diff は残さない）
- **スキーマ**: `schemas/actions.schema.json`（GER 所有。ZET が写す）、`schemas/restore-request.schema.json` を追加。`schemas/vendor/remediation-plan.schema.json` を ZET の plan 1.1（relation / finding_path / group / evidence / followup / scope、checklist の target null）に更新。`ger/jsonschema_lite.py` を ZET の版（maxLength / maxItems）に更新
- **テスト**: 操作ごとのフィクスチャ（合格・拒否）、途中の失敗からのロールバック、ロールバックの失敗と recover、途中で落ちた実行と recover、restore の往復、改ざん（再ハッシュした計画・隔離ストア）と TOCTOU（差し替え・途中のシンボリックリンク）、ツリーハッシュのテストベクタ。strace の検証を全コマンド・全操作種別に広げ、ネットワークのシステムコールが 0 件であることも確かめる（`tests/zero_exec.py`）。E2E（`tests/run-e2e.sh`、ZES が無ければ SKIP）
- **findings 1.1 への依存**: ZES の findings 1.1（kind / subject / locators / related / evidence / scan_roots）は未実装。Phase 1 は findings 1.0 の `path` と `module` と GER 自身の導き直しで動く（ZET が 1.1 の項目を任意で受け付ける）

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
