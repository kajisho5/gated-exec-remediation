<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo/ger-logo-dark.svg">
    <img src="brand/logo/ger-logo-light.svg" alt="gated-exec remediation" height="72">
  </picture>
</p>

[English](README.md) | 日本語

# gated-exec-remediation（GER）

**Gated-Exec Remediation** — [Zero-Exec Shield（ZES）](https://github.com/kajisho5/zero-exec-shield) の修復層です。[ZET（zero-exec-triage）](https://github.com/kajisho5/zero-exec-triage) が確定した修復計画を、すべてのゲートを通過した場合にだけ実行します。3 層で唯一、変更を行う層です。

```
[ZES] findings.json ──▶ [ZET] remediation-plan.json ──▶ [GER] remediation-log.json
        検知（実行なし）        判断（実行なし）              修復（ゲート付き実行）
```

- **ゲート G-1〜G-10**: 1 つでも失敗したら何も変更しません
- **承認は計画の中身に結びつく**: `approval_token` は確定 plan の `plan_hash`。承認後に計画を変えると止まります（示すのは完全性で、真正性ではありません。[承認](#承認) を参照）
- **dry-run 必須**: 同一入力の未使用の dry-run 成功記録（既定 24 時間以内）が無いと apply できません。dry-run 1 回で apply は 1 回です
- **修復は絞るだけ（定義 T）**: 取り除けるのは GER が持つ危険パターンの閉じた表に一致する単位だけで、一致するかは GER が現在の内容に対して自分で評価します。足せるのは閉じた定数表の値だけ。変更後をパースし直して「変更前 − 取り除いた単位」と一致することを確かめます。chmod は権限ビットを足せません
- **何も削除しない**: 隔離したものと、編集したファイルの編集前の版は、専用の隔離ストアに残り、`ger restore` で戻せます
- **全件ロールバック**: 1 件でも失敗したら残りを実行せず、適用済みを逆順に戻します。途中で落ちた実行はジャーナルから `ger recover` で巻き戻します
- **外部プロセスもネットワークも使わない**: 移動は `os.rename`、バックアップは `os.link`、chmod は `os.fchmod`。Python 3.11 以上の標準ライブラリのみで、テストで全コマンドを strace で確かめます
- **Phase 1 の操作**: `quarantine`・`edit_json`（JSON / JSONC）・`edit_toml`（Phase 1 の範囲）・`remove_line`・`disable_mcp_server`・`checklist`・`chmod` と `ger restore`。それ以外（`write_config`・`rotate_secret`・`replace_token` など）を含む計画は全体を拒否します

## GER が直すもの・直さないもの

件数より、ここを正直に書くことのほうが大事です。下の「自動」は、GER が変更し、ZES で再スキャンするとその finding が消えることを意味します。**インシデントが終わったことは意味しません**。マルウェアの痕跡への自動修復には、必ず後続のチェックリスト（インシデント対応、秘密情報のローテーション、`launchctl bootout` など）が付き、人が作業して `ger confirm` で記録します。

| | 対象 | 方法 |
|---|---|---|
| **自動** | 悪性のペイロード・ドロッパー・`.pth` の起動フック・IoC のファイル・悪性の git hooks・SymJack のシンボリックリンク・ポイズニングされた MCP ツール定義・eBPF / LD_PRELOAD のスクリプト | `quarantine`（ファイル・ツリー・リンクそのもの） |
| **自動** | `node_modules/<name>` にインストールされた侵害パッケージ、ブラウザ拡張（`Extensions/<id>`、全バージョン）、SkillPact の乖離・差分異常のあるスキル、侵害された `*.dist-info`（**RECORD があるときだけ**。RECORD に載っている site-packages の下の全ファイルを移す） | 関係つきの `quarantine`（`npm_pkg_dir`・`npm_installed`・`ext_dir`・`skill_dir`・`pypi_record`） |
| **自動** | `.mcp.json`・VS Code の `mcp.json`（JSONC）・`~/.claude.json`・Cursor / Windsurf の危険な MCP サーバー、Codex の `.codex/config.toml` で標準のテーブルヘッダで定義されたサーバー | `disable_mcp_server` |
| **自動** | `package.json` のインストール時のライフサイクルスクリプト、ZES が報告する Claude Code の `hooks` の項目（危険なコマンド行、ネットワークへのアクセスや難読化、キャンペーン文字列。その項目だけ）、VS Code の `runOn: folderOpen`（`default` にする） | `edit_json` |
| **自動** | シェルの rc の行（`LD_PRELOAD=`・`curl … \| sh`・`base64 -d \| sh`・`HISTFILE=/dev/null`）、git の `fsmonitor` / `sshCommand` / `hooksPath`、php.ini の `auto_prepend_file`、`ld.so.preload` の行、`/etc/cron.d` の取得して実行する行 | `remove_line`（最上位の 1 行だけ） |
| **自動** | LaunchAgent / LaunchDaemon の plist、systemd のユーザーユニット | ファイルの `quarantine` — **と** CL-LAUNCHD / CL-SYSTEMD のチェックリスト（既に読み込まれているジョブは、`launchctl bootout` / `systemctl stop` を実行するまで動き続けるため） |
| **チェックリスト** | ロックファイル・requirements の侵害版・脆弱版、`*.egg-info` と RECORD の無い `*.dist-info`、サーバー・ランタイムの CVE（GitLab・TeamCity・Jenkins・PHP・Node.js・CA バンドルなど）、GitHub Actions の pwn request と SHA 固定されていないアクション・イメージ、`npx` / `uvx` の版を固定していない MCP サーバー、ドット区切りのキーやインラインテーブルで定義した Codex の TOML、crontab、環境変数、`.env`、秘密情報・トークン、シェル履歴、ビルドフック、`trust_remote_code`、cosign のフラグ、SBOM | 具体的な手順つきの `checklist`（CL-PKG・CL-VENV・CL-UPGRADE・CL-PHP・CL-PWN・CL-PIN・CL-MCP-PIN・CL-CRON・CL-ENV・CL-SECRET・CL-IR・CL-REVIEW など） |
| **自動化しない** | ロックファイルの手での書き換え、ネットワークでタグを SHA に・版をダイジェストに解決すること、パッケージのインストール・更新・OS の更新・イメージの再ビルド、秘密情報の失効・ローテーション、`launchctl` / `systemctl` / `crontab` / `bpftool` / `rmmod` とプロセスの停止、git 履歴の書き換え・push・GitHub 上のワークフローの無効化、隔離ストアからの削除、コードの意味を変える修正、シェル履歴の編集（証拠のため） | 設計上の対象外。外部プロセス・ネットワーク・人の判断が要るか、元に戻せないため |

ZES のフィクスチャ（53 のツリー、共有のテスト用ホームを含めて 331 件）では、Phase 1 で 80 件を自動で取り除き、残る 251 件は計画したチェックリスト（185 件）・defer / exception（47 件）・held（19 件）とちょうど一致します。`ger restore` で 331 件すべてが戻ります（[E2E](#e2ezes--zet--ger--zes) を参照）。

## 使い方

```bash
bin/ger verify  ger-input.json --operator ops
bin/ger dry-run ger-input.json --operator ops -o dry-run-log.json
bin/ger apply   ger-input.apply.json --operator ops -o apply-log.json   # mode だけ "apply" に変えた入力
bin/ger verify-log

# Phase 1
bin/ger preview draft-plan.json --operator alice -o previewed-plan.json --report preview-report.json [--diff]
bin/ger confirm ger-input.apply.json --operator ops --item <finding_id> --step CL-IR:s1
bin/ger quarantine-list [--json] [--plan-id ID]
bin/ger restore restore-request.json --operator ops -o restore-log.json      # 先に mode "dry-run"、次に "apply"
bin/ger recover ger-input.apply.json --operator ops -o recover-log.json
```

Phase 1 の流れ: `zet draft`（finding ごとに自動の操作とチェックリストを提案）→ 判断者が提案を採用 → `ger preview` が現在のファイルから正確なハッシュ・ops・`expected_after_sha256` を埋める（読むだけ。安全にできないものは理由を出すので、判断者はその finding をチェックリストに切り替える）→ `zet finalize` → 承認 → `ger dry-run` → `ger apply` → ZES で再スキャン。承認者は変更後の正確なバイト列を承認することになります。`--diff` は unified diff を端末に出すだけで、diff と取り除いた行はどのログにも残しません。

`verify-log [LOG]` は監査ログのハッシュチェーンを検証します（健全なら `0`、壊れていれば `3`、ログが無い・読めない場合は `64`。読むだけで、この実行自体は記録しません）。

入力（[schemas/ger-input.schema.json](schemas/ger-input.schema.json)）:

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

| 終了コード | 意味 |
|---|---|
| 0 | 成功 |
| 3 | ゲートで拒否（何も変更していない） |
| 4 | 実行中に失敗し、全件ロールバック済み |
| 5 | ロールバックも完了できなかった、または変更を適用したが remediation-log を書けなかった（要手動対応） |
| 64 / 70 | 引数・環境エラー / 内部エラー |

環境変数: `GER_QUARANTINE_DIR`（隔離ストア、既定 `$XDG_STATE_HOME/ger/quarantine` または `~/.local/state/ger/quarantine`）、`GER_LOG_DIR`（監査ログ、既定 `$XDG_STATE_HOME/ger/`。`XDG_STATE_HOME` が未設定なら `~/.local/state/ger/`。起動時に一度だけ実パスへ解決し、ログの読み書きはすべて解決後のパスで行います）、`GER_DRYRUN_TTL`（dry-run 記録の有効秒数、既定 86400、最大 604800）、`GER_APPROVAL_MAX_AGE`（承認の有効秒数。`approved_at` から数え、既定 604800 = 7 日、最大 31622400）。
`--now`（現在時刻の上書き）はテスト専用で、`GER_ALLOW_NOW_OVERRIDE=1` のときだけ受け付けます（それ以外は終了コード 64）。`--now` を使った実行は監査ログに `now_override: true` として記録します。G-8 は同じ扱いの dry-run 記録だけを数えます（`--now` なしの apply は `--now` なしの dry-run だけ、`--now` 付きの apply は `--now` 付きの dry-run だけ。期限切れの実時刻の記録を `--now` で期限内に見せかけられません）。ZET が `--now` で draft / finalize した計画には `now_override: true` が付き、`GER_ALLOW_NOW_OVERRIDE=1` でなければ G-2 で拒否します。

`-o` の出力先は変更を始める前に確認します（空でなく末尾が `/` でないこと、指定されたパスのままの親ディレクトリが存在し書き込めること、既存なら通常ファイルであること（ディレクトリ・FIFO・ソケット・`/dev/null` などのデバイス・シンボリックリンクは拒否。remediation-log はアトミックな rename で書き出し、リンク先ではなくリンク自体を置き換えてしまうため、シンボリックリンクはたどらずに拒否します）、監査ログ・監査ログのディレクトリ内のファイル・入力ファイル・計画の対象のいずれとも同じファイルでないこと、計画の対象に親ディレクトリやその上位ディレクトリ（与えられたパスの字句上の上位（途中のシンボリックリンクを置いたディレクトリを含む）と実パスの上位の両方）が含まれないこと（apply 後に remediation-log を書けなくなるため）。実パスと、既存なら `st_dev`/`st_ino` で比較するため親ディレクトリのパスにあるシンボリックリンクやハードリンク経由でも拒否します）。違反は終了コード 64 で、計画の対象との衝突は入力を読んだ後に判明するため監査ログに `result: "error"` として理由付きで記録します。remediation-log は監査ログより先に書き出し、書けなかった場合は成功として記録せず、今回の記録と取り違えないよう `-o` の位置にある以前のファイルを削除します（apply で変更が残っている可能性があるときは終了コード 5。全件を適用しロールバックしていない場合、監査ログには `result: "applied_unlogged"` と記録し、`rollback_failed` はロールバックに失敗した場合だけです）。

## 承認

`approval_token` は確定 plan の `plan_hash`（正規化 JSON の SHA-256）と一致し、`approval.plan_id` は plan と一致している必要があります。これが示すのは **完全性だけで、真正性ではありません**。ハッシュを計算した時点から plan が変わっていないことは分かりますが、ZET が作った plan であることや承認者がその plan を見たことは示しません。`zet finalize` の後に plan を書き換えて `plan_hash` を計算し直し、`approval_token` も合わせた場合は **暗号的には検出できません**。検出には承認者による plan への署名が必要で、将来の課題です。

そのような plan でできることを狭めるため、GER は ZET の不変条件のうち plan だけで評価できるものをすべて再検査し（G-1: I-4 の action の形と対象パスの形、ZET が各 item に写す `skillpact` の要約に対する I-5 / I-6 / I-7、承認者の人数、自己承認、日付の前後関係など。G-1 の行を参照）、chmod は対象の現在の mode から権限ビットを外すことだけを許し（G-7）、`evidence` / `evidence_hash` があれば現在のファイルと比べ（G-7）、危険パターンの表とパースし直しの検査を計画を信用せず現在の内容に対して評価し（G-10）、関係をファイルシステムから導き直し、対象を承認された `plan.scope` の中かつ保護対象の外に限ります（G-9）。findings が無いと確かめられないのは「`finding_path` が本当に ZES の報告したパスであること」です。そのため、書き換えて再ハッシュした plan は範囲の中で別の対象を選べますが、できるのは GER の危険パターンの表に一致する単位を取り除くこと（または権限を絞ること）だけで、どの変更も隔離ストアに残って restore でき、コマンド・URL・パスを足すことはできません。また承認は `approved_at` から `GER_APPROVAL_MAX_AGE` 秒（既定 7 日）で失効し、現在時刻が remediate の item の `due_at` の最大値を過ぎた計画も拒否します。

## 操作（Phase 1）

| 操作 | params（`ger preview` が埋める） | 補足 |
|---|---|---|
| `quarantine` | `{kind: file, sha256}` / `{kind: tree, tree_sha256}` / `{kind: symlink, link_target}`。npm の関係は `subject`、`pypi_record` は `record: true` | `os.rename` でストアへ移し、ファイルは 0400、ディレクトリは 0500 にする（元の mode はマニフェストに残す）。ハードリンクされたファイル、FIFO・ソケット・デバイス、ストアと別のデバイスにある対象、メタデータだけの対象（`.dist-info` だけ、`node_modules/*/package.json` だけなど）は拒否 |
| `edit_json` | `{format: json\|jsonc, ops: [{op: remove\|replace_const, pointer, before_sha256, const?}], file_sha256, expected_after_sha256}` | GER 自身の字句解析器で書式とコメントを保つ。キーの重複は拒否 |
| `edit_toml` | `{ops: [{op: remove_table, key_path, before_sha256}], file_sha256, expected_after_sha256}` | Phase 1 の範囲: 標準のテーブルヘッダで定義された `[mcp_servers.<name>]`（とそのサブテーブル）だけ。ドット区切りのキーとインラインテーブルは拒否 |
| `remove_line` | `{lines: [{n, sha256, pattern_id}], file_sha256, expected_after_sha256}` | 行の全体がパターンに一致すること。ヒアドキュメント・関数・`if` / `case` / ループの中や継続行は拒否。CRLF と BOM は保つ |
| `disable_mcp_server` | `edit_json`（`format` json / jsonc）または `edit_toml`（`format: toml`）と同じ | MCP サーバーの定義だけを取り除ける |
| `checklist` | `{template, steps: [{id, text, blocking}], verify?: {kind}}` | ファイルを変えない。結果は `pending_manual`。`target` は null にできる（crontab・環境変数） |
| `chmod` | `{mode: "0NNN"}` | 0.1 から変更なし |

同じファイルへの複数の finding（例: 1 つの `package.json` への §2 と §15）は同じ `action.group` を持ち、書き込み 1 回のトランザクションとして適用します。実行順は、参照を取り除く編集 → quarantine → chmod → checklist です。

**関係**（`action.relation`）: `self`・`npm_pkg_dir`・`npm_installed`・`pypi_record`・`ext_dir`・`skill_dir`、または `none`（対象の無いチェックリスト）。ZET は字句上の条件を確かめ、GER は同じ関係をファイルシステムから導き直します（例: `node_modules/<name>/package.json` の name が `params.subject` と一致すること、RECORD の各メンバーが sha256 と一致すること）。

**隔離ストア**: `~/.local/state/ger/quarantine`（0700、マーカーファイル `.ger-quarantine-store`）。構成は `<run_id>/<seq>/{payload, manifest.json}` と `journal/<run_id>.jsonl`。GER はここから何も削除しません。削除（purge）は手作業で、消した後は restore もロールバックもできません。ZES がマーカーを読み飛ばすようになるまでは、ストアを ZES の `--root` の外に置いてください（GER は `plan.scope.roots` の下のストアを拒否します）。

**restore**（`ger restore`、計画の外）: restore-request はエントリごとに `quarantine_id` と `manifest_sha256`（`ger quarantine-list --json` で分かる）を並べ、**承認者 2 名**・先に dry-run・内容に対するトークンが必要です。GER はストアの中身がマニフェストと一致すること、元のパスが空いていること（編集なら、ファイルが GER の書いた内容のままであること）を確かめてから戻します。置き換えられる版はストアに残します。

**チェックリスト**: `ger apply` は残った手作業を表示します。`ger confirm` は手順を 1 つずつ監査ログに記録します（apply の成功の後だけ、承認者は不可）。ローカルで確かめられるもの（`verify: path_absent` / `file_hash_changed`）は GER が確かめ、それ以外は `self_attested` と記録し、「検証済み」とは呼びません。

**承認者の人数**: チェックリスト・`self` の quarantine・編集・chmod は 1 名。`restore`、root が必要な対象（システムのディレクトリ、または実行ユーザーが所有しないファイル。root 用とそれ以外を同じ計画に混ぜない）、不可逆・破壊的な操作（Phase 1 には無い）、SkillPact の差分異常、危険な効果を宣言したスキルは **2 名**。

## ゲート

| # | 拒否する条件 |
|---|---|
| G-1 | スキーマ不適合（入力・plan とも strict、版固定。`params` は [schemas/actions.schema.json](schemas/actions.schema.json) と操作ごとの検査に合うこと。plan 1.0 は chmod だけ。plan 1.1 の action は `relation`・`finding_path`・`evidence` を持ち、target を null にできるのはチェックリストだけ。`skillpact_effects` は SkillPact 0.8 の 6 効果のみ）、入力に `findings` がある、mode とコマンドの不一致、remediate の item で `finding_id` が重複（実行結果を item に一意に対応づけられない）、`approved_at` / `created_at` / item の日時が実在しない日時（2 月 30 日、25 時など）、入力 JSON の object でキーが重複・入れ子が 64 段を超える。さらに findings やポリシーが要らない ZET の不変条件（メッセージは `ZET I-n equivalent`）: items と held を通じて finding_id が重複（I-1）、exception に exception_type / reason / recheck_at・承認者が無い、exception 以外に exception_type がある、INFO 以外の defer に reason / recheck_at が無い、判断者が item の承認者に含まれる（I-3）、remediate に owner / due_at / action が無い、remediate 以外に action がある、対象が正規化済みの絶対パスでない（`.` `..` 連続した `/`（先頭の `//` を含む）不可）（I-4）、乖離のある finding が exception（I-5）、item の承認者の重複、diff_anomaly の finding や exec / network / spend / send を宣言したスキルの remediate で item の承認者が 2 名未満（I-6）、署名フィールドがあり乖離のある finding が CRITICAL でない（I-7）、`skillpact_effects` が item の `skillpact.declared_effects` と不一致、decided_at が created_at より前・未来、due_at / recheck_at が decided_at より前（I-9）、partial なのに held が空（I-12） |
| G-2 | plan.status が ok / partial 以外（draft・error）、plan に `now_override: true`（ZET が `--now` で作成）があり `GER_ALLOW_NOW_OVERRIDE` が `1` でない、現在時刻が remediate の item の `due_at` の最大値を過ぎている（計画の期限切れ。ZET で判断し直す） |
| G-3 | plan_hash が本体と不一致、approval.plan_id 不一致、approval_token ≠ plan_hash、approved_at が未来または計画作成前、承認が `GER_APPROVAL_MAX_AGE` 秒（既定 7 日）より古い |
| G-4 | `--operator` が承認者に含まれる（人名は大文字小文字を区別せずに比較） |
| G-5 | 操作が allowed_actions に無い、または GER 未対応 |
| G-6 | root が必要な対象、不可逆・破壊的な操作で承認者が 2 名未満（plan 1.1 では item にも 2 名）。reversible / skillpact_effects（[SkillPact](https://github.com/kajisho5/skillpact) の effects）が無い（ZET 確定済みでない）、reversible が操作の性質と不一致、不可逆操作で承認者 2 名未満、危険な効果（exec / network / spend / send）を宣言したスキルへの操作が allowed_actions に明示されていない・承認者 2 名未満（承認者は `approval.approved_by`。大文字小文字だけが異なる名前は同一人物として数える）。ZET の I-6 も item に同じ 2 名を求める |
| G-7 | 対象が正規化済みの絶対パスでない・存在しない・途中の要素がシンボリックリンクやディレクトリ以外（GER は `/` から 1 要素ずつ `O_PATH\|O_NOFOLLOW\|O_DIRECTORY` でたどり、親の fd を apply まで保持する）・`ger preview` が見たものと違う（`sha256` / `tree_sha256` / `link_target` / `file_sha256` / `before_sha256`、または計算し直した結果が `expected_after_sha256` と違う）・group の外で他の item の対象と重なる・隔離ストアと別のデバイス・ファイルを期待する所でシンボリックリンク・通常ファイル/ディレクトリ以外・所有者でない・監査ログ／監査ログのディレクトリ／それらの上位ディレクトリ（指定された `GER_LOG_DIR` の字句上の上位（途中のシンボリックリンクを置いたディレクトリを含む）と実パスの上位の両方。変更すると GER が記録できなくなる）・計画内で重複（ハードリンクで同じ実体を指す場合を含む）、chmod の mode が `^0[0-7]{3}$` 以外・world-writable・対象の現在の mode に無い権限ビットを足す（修復は権限を絞るだけ）、`action.evidence_hash` があり現在のファイルと一致しない（ZES と同じ規則で計算: 100MB 以下の通常ファイルは内容の SHA-256、100MB 超は `path\|size\|mtime` の SHA-256。ディレクトリは ZES が finding の detail をハッシュするため比べない） |
| G-9 | 範囲と関係: chmod 以外のファイルを変える操作で `plan.scope` が無い、対象が `scope.roots` / `scope.home` の外、隔離ストアが scope のルート・site-packages・node_modules・`PATH` のディレクトリの下、保護対象（`/` とトップレベルのシステムディレクトリ、`$HOME` そのもの、GER のインストール先、Python の標準ライブラリ、監査ログ、隔離ストア、それらの上位。`/etc` の下は `ld.so.preload`・`hosts`・`cron.d/*` だけ）、root が必要な対象で承認者が 2 名未満・root が必要な対象とそうでない対象が同じ計画にある、`relation` が字句上・ファイルシステム上で成り立たない |
| G-10 | 定義 T: 取り除く単位が GER の危険パターンの表 H に無い（T-1）、足す値が定数表 K に無い（T-2）、パースし直した結果が「変更前 − 取り除いた単位」と違う（T-3）、ZES が検知するメタデータだけを取り除きコードを残す（Q-6） |
| G-8 | apply 時に、同一 plan_hash・同一入力（mode 以外）・同じ `--now` の扱いの、未使用の dry-run 成功記録が有効期限内に無い、または監査ログのハッシュチェーンが壊れている（UTF-8 の JSON object として読めない行も壊れているとみなす）。dry-run 記録は、その後に同じ計画・同じ入力で実行まで進んだ apply で使用済みになる（apply は最初の変更の前に開始の記録 `result: "started"` を追記するため、強制終了された apply でも使用済み）。拒否や変更前の引数エラーでは使用済みにならない。verify / dry-run / apply 時に、隔離ストアに未完了のジャーナル（強制終了された apply、ロールバックに失敗した apply）がある場合も拒否する（先にその計画の入力で `ger recover` を実行する）。`ger recover` は後の apply・restore が対象に触れたステップを再生せず、ほかのすべてのステップを正確に元に戻せるときだけ元に戻す。ジャーナルの書き込みに失敗した apply は止まる（終了コード 5）（[設計 §3.1](docs/design/design.ja.md)） |

実行中は、事前検証時の実体 ID（`st_dev`・`st_ino`・`st_ctime_ns`）と一致する場合だけ変更します。i-node 番号は削除・再作成で再利用されることがあるため、ctime も含めて同一の実体かを判定しています。

## スキーマ

| ファイル | 所有 | 内容 |
|---|---|---|
| [schemas/remediation-log.schema.json](schemas/remediation-log.schema.json) | **GER** | 出力契約（契約 §6 に `mode` と `plan_hash` を追加。1.1 で `pending_manual`・`group`・`quarantine_ids`・`followup` を追加） |
| [schemas/ger-input.schema.json](schemas/ger-input.schema.json) | GER | 入力 |
| [schemas/actions.schema.json](schemas/actions.schema.json) | **GER** | 操作ごとの params。ZET が版固定で写す |
| [schemas/restore-request.schema.json](schemas/restore-request.schema.json) | GER | `ger restore` の入力 |
| [schemas/vendor/remediation-plan.schema.json](schemas/vendor/remediation-plan.schema.json) | ZET | 版固定の写し（`schemas/vendor/VENDOR.json` に取り込み元コミットと SHA-256） |

## 監査ログ

`$GER_LOG_DIR/ger-audit.jsonl`。1 行 1 レコード（command / operator / plan_id / plan_hash / input_hash / output_hash / started_at / finished_at / result / gate_failed / now_override / prev_hash。apply は item ごとに種類・対象・関係・変更前後のハッシュ・ops のダイジェスト・隔離 ID・マニフェストのハッシュも、confirm は finding・手順・作業者・確認結果も記録）。ファイルの内容・diff・取り除いた行は残さず、ハッシュと行番号と pointer だけを残します。拒否も記録します。`bin/ger verify-log` でハッシュチェーン全体を検証できます。追記の前に末尾の連結（最終行が改行で終わる JSON object で、直前の行のハッシュを持つこと）を確かめ、壊れたチェーンには追記しないため何も実行しません（終了コード 64。`verify-log` で確認し、ログを退避してから実行し直してください）。ログに書けない場合は実行しません。既存のログディレクトリが実行ユーザーの所有でない、またはグループ・他者から書き込み可能な場合も実行しません（終了コード 64）。

## テスト

```bash
tests/run-tests.sh   # 単体テスト＋ strace による外部プロセス・ネットワークゼロ検証
ZES_HOME=/path/to/zero-exec-shield ZET_HOME=/path/to/zero-exec-triage tests/run-e2e.sh   # E2E（ZES が無ければ SKIP）
```

`run-tests.sh` は単体テスト（一時ディレクトリの実ファイルで全操作の合格・拒否、途中の失敗からの全件ロールバック、ロールバックの失敗と `ger recover`、途中で落ちた実行と `ger recover`、apply の変更のたびに SIGKILL して再実行が拒否されることと `ger recover`、restore の往復、承認後に書き換えて再ハッシュした計画、差し替えられた対象と途中のシンボリックリンク、改ざんされた隔離ストア、`ger-tree-v1` のテストベクタ）と、全操作種別を含む計画で全コマンドを strace で実行し、bash / python3 以外の `execve` とネットワークのシステムコールが無いことの確認を行います。

root で実行すると「読めないファイル」のテストは SKIP になります（一般ユーザーでは実行されます）。ZET が確定した実際の計画で、スキーマと plan_hash の互換性も確認しています（`tests/fixtures/zet-final-plan.json` は round 3 より前の ZET の出力で新しい任意フィールドを持たない。`tests/fixtures/zet-final-plan-r3.json` は `items[].skillpact` と `action.evidence_hash` を持ち、GER が G-1 で再検査する ZET の不変条件にも合格すること。`tests/fixtures/zet-final-plan-11.json` は chaindrop の E2E で作った ZET 0.2 の plan 1.1 で、group・followup・チェックリストと `ger preview` が埋めた params を持つ）。

## E2E（ZES → ZET → GER → ZES）

`tests/run-e2e.sh` は ZES のフィクスチャ（とそのホーム）を一時ディレクトリに写し、`zes-scan.sh` で検知し（ZES のリポジトリは読むだけ）、`zet draft`、提案の採用（できるものは自動、それ以外はチェックリスト。`ger preview` が拒否したものはチェックリストに切り替える）、`ger preview`、`zet finalize`、承認、`ger dry-run`、`ger apply`、再スキャン、ストアの全エントリの `ger restore`、3 回目のスキャンを行います。合格の条件は、再スキャンで残る finding がチェックリスト・defer・exception・held の item とちょうど一致し、restore 後のスキャンが最初のスキャンと一致する（finding の id も一致する）ことです。

ZES v0.4.0（92be8b7、findings 1.1）と ZET `main` 9792941 での結果（件数は finding の数。「自動」は GER がファイルを変える操作で直し、再スキャンで消えた finding。「チェックリスト」は `pending_manual` の item。「held」は ZES がエラーを出したモジュールの finding。オフラインで省いた §6 と、わざと解析できない入力を置いたモジュール（§21 の YAML のエイリアス、§15 の `bun.lockb`、§49 の壊れた `skill.contract.json` など））:

| フィクスチャ | 検知 | 自動 | チェックリスト | defer / exception | held | apply 後 | restore 後 | 結果 |
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
| **合計** | **331** | **80** | **185** | **47** | **19** | **251** | **331** | **53/53** |

`ger preview` が拒否してチェックリストに切り替えたもの: Codex の `a-dotted-top`・`d-dotted-under-table`・`i-inline-nested`（ドット区切りのキーやインラインテーブルで定義したサーバー）、litellm の `litellm-1.107.0.dist-info`（RECORD が無く、メタデータだけを隔離するとコードが残るため。Q-6）、r3-symlink-config の `ev/.vscode/tasks.json` と `ev/.mcp.json`（対象がシンボリックリンク。GER はリンク越しに編集しない）。

## ライセンス

[Apache License 2.0](LICENSE)。脆弱性の報告は [SECURITY.ja.md](SECURITY.ja.md) を参照してください。
