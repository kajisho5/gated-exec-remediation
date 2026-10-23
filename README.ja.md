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

- **ゲート G-1〜G-8**: 1 つでも失敗したら何も変更しません
- **承認は計画の中身に結びつく**: `approval_token` は確定 plan の `plan_hash`。承認後に計画を変えると止まります（示すのは完全性で、真正性ではありません。[承認](#承認) を参照）
- **dry-run 必須**: 同一入力の未使用の dry-run 成功記録（既定 24 時間以内）が無いと apply できません。dry-run 1 回で apply は 1 回です
- **修復は権限を絞るだけ**: chmod は対象の現在の mode に無い権限ビットを足せません
- **全件ロールバック**: 1 件でも失敗したら残りを実行せず、適用済みを逆順に戻します
- **外部プロセスを起動しない**: chmod も `os.fchmod` で行います。Python 3.11 以上の標準ライブラリのみ
- **初版の操作は chmod のみ**: `write_config` / `rotate_secret` を含む計画は全体を拒否します

## 使い方

```bash
bin/ger verify  ger-input.json --operator ops
bin/ger dry-run ger-input.json --operator ops -o dry-run-log.json
bin/ger apply   ger-input.apply.json --operator ops -o apply-log.json   # mode だけ "apply" に変えた入力
bin/ger verify-log
```

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

環境変数: `GER_LOG_DIR`（監査ログ、既定 `$XDG_STATE_HOME/ger/`。`XDG_STATE_HOME` が未設定なら `~/.local/state/ger/`。起動時に一度だけ実パスへ解決し、ログの読み書きはすべて解決後のパスで行います）、`GER_DRYRUN_TTL`（dry-run 記録の有効秒数、既定 86400、最大 604800）、`GER_APPROVAL_MAX_AGE`（承認の有効秒数。`approved_at` から数え、既定 604800 = 7 日、最大 31622400）。
`--now`（現在時刻の上書き）はテスト専用で、`GER_ALLOW_NOW_OVERRIDE=1` のときだけ受け付けます（それ以外は終了コード 64）。`--now` を使った実行は監査ログに `now_override: true` として記録します。G-8 は同じ扱いの dry-run 記録だけを数えます（`--now` なしの apply は `--now` なしの dry-run だけ、`--now` 付きの apply は `--now` 付きの dry-run だけ。期限切れの実時刻の記録を `--now` で期限内に見せかけられません）。ZET が `--now` で draft / finalize した計画には `now_override: true` が付き、`GER_ALLOW_NOW_OVERRIDE=1` でなければ G-2 で拒否します。

`-o` の出力先は変更を始める前に確認します（空でなく末尾が `/` でないこと、指定されたパスのままの親ディレクトリが存在し書き込めること、既存なら通常ファイルであること（ディレクトリ・FIFO・ソケット・`/dev/null` などのデバイス・シンボリックリンクは拒否。remediation-log はアトミックな rename で書き出し、リンク先ではなくリンク自体を置き換えてしまうため、シンボリックリンクはたどらずに拒否します）、監査ログ・監査ログのディレクトリ内のファイル・入力ファイル・計画の対象のいずれとも同じファイルでないこと、計画の対象に親ディレクトリやその上位ディレクトリ（与えられたパスの字句上の上位（途中のシンボリックリンクを置いたディレクトリを含む）と実パスの上位の両方）が含まれないこと（apply 後に remediation-log を書けなくなるため）。実パスと、既存なら `st_dev`/`st_ino` で比較するため親ディレクトリのパスにあるシンボリックリンクやハードリンク経由でも拒否します）。違反は終了コード 64 で、計画の対象との衝突は入力を読んだ後に判明するため監査ログに `result: "error"` として理由付きで記録します。remediation-log は監査ログより先に書き出し、書けなかった場合は成功として記録せず、今回の記録と取り違えないよう `-o` の位置にある以前のファイルを削除します（apply で変更が残っている可能性があるときは終了コード 5。全件を適用しロールバックしていない場合、監査ログには `result: "applied_unlogged"` と記録し、`rollback_failed` はロールバックに失敗した場合だけです）。

## 承認

`approval_token` は確定 plan の `plan_hash`（正規化 JSON の SHA-256）と一致し、`approval.plan_id` は plan と一致している必要があります。これが示すのは **完全性だけで、真正性ではありません**。ハッシュを計算した時点から plan が変わっていないことは分かりますが、ZET が作った plan であることや承認者がその plan を見たことは示しません。`zet finalize` の後に plan を書き換えて `plan_hash` を計算し直し、`approval_token` も合わせた場合は **暗号的には検出できません**。検出には承認者による plan への署名が必要で、将来の課題です。

そのような plan でできることを狭めるため、GER は ZET の不変条件のうち plan だけで評価できるものをすべて再検査し（G-1: I-4 の action の形と対象パスの形、ZET が各 item に写す `skillpact` の要約に対する I-5 / I-6 / I-7、承認者の人数、自己承認、日付の前後関係など。G-1 の行を参照）、chmod は対象の現在の mode から権限ビットを外すことだけを許し（G-7）、`evidence_hash` があれば現在のファイルと比べます（G-7）。findings が無いと確かめられないのは「対象が finding の指すパスであること」（ZET の I-4）です。そのため、書き換えて再ハッシュした plan は別の対象を選べますが、できるのは実行者が所有するファイルの権限を絞ることだけで、緩めることはできません。また承認は `approved_at` から `GER_APPROVAL_MAX_AGE` 秒（既定 7 日）で失効し、現在時刻が remediate の item の `due_at` の最大値を過ぎた計画も拒否します。

## ゲート

| # | 拒否する条件 |
|---|---|
| G-1 | スキーマ不適合（入力・plan とも strict、版固定。`skillpact_effects` は SkillPact 0.8 の 6 効果のみ）、入力に `findings` がある、mode とコマンドの不一致、remediate の item で `finding_id` が重複（実行結果を item に一意に対応づけられない）、`approved_at` / `created_at` / item の日時が実在しない日時（2 月 30 日、25 時など）、入力 JSON の object でキーが重複・入れ子が 64 段を超える。さらに findings やポリシーが要らない ZET の不変条件（メッセージは `ZET I-n 相当`）: items と held を通じて finding_id が重複（I-1）、exception に exception_type / reason / recheck_at・承認者が無い、exception 以外に exception_type がある、INFO 以外の defer に reason / recheck_at が無い、判断者が item の承認者に含まれる（I-3）、remediate に owner / due_at / action が無い、remediate 以外に action がある、対象が正規化済みの絶対パスでない（`.` `..` 連続した `/`（先頭の `//` を含む）不可）（I-4）、乖離のある finding が exception（I-5）、item の承認者の重複、diff_anomaly の finding や exec / network / spend / send を宣言したスキルの remediate で item の承認者が 2 名未満（I-6）、署名フィールドがあり乖離のある finding が CRITICAL でない（I-7）、`skillpact_effects` が item の `skillpact.declared_effects` と不一致、decided_at が created_at より前・未来、due_at / recheck_at が decided_at より前（I-9）、partial なのに held が空（I-12） |
| G-2 | plan.status が ok / partial 以外（draft・error）、plan に `now_override: true`（ZET が `--now` で作成）があり `GER_ALLOW_NOW_OVERRIDE` が `1` でない、現在時刻が remediate の item の `due_at` の最大値を過ぎている（計画の期限切れ。ZET で判断し直す） |
| G-3 | plan_hash が本体と不一致、approval.plan_id 不一致、approval_token ≠ plan_hash、approved_at が未来または計画作成前、承認が `GER_APPROVAL_MAX_AGE` 秒（既定 7 日）より古い |
| G-4 | `--operator` が承認者に含まれる（人名は大文字小文字を区別せずに比較） |
| G-5 | 操作が allowed_actions に無い、または GER 未対応 |
| G-6 | reversible / skillpact_effects（[SkillPact](https://github.com/kajisho5/skillpact) の effects）が無い（ZET 確定済みでない）、reversible が操作の性質と不一致、不可逆操作で承認者 2 名未満、危険な効果（exec / network / spend / send）を宣言したスキルへの操作が allowed_actions に明示されていない・承認者 2 名未満（承認者は `approval.approved_by`。大文字小文字だけが異なる名前は同一人物として数える）。ZET の I-6 も item に同じ 2 名を求める |
| G-7 | 対象が正規化済みの絶対パスでない・存在しない・シンボリックリンク（途中経路を含む）・通常ファイル/ディレクトリ以外・所有者でない・監査ログ／監査ログのディレクトリ／それらの上位ディレクトリ（指定された `GER_LOG_DIR` の字句上の上位（途中のシンボリックリンクを置いたディレクトリを含む）と実パスの上位の両方。変更すると GER が記録できなくなる）・計画内で重複（ハードリンクで同じ実体を指す場合を含む）、chmod の mode が `^0[0-7]{3}$` 以外・world-writable・対象の現在の mode に無い権限ビットを足す（修復は権限を絞るだけ）、`action.evidence_hash` があり現在のファイルと一致しない（ZES と同じ規則で計算: 100MB 以下の通常ファイルは内容の SHA-256、100MB 超は `path\|size\|mtime` の SHA-256。ディレクトリは ZES が finding の detail をハッシュするため比べない） |
| G-8 | apply 時に、同一 plan_hash・同一入力（mode 以外）・同じ `--now` の扱いの、未使用の dry-run 成功記録が有効期限内に無い、または監査ログのハッシュチェーンが壊れている（UTF-8 の JSON object として読めない行も壊れているとみなす）。dry-run 記録は、その後に同じ計画・同じ入力で実行まで進んだ apply（result が `ok` / `rolled_back` / `rollback_failed` / `applied_unlogged`）で使用済みになる。拒否や変更前の引数エラーでは使用済みにならない |

実行中は、事前検証時の実体 ID（`st_dev`・`st_ino`・`st_ctime_ns`）と一致する場合だけ変更します。i-node 番号は削除・再作成で再利用されることがあるため、ctime も含めて同一の実体かを判定しています。

## スキーマ

| ファイル | 所有 | 内容 |
|---|---|---|
| [schemas/remediation-log.schema.json](schemas/remediation-log.schema.json) | **GER** | 出力契約（契約 §6 に `mode` と `plan_hash` を追加） |
| [schemas/ger-input.schema.json](schemas/ger-input.schema.json) | GER | 入力 |
| [schemas/vendor/remediation-plan.schema.json](schemas/vendor/remediation-plan.schema.json) | ZET | 版固定の写し（`schemas/vendor/VENDOR.json` に取り込み元コミットと SHA-256） |

## 監査ログ

`$GER_LOG_DIR/ger-audit.jsonl`。1 行 1 レコード（command / operator / plan_id / plan_hash / input_hash / output_hash / started_at / finished_at / result / gate_failed / now_override / prev_hash）。拒否も記録します。`bin/ger verify-log` でハッシュチェーン全体を検証できます。追記の前に末尾の連結（最終行が改行で終わる JSON object で、直前の行のハッシュを持つこと）を確かめ、壊れたチェーンには追記しないため何も実行しません（終了コード 64。`verify-log` で確認し、ログを退避してから実行し直してください）。ログに書けない場合は実行しません。既存のログディレクトリが実行ユーザーの所有でない、またはグループ・他者から書き込み可能な場合も実行しません（終了コード 64）。

## テスト

```bash
tests/run-tests.sh   # 単体テスト（一時ディレクトリの実ファイルで chmod・ロールバック・差し替え検出を検証）＋ strace による外部プロセスゼロ検証
```

root で実行すると「読めないファイル」のテストは SKIP になります（一般ユーザーでは実行されます）。ZET が確定した実際の計画（`tests/fixtures/zet-final-plan.json`）で、スキーマと plan_hash の互換性も確認しています。

## ライセンス

[Apache License 2.0](LICENSE)。脆弱性の報告は [SECURITY.md](SECURITY.md) を参照してください。
