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
- **承認は計画の中身に結びつく**: `approval_token` は確定 plan の `plan_hash`。承認後に計画を変えると止まります
- **dry-run 必須**: 同一入力の dry-run 成功記録（既定 24 時間以内）が無いと apply できません
- **全件ロールバック**: 1 件でも失敗したら残りを実行せず、適用済みを逆順に戻します
- **外部プロセスを起動しない**: chmod も `os.fchmod` で行います。Python 3.11 以上の標準ライブラリのみ
- **初版の操作は chmod のみ**: `write_config` / `rotate_secret` を含む計画は全体を拒否します

## 使い方

```bash
bin/ger verify  ger-input.json --operator ops
bin/ger dry-run ger-input.json --operator ops -o dry-run-log.json
bin/ger apply   ger-input.apply.json --operator ops -o apply-log.json   # mode だけ "apply" に変えた入力
```

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
| 5 | ロールバックも完了できなかった（要手動対応） |
| 64 / 70 | 引数・環境エラー / 内部エラー |

環境変数: `GER_LOG_DIR`（監査ログ、既定 `~/.local/state/ger/`）、`GER_DRYRUN_TTL`（dry-run 記録の有効秒数、既定 86400、最大 604800）。
`--now`（現在時刻の上書き）はテスト専用で、`GER_ALLOW_NOW_OVERRIDE=1` のときだけ受け付けます（それ以外は終了コード 64）。

`-o` の出力先は変更を始める前に確認します（親ディレクトリが存在し書き込めること、既存のディレクトリでないこと、監査ログ・監査ログのディレクトリ内のファイル・入力ファイル・計画の対象のいずれとも同じファイルでないこと。実パスと、既存なら `st_dev`/`st_ino` で比較するためシンボリックリンクやハードリンク経由でも拒否します）。違反は終了コード 64 で、計画の対象との衝突は入力を読んだ後に判明するため監査ログに `result: "error"` として理由付きで記録します。remediation-log は監査ログより先に書き出し、書けなかった場合は成功として記録しません（apply で変更が残っている可能性があるときは終了コード 5）。

## ゲート

| # | 拒否する条件 |
|---|---|
| G-1 | スキーマ不適合（入力・plan とも strict、版固定）、入力に `findings` がある、mode とコマンドの不一致、remediate の item で `finding_id` が重複（実行結果を item に一意に対応づけられない）、`approved_at` / `created_at` が実在しない日時（2 月 30 日、25 時など）、入力 JSON の object でキーが重複・入れ子が 64 段を超える |
| G-2 | plan.status が ok / partial 以外（draft・error） |
| G-3 | plan_hash が本体と不一致、approval.plan_id 不一致、approval_token ≠ plan_hash、approved_at が未来または計画作成前 |
| G-4 | `--operator` が承認者に含まれる（人名は大文字小文字を区別せずに比較） |
| G-5 | 操作が allowed_actions に無い、または GER 未対応 |
| G-6 | reversible / skillpact_effects が無い（ZET 確定済みでない）、reversible が操作の性質と不一致、不可逆操作で承認者 2 名未満（大文字小文字だけが異なる名前は同一人物として数える） |
| G-7 | 対象が正規化済みの絶対パスでない・存在しない・シンボリックリンク（途中経路を含む）・通常ファイル/ディレクトリ以外・所有者でない・計画内で重複（ハードリンクで同じ実体を指す場合を含む）、chmod の mode が `^0[0-7]{3}$` 以外 |
| G-8 | apply 時に、同一 plan_hash・同一入力（mode 以外）の dry-run 成功記録が有効期限内に無い、または監査ログのハッシュチェーンが壊れている |

実行中は、事前検証時の実体 ID（`st_dev`・`st_ino`・`st_ctime_ns`）と一致する場合だけ変更します。i-node 番号は削除・再作成で再利用されることがあるため、ctime も含めて同一の実体かを判定しています。

## スキーマ

| ファイル | 所有 | 内容 |
|---|---|---|
| [schemas/remediation-log.schema.json](schemas/remediation-log.schema.json) | **GER** | 出力契約（契約 §6 に `mode` と `plan_hash` を追加） |
| [schemas/ger-input.schema.json](schemas/ger-input.schema.json) | GER | 入力 |
| [schemas/vendor/remediation-plan.schema.json](schemas/vendor/remediation-plan.schema.json) | ZET | 版固定の写し（`schemas/vendor/VENDOR.json` に取り込み元コミットと SHA-256） |

## 監査ログ

`$GER_LOG_DIR/ger-audit.jsonl`。1 行 1 レコード（command / operator / plan_id / plan_hash / input_hash / output_hash / started_at / finished_at / result / gate_failed / prev_hash）。拒否も記録します。ログに書けない場合は実行しません。既存のログディレクトリが実行ユーザーの所有でない、またはグループ・他者から書き込み可能な場合も実行しません（終了コード 64）。

## テスト

```bash
tests/run-tests.sh   # 単体テスト（41 件。一時ディレクトリの実ファイルで chmod・ロールバック・差し替え検出を検証）＋ strace による外部プロセスゼロ検証
```

root で実行すると「読めないファイル（0000）」のテストは SKIP になります（一般ユーザーでは 41 件すべて実行）。ZET が確定した実際の計画（`tests/fixtures/zet-final-plan.json`）で、スキーマと plan_hash の互換性も確認しています。

## ライセンス

[Apache License 2.0](LICENSE)。脆弱性の報告は [SECURITY.md](SECURITY.md) を参照してください。
