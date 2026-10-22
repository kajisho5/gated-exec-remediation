# GER（Gated-Exec Remediation）詳細設計書 — Step 1

- **版**: 設計 0.1（2026-10-22）／ 2026-10-22 承認（C-1〜C-6 を採用）、実装 0.1.0
- **層**: 修復層（ZES → ZET の後段。3 層で唯一、変更を実行する）
- **原則**: Gated-Exec。すべてのゲートを通過した操作だけを、計画に書かれた対象にだけ、冪等に実行する
- **上位文書**: [ZES スキル契約書](https://github.com/kajisho5/zero-exec-shield/blob/claude/zes-v5.2-skillpact/docs/skill-contracts.md)（§1, §5〜§8）、[ZET 設計書](https://github.com/kajisho5/zero-exec-triage/blob/claude/zet-design/docs/design/design.md)

```
[ZET] remediation-plan.json ─┐
人間の承認（approval）───────┼─▶ [GER] ゲート 1〜7 ─▶ dry-run ─▶ apply ─▶ remediation-log.json
allowed_actions ─────────────┘
```

---

## 1. 要件定義

### 1.1 目的
ZET が確定した修復計画を、人間の明示承認を受けたうえで実行する。誤った計画・承認のない計画・計画外の対象への変更を **実行前に** すべて止めることが最優先で、修復の網羅性は二の次とする。

### 1.2 初版のスコープ

| 操作 | 初版 | 理由 |
|---|---|---|
| `chmod` | **実装** | 可逆・ローカル・冪等で、ZES §11（SSH/GPG 権限）の修復にそのまま使える |
| `write_config` | 未対応として **拒否** | 設定ファイルの書き換え範囲（差分形式・対象形式）が契約で未定義 |
| `rotate_secret` | 未対応として **拒否** | 外部サービスの認証情報を変える不可逆操作。対象サービスと API の取り扱いを決めてから |

未対応の操作を含む計画は、**その 1 件だけでなく計画全体を事前検証で拒否**する（部分適用禁止）。

### 1.3 機能一覧

| コマンド | 内容 | 終了コード |
|---|---|---|
| `ger verify <ger-input.json>` | ゲート 1〜6 の検証のみ（変更なし） | 0=OK / 3=拒否 / 64=引数 |
| `ger dry-run <ger-input.json>` | 検証＋各操作の before/after を計算してログに記録（変更なし） | 0 / 3 |
| `ger apply <ger-input.json>` | 検証＋同一計画の dry-run 記録を確認して実行。失敗時は全件ロールバック | 0 / 3=拒否 / 4=失敗しロールバック済 / 5=ロールバックも失敗 |

`ger-input.json` は契約 §5（`schema_version` / `plan` / `approval` / `mode` / `allowed_actions`）。`mode` とサブコマンドが食い違う場合は拒否。

### 1.4 非機能要件
- **依存ゼロ**: Python 3.11 以上の標準ライブラリのみ。`python3 -I` で起動
- **外部プロセスを起動しない**: `chmod` も `os.chmod` で行い、シェル・外部コマンドを使わない
- **fail-closed**: どのゲートでも失敗したら何も変更しない
- **冪等**: 既に目標状態なら `skipped`（`reason: "already_compliant"`）

---

## 2. ゲート（実行前の全検査）

| # | ゲート | 拒否条件 | 根拠 |
|---|---|---|---|
| G-1 | スキーマ | 入力・plan が strict スキーマに不適合、`schema_version` 不一致、入力に `findings` キーがある | 飛び越し禁止・版固定 |
| G-2 | 計画状態 | `plan.status` が `ok`/`partial` 以外（`draft`・`error` は拒否） | 失敗の伝播（ZET A-1） |
| G-3 | 承認 | `approval.plan_id != plan.plan_id`、`approval_token != plan_hash`、`approved_by` が空 | 承認なき実行禁止（§3） |
| G-4 | 自己承認防止 | `approval.approved_by` に `--operator` が含まれる | 承認の連鎖 |
| G-5 | 許可リスト | `action.type` が `allowed_actions` 外、または GER 未対応 | 許可リスト方式 |
| G-6 | 二重承認 | `action.reversible == false` で `approval.approved_by` が 2 名未満。`action.skillpact_effects` に exec/network/secrets を含むのに、その操作が `allowed_actions` に明示されていない | `reversible: false`・SkillPact 不変条件 |
| G-7 | 対象の事前検証（全件） | 対象が存在しない／絶対パスでない／`..` を含む／シンボリックリンク（`lstat`）／計画外のパス／操作固有の検証失敗 | 対象の限定・部分適用禁止 |
| G-8 | dry-run 記録（apply のみ） | 同じ `plan_hash` と `input_hash` の dry-run 成功記録が監査ログに無い、または `GER_DRYRUN_TTL`（既定 24 時間）より古い | dry-run を経ない apply 禁止 |

`held[]` は読まない。`items[]` のうち `decision == "remediate"` のものだけが実行対象（`exception` / `defer` は `skipped`）。

---

## 3. 実行とロールバック

```
全件 G-1〜G-8 → OK
  └─ for item in items(remediate):
        before = 現状を記録（chmod: lstat の st_mode & 0o7777）
        if before == after: skipped(already_compliant); continue
        適用 → 直後に再 lstat で after を確認（TOCTOU 対策: 適用前後で st_ino / st_dev 一致を確認）
        失敗 → 中止し、適用済みを逆順に before へ戻す（rolled_back）
```

- 1 件でも `failed` が出たら残りは実行しない（契約 §7）
- ロールバック自体が失敗した場合は終了コード 5、ログに対象と状態を全件記録して人手対応を促す
- `chmod` の `params`: `{"mode": "0600"}`（8 進文字列のみ受理。setuid/setgid/sticky ビット付与は拒否）。ディレクトリへの再帰適用はしない（親・子への遡及禁止）

---

## 4. 承認トークン

契約の `approval_token` は形式が未定義のため、**plan 本体の正規化 JSON（キー順ソート、区切り `,`/`:`、UTF-8）の SHA-256 = `plan_hash`** と一致することを要求する（ZET A-6）。承認者は確定 plan のハッシュに対して承認するので、承認後に plan を差し替えると G-3 で止まる。

将来の強化案（初版対象外）: 承認者ごとの署名（SSH 署名 `ssh-keygen -Y verify` 等）。ただし外部コマンド起動を伴うため、採用時は Zero-Exec 方針との整理が必要。

---

## 5. 監査ログ（追記専用）

- 既定パス: `$GER_LOG_DIR/ger-audit.jsonl`（既定 `~/.local/state/ger/`、ZES・ZET とは別ファイル・別リテンション）
- 1 行 1 レコード: `skill`（"ger"）/ `version` / `command` / `plan_id` / `plan_hash` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator` / `result` / `gate_failed`（拒否時）
- 出力 `remediation-log.json`（契約 §6）は実行ごとに別ファイルで書き出し、そのハッシュを監査ログに残す
- ハッシュチェーン（`prev_hash`）を持たせる（ZET B-2 と同方式）。G-8 は監査ログのチェーンが壊れていたら dry-run 記録を信用せず拒否する

---

## 6. 構成（実装に合わせて更新）

```
gated-exec-remediation/
├── SKILL.md                          # エージェント向け手順（承認を代行しない、apply 前に必ず dry-run）
├── bin/ger                           # 起動スクリプト（bash 組み込みのみでパス解決し python3 -I で起動）
├── ger/
│   ├── __main__.py / cli.py          # 引数・終了コード・--operator 必須・監査ログ記録
│   ├── gates.py                      # G-1〜G-8（変更を一切行わない）
│   ├── executor.py                   # dry-run / apply / 全件ロールバック
│   ├── actions/{__init__.py, chmod.py}   # 操作レジストリ（未登録の type は G-5 で拒否）
│   ├── audit.py                      # 追記専用ログ＋ハッシュチェーン＋dry-run 記録の検索
│   ├── core.py                       # 正規化 JSON・plan_hash / input_hash・原子的書き出し
│   └── jsonschema_lite.py            # ZET と同一の検証器（VENDOR.json で版固定）
├── schemas/{ger-input, remediation-log}.schema.json
├── schemas/vendor/{remediation-plan.schema.json, VENDOR.json}
├── tests/{run.py, run-tests.sh, test_ger.py, fixtures/zet-final-plan.json}
├── docs/design/{design.md, flow.svg}
├── README.md
└── CHANGELOG.md
```

実装時の変更点:
- 実体の同一性判定を `(st_dev, st_ino)` から `(st_dev, st_ino, st_ctime_ns)` に強化した。削除・再作成で i-node 番号が再利用され、差し替えを検出できないことをテストで確認したため
- `input_hash` は入力から `mode` を除いた正規化 JSON の SHA-256（dry-run と apply で同一入力かを判定するため）
- remediation-log に `mode` と `plan_hash` を追加（契約 §6 への追加。どの計画のどの実行かを一意にするため）

操作は共通インターフェース（`plan(target, params) -> (before, after)` / `apply()` / `rollback(before)` / `verify(after)`）で追加する。`write_config` / `rotate_secret` は設計が固まるまでレジストリに登録しない。

---

## 7. エッジケース

| ケース | 扱い |
|---|---|
| 対象が dry-run 後に削除・置換された | apply 時の G-7 と st_ino 確認で失敗 → 全件ロールバック |
| 対象がシンボリックリンク | 拒否（リンク先を変更させない） |
| 同じ対象に 2 件の chmod | 計画の矛盾として拒否 |
| root 所有で権限不足 | 事前検証（`os.access` ではなく所有者・実効 UID で判定）で拒否 |
| `mode` が `"600"`（先頭 0 なし）や `0o600` | 文字列 `^0[0-7]{3}$` のみ受理 |
| ログディレクトリに書けない | 何も実行せず拒否（記録できない操作はしない） |

---

## 8. テスト方針
- ゲートごとに合格・拒否を最低 1 組（G-1〜G-8）
- chmod: 一時ディレクトリで before/after、冪等（2 回目は skipped）、ロールバック（途中で失敗を注入）
- 承認後の plan 差し替えを G-3 で検出
- dry-run なし apply の拒否、期限切れ dry-run の拒否、ハッシュチェーン破損時の拒否
- 外部プロセスゼロ: `strace -f -e trace=execve` で `python3` 以外の execve が 0 件

---

## 9. 要承認事項

| ID | 内容 | 推奨 |
|---|---|---|
| C-1 | 初版は `chmod` のみ、他は計画全体を拒否 | 採用 |
| C-2 | `approval_token = plan_hash`（§4） | 採用 |
| C-3 | dry-run の有効期限 24 時間（G-8） | 採用 |
| C-4 | apply の終了コード 4（ロールバック済）/ 5（ロールバック失敗） | 採用 |
| C-5 | Python 3.11+ 標準ライブラリのみ、外部コマンド不使用 | 採用 |
| C-6 | ZET 設計書 A-4（`reversible` / `skillpact_effects` を plan で受け取る）に依存 | ZET と同時に承認 |
