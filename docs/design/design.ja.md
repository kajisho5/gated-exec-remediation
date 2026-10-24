[English](design.md) | 日本語

# GER（Gated-Exec Remediation）詳細設計書 — Step 1

- **版**: 設計 0.1（2026-10-22）／ 2026-10-22 承認（C-1〜C-6 を採用）、実装 0.1.0
- **追補**: 修復能力拡張 設計 0.2（2026-10-23 承認。Q-1〜Q-6 を推奨どおり採用）の Phase 1 を実装（§10）。§1〜§9 は Phase 1 に合わせて更新した
- **層**: 修復層（ZES → ZET の後段。3 層で唯一、変更を実行する）
- **原則**: Gated-Exec。すべてのゲートを通過した操作だけを、計画に書かれた対象にだけ、冪等に実行する
- **上位文書**: [ZES スキル契約書](https://github.com/kajisho5/zero-exec-shield/blob/main/docs/skill-contracts.md)（§1, §5〜§8）、[ZET 設計書](https://github.com/kajisho5/zero-exec-triage/blob/main/docs/design/design.md)

```
[ZET] draft ─▶ [GER] preview（params のハッシュ・ops を埋める。変更なし）─▶ [ZET] finalize
[ZET] remediation-plan.json ─┐
人間の承認（approval）───────┼─▶ [GER] ゲート 1〜10 ─▶ dry-run ─▶ apply ─▶ remediation-log.json
allowed_actions ─────────────┘                                  └─▶ 隔離ストア（restore で戻せる）・checklist（confirm で記録）
```

---

## 1. 要件定義

### 1.1 目的
ZET が確定した修復計画を、人間の明示承認を受けたうえで実行する。誤った計画・承認のない計画・計画外の対象への変更を **実行前に** すべて止めることが最優先で、修復の網羅性は二の次とする。

### 1.2 スコープ（Phase 1）

| 操作 | Phase 1 | 内容 |
|---|---|---|
| `chmod` | 実装（初版から） | 権限を絞るだけ。ZES §11（SSH/GPG 権限） |
| `quarantine` | **実装** | ファイル・ツリー・シンボリックリンクを隔離ストアへ rename で移す。関係 self / npm_pkg_dir / npm_installed / pypi_record / ext_dir / skill_dir |
| `edit_json` | **実装** | JSON / JSONC の H に一致するメンバーを取り除く・K の定数に置き換える（書式とコメントを保つ） |
| `edit_toml` | **実装（Phase 1 の範囲）** | 標準のテーブルヘッダで定義された `[mcp_servers.<name>]` を取り除く。ドット区切りのキー・インラインテーブルは拒否 |
| `remove_line` | **実装** | シェルの rc・git config・php.ini・ld.so.preload・/etc/cron.d の H に一致する最上位の 1 行を取り除く |
| `disable_mcp_server` | **実装** | edit_json / edit_toml の preset（MCP サーバーの定義だけ） |
| `checklist` | **実装** | GER はファイルを変えない。apply で `pending_manual`、`ger confirm` で手順ごとに記録 |
| `ger restore` | **実装** | 計画の外のコマンド。隔離したもの・編集前のファイルを戻す（承認者 2 名・dry-run 必須） |
| `replace_token` / `pin_action` / `pin_digest` / `ensure_line`、関係 plist_program / preload_lib / unit_wants | Phase 2（未実装。G-5 / G-9 で拒否） | |
| `write_config` / `rotate_secret` | 登録しない | 秘密情報の失効・ローテーションはネットワークと不可逆な操作が要るため、どの段階でもチェックリスト |

ファイルを削除する操作は無い。どの操作も変える前の状態を隔離ストアに残す（chmod は元の mode を remediation-log に残す）。未対応の操作を含む計画は、**その 1 件だけでなく計画全体を事前検証で拒否**する（部分適用禁止）。

### 1.3 機能一覧

| コマンド | 内容 | 終了コード |
|---|---|---|
| `ger verify <ger-input.json>` | ゲート 1〜6 の検証のみ（変更なし） | 0=OK / 3=拒否 / 64=引数 |
| `ger dry-run <ger-input.json>` | 検証＋各操作の before/after を計算してログに記録（変更なし） | 0 / 3 |
| `ger apply <ger-input.json>` | 検証＋同一計画の dry-run 記録を確認して実行。失敗時は全件ロールバック | 0 / 3=拒否 / 4=失敗しロールバック済 / 5=ロールバックも失敗 |
| `ger verify-log [LOG]` | 監査ログのハッシュチェーンを検証（読むだけ。この実行は記録しない） | 0=健全 / 3=破損 / 64=ログが無い・読めない |
| `ger preview <draft-plan.json> -o OUT [--report R] [--diff]` | 下書きの action の params（ハッシュ・ops・`expected_after_sha256`）を現在の内容から埋める。変更しない。監査ログに `preview` として記録するが dry-run には数えない | 0 / 3=拒否あり（`--report` に item ごとの理由） |
| `ger confirm <ger-input.json> --item FID --step CL-XXX:sN` | checklist / followup の手順の確認を監査ログに追記（apply の成功記録の後。作業者は承認者でないこと） | 0 / 3 |
| `ger restore <restore-request.json> -o OUT` | 隔離ストアのエントリを戻す（§10.5） | 0 / 3 / 4 / 5 |
| `ger recover <ger-input.json> -o OUT` | ジャーナルに残った未完了の apply を巻き戻す（G-1〜G-4 を適用） | 0 / 3 / 5 |
| `ger quarantine-list [--json] [--plan-id ID]` | 隔離ストアの一覧とマニフェストの検証（読むだけ） | 0 |

`ger-input.json` は契約 §5（`schema_version` / `plan` / `approval` / `mode` / `allowed_actions`）。`mode` とサブコマンドが食い違う場合は拒否。

### 1.4 非機能要件
- **依存ゼロ**: Python 3.11 以上の標準ライブラリのみ。`python3 -I -S` で起動（site を読み込まないので site-packages の `.pth` も実行されない）
- **外部プロセスもネットワークも使わない**: `chmod` も `os.fchmod`、移動は `os.rename`、バックアップは `os.link` で行い、シェル・外部コマンドを使わない。テストで全コマンドの execve とネットワークのシステムコールを strace で確かめる
- **fail-closed**: どのゲートでも失敗したら何も変更しない
- **冪等**: 既に目標状態なら `skipped`（`reason: "already_compliant"`）

---

## 2. ゲート（実行前の全検査）

| # | ゲート | 拒否条件 | 根拠 |
|---|---|---|---|
| G-1 | スキーマ | 入力・plan が strict スキーマに不適合、`schema_version` 不一致、入力に `findings` キーがある。action の params が `schemas/actions.schema.json` と操作の意味の検査に合わない。plan 1.0 に chmod 以外の操作がある。plan 1.1 の action に relation / finding_path / evidence が無い、target が null なのに checklist でない。plan だけで評価できる ZET の不変条件（I-1 の一意性、I-3、I-4 の action の形と対象パスの形、`items[].skillpact` に対する I-5 / I-6 / I-7 と `skillpact_effects` の整合、危険な効果の remediate の承認者 2 名、I-9 の日付の前後関係、I-11 の日時の実在、I-12 の partial と held）に反する | 飛び越し禁止・版固定・承認トークンは完全性しか示さないため（§4） |
| G-2 | 計画状態 | `plan.status` が `ok`/`partial` 以外（`draft`・`error` は拒否）。`now_override: true` の plan（ZET が `--now` で作成）で `GER_ALLOW_NOW_OVERRIDE` が `1` でない。現在時刻が remediate の `due_at` の最大値を過ぎている | 失敗の伝播（ZET A-1）・テスト用の計画と期限切れの計画を実行しない |
| G-3 | 承認 | `approval.plan_id != plan.plan_id`、`approval_token != plan_hash`、`approved_by` が空、`approved_at` が未来・plan 作成前・`GER_APPROVAL_MAX_AGE`（既定 7 日）より古い | 承認なき実行禁止（§3）・古い承認の再利用禁止 |
| G-4 | 自己承認防止 | `approval.approved_by` に `--operator` が含まれる | 承認の連鎖 |
| G-5 | 許可リスト | `action.type` が `allowed_actions` 外、または GER 未対応 | 許可リスト方式 |
| G-6 | 二重承認 | `action.reversible == false`・破壊的な操作（Phase 1 には無い）・root が必要な対象で `approval.approved_by` が 2 名未満（plan 1.1 では item の `approved_by` にも 2 名を求める）。`action.skillpact_effects` に exec/network/spend/send（SkillPact 0.8）を含むのに、その操作が `allowed_actions` に明示されていない、または `approval.approved_by` が 2 名未満（ZET の I-6 も item の `approved_by` に 2 名を求める） | `reversible: false`・SkillPact 不変条件 |
| G-7 | 対象の事前検証（全件） | 対象が存在しない／正規化済みの絶対パスでない／途中の要素がシンボリックリンク（`/` から 1 要素ずつ `O_PATH\|O_NOFOLLOW\|O_DIRECTORY` でたどる）／監査ログ・隔離ストアとその上位／同じ対象への操作が group 以外で重複・一方が他方の上位／操作固有の検証失敗（chmod: 現在の mode に無い権限ビットを足す。quarantine: 種類・ハッシュ・`st_nlink`・FIFO・別のデバイス。編集: 1 MiB 超・xattr・`file_sha256` と `expected_after_sha256` の不一致）／`action.evidence`（1.0 は `evidence_hash`）が現在の finding_path と不一致 | 対象の限定・部分適用禁止・dry-run の結果を apply に縛る |
| G-9 | 範囲と関係 | ファイルを変える操作（chmod 以外）で `plan.scope` が無い・対象が `scope.roots` と `scope.home` の外／隔離ストアが scope.roots・site-packages・node_modules・PATH の下／保護対象（§10.6）／`/etc` の許可リスト外／root が必要な対象（システムのディレクトリの下・所有者が実行ユーザーでない）で承認者が 2 名未満、または root が必要な対象とそうでない対象が同じ計画にある／`action.relation` が字句上・ファイルシステム上で成り立たない（§10.3） | 対象と finding の関係を GER が自分で導き直す |
| G-10 | 定義 T（絞るだけ） | 取り除く単位が GER の表 H に一致しない（T-1）・足すものが表 K に無い（T-2）・変更後をパースし直した結果が「変更前 − 取り除いた単位 ⊕ K の置き換え」と一致しない（T-3）・見かけだけの修復（Q-6） | 改ざんされた計画でも緩める変更をさせない |
| G-8 | dry-run 記録と未完了のジャーナル | apply: 同じ `plan_hash` と `input_hash`、同じ `--now` の扱いの、未使用の dry-run 成功記録が監査ログに無い、または `GER_DRYRUN_TTL`（既定 24 時間）より古い。記録は apply が最初の変更の前に追記する開始の記録（`result: "started"`）で使用済みになる（途中で強制終了された apply でも使用済み。§3.1）。verify / dry-run / apply: 隔離ストアに未完了のジャーナル（強制終了された apply、ロールバックに失敗した apply）がある。先に `ger recover` を実行する | dry-run を経ない apply 禁止・1 回の dry-run で 1 回の apply・未完了の apply の上に apply しない |

`held[]` は読まない。`items[]` のうち `decision == "remediate"` のものだけが実行対象（`exception` / `defer` は `skipped`）。

---

## 3. 実行とロールバック

Phase 1 では、同じ `action.group` の item を 1 つのステップ（トランザクション）にまとめ、ステップを
(1) 参照を取り除く編集（edit_json / edit_toml / remove_line / disable_mcp_server）→ (2) quarantine → (3) chmod → (4) checklist
の順に実行する（同じ種類の中では計画の順）。結果は item ごとに出す（group の item は `reason: "group:<id>"`）。
ファイルを変えるステップは、各段階の前後でジャーナル（隔離ストアの `journal/<run_id>.jsonl`、fsync 付き）に undo の情報を書く。
例外による失敗は全件を逆順にロールバックし（終了コード 4）、ロールバックにも失敗したらジャーナルを開いたまま残す（終了コード 5）。
プロセスが途中で落ちた場合も含め、開いたままのジャーナルは `ger recover` で巻き戻す。以下は初版（chmod）からの規則:

```
全件 G-1〜G-8 → OK
  └─ for item in items(remediate):
        before = 現状を記録（chmod: lstat の st_mode & 0o7777）
        if before == after: skipped(already_compliant); continue
        適用 → 直後に再 lstat で after を確認（TOCTOU 対策: 適用前後で st_ino / st_dev 一致を確認）
        失敗 → 中止し、適用済みを逆順に before へ戻す（rolled_back）
```

### 3.1 強制終了・再実行・recover

強制終了された apply（SIGKILL、電源断）は監査ログに最後の記録を書かず、ジャーナルを開いたまま残す。再実行とその後の `ger recover` が確定済みの修復を元に戻さないよう、次の 2 つの規則を置く。

1. **dry-run 記録は最初の変更の前に使用済みにする。** ゲートを通った後、apply は監査ログのロックの下で未使用の dry-run 記録があることを確かめ直してから、開始の記録（`command: "apply"`、`result: "started"`、ジャーナルの `run_id` 付き）を追記する。何かを変えるのはその後。最初の apply が強制終了されていても、同じ dry-run での 2 回目の apply は G-8 で拒否する。最後の記録にも同じ `run_id` が入る
2. **未完了のジャーナルの上では何も実行しない。** 隔離ストアに開いたままのジャーナルがある間、verify・dry-run・apply は G-8 で拒否し、そのジャーナルの run id と plan id を示す。作業者は先にその計画の入力で `ger recover` を実行する。recover でも閉じられないジャーナル（ロールバックがまた失敗する）は人手で解決し、その後ジャーナルのファイルを `<store>/journal/` から手で移す

`ger recover` は安全なときだけ開いたジャーナルを再生する。

- **上書きされたジャーナルは再生しない。** そのジャーナルの実行の開始の記録より後に、別の apply（開始した、または実行した）か restore が監査ログにあれば、ジャーナルを `superseded` の事象で閉じ、何も巻き戻さない。後の実行が同じ対象を変えたか確かめており（`already_compliant`）、古いジャーナルを再生するとそれを元に戻してしまうため。対象は今の状態のままで、dry-run と apply で計画を完了する。以前の GER が書いたジャーナルには開始の記録が無い。その場合は run id の秒以降に始まったすべての記録を後のものと数える（`run_id` の無い、同じ計画・入力の apply の `rollback_failed` の記録は除く。それ自身の最後の記録でありうるため）
- **全部か無しか。** 何かを元に戻す前に、元に戻すすべてのステップを確かめる。隔離した物がストアにあり元の場所が空いていること、編集したファイルが GER の書いたバイト列（`after_sha256`）のままでバックアップがあること、chmod の対象が同じ i-node で GER の mode であること。1 つでも合わなければ何も元に戻さず、ジャーナルは開いたまま、終了コードは 5
- **変更とそのジャーナルの行の間で落ちた場合。** 段階は、それが告げる変更の前にジャーナルに書く。変更の直後にプロセスが落ちたら、recover はファイルシステムから状態を読む。段階 `entry` の移動でペイロードがすでにストアにあれば移動済み、段階 `linked` の編集で一時ファイルが無く対象が期待した内容の新しい i-node なら置き換え済み、chmod の意図（`stage: "start"`、変更の前に記録）は mode が GER のものであるときだけ元に戻す。落ちる直前に作ったバックアップのハードリンク（対象は変わっていない）は、対象が `st_nlink` 2 のまま残らないようストアから外す（内容は対象に残る）。途中で止まったロールバックで元に戻っていたステップは、それと認めて飛ばす

テスト `TestKillPoints` は、apply をファイルシステムの変更と fsync のそれぞれの直後に SIGKILL で止め（隔離・ツリー・MCP の編集・行の削除・chmod の計画で 77 か所）、apply を再実行し（拒否される）、recover を実行して、対象が完全に修復済みか完全に元どおりのどちらかであること、その後の dry-run と apply で計画が完了すること、監査ログのハッシュチェーンが正しいことを確かめる。

- 1 件でも `failed` が出たら残りは実行しない（契約 §7）
- ロールバック自体が失敗した場合は終了コード 5、ログに対象と状態を全件記録して人手対応を促す
- `chmod` の `params`: `{"mode": "0600"}`（8 進文字列のみ受理。setuid/setgid/sticky ビットと world-writable の付与は拒否）。ディレクトリへの再帰適用はしない（親・子への遡及禁止）
- chmod は権限を絞る操作に限る: 新しい mode が現在の mode（G-7 で `lstat` した値）に無いビットを 1 つでも含めば拒否（`mode & ~before != 0`）。ロールバックは記録した `before` に戻すため、このゲートを通らない
- `action.evidence_hash`（ZET A-8）があれば G-7 で現在のファイルと比べる。規則は ZES と同じ: 100MB 以下の通常ファイルは内容の SHA-256、100MB 超は `パス|サイズ|mtime（秒）` の SHA-256。ディレクトリは ZES が finding の detail をハッシュするため比べない。読めない通常ファイルは確かめられないため拒否

---

## 4. 承認トークン

契約の `approval_token` は形式が未定義のため、**plan 本体の正規化 JSON（キー順ソート、区切り `,`/`:`、UTF-8）の SHA-256 = `plan_hash`** と一致することを要求する（ZET A-6）。承認者は確定 plan のハッシュに対して承認するので、承認後に plan を差し替えると G-3 で止まる。

**限界**: `plan_hash` が示すのは完全性（ハッシュを計算した時点から変わっていないこと）だけで、真正性（ZET が作り、承認者がその内容を見たこと）ではない。finalize の後に plan を書き換えて `plan_hash` と `approval_token` を計算し直すと、暗号的には検出できない。そのため GER は次の多層防御を行う:

- plan だけで評価できる ZET の不変条件を G-1 で再検査する（`items[].skillpact`（ZET A-9）があれば I-5 / I-6 / I-7 も）
- chmod は権限を絞るだけ（G-7）。書き換えた plan でも権限を緩められない
- 承認の有効期限（`GER_APPROVAL_MAX_AGE`、既定 7 日）と、remediate の `due_at` の最大値を過ぎた計画の拒否
- findings が無いと確かめられない「対象が finding の path であること」（ZET の I-4）は確かめられない。書き換えた plan は、実行者が所有する別のファイルの権限を絞ることはできる

将来の強化案（初版対象外）: 承認者ごとの署名（SSH 署名 `ssh-keygen -Y verify` 等）。ただし外部コマンド起動を伴うため、採用時は Zero-Exec 方針との整理が必要。

---

## 5. 監査ログ（追記専用）

- 既定パス: `$GER_LOG_DIR/ger-audit.jsonl`（既定 `~/.local/state/ger/`、ZES・ZET とは別ファイル・別リテンション）
- 1 行 1 レコード: `skill`（"ger"）/ `version` / `command` / `plan_id` / `plan_hash` / `input_hash` / `output_hash` / `started_at` / `finished_at` / `operator` / `result` / `gate_failed`（拒否時）
- 出力 `remediation-log.json`（契約 §6）は実行ごとに別ファイルで書き出し、そのハッシュを監査ログに残す
- ハッシュチェーン（`prev_hash`）を持たせる（ZET B-2 と同方式）。G-8 は監査ログのチェーンが壊れていたら dry-run 記録を信用せず拒否する
- 追記の前に、排他ロックの下で末尾の連結（最終行が改行で終わる JSON object で、`prev_hash` が直前の行と一致）を確かめ、壊れていれば追記しない（何も実行せず終了コード 64）。全体の検証は `ger verify-log`
- `GER_LOG_DIR` は起動時に一度だけ実パスへ解決し、ログの読み書きはすべて解決後のパスで行う。G-7 では解決前（字句上）と解決後の両方の上位ディレクトリを保護する。-o の親ディレクトリも同様に両方の上位を計画の対象から外す（途中のシンボリックリンクを置いたディレクトリを chmod 0000 されると、そのパス経由で書けなくなるため）

---

## 6. 構成（実装に合わせて更新）

```
gated-exec-remediation/
├── SKILL.md                          # エージェント向け手順（承認を代行しない、apply 前に必ず dry-run）
├── bin/ger                           # 起動スクリプト（bash 組み込みのみでパス解決し python3 -I -S で起動）
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
├── docs/design/{design.md, design.ja.md, flow.svg, flow.ja.svg}
├── README.md / README.ja.md
└── CHANGELOG.md
```

実装時の変更点:
- 実体の同一性判定を `(st_dev, st_ino)` から `(st_dev, st_ino, st_ctime_ns)` に強化した。削除・再作成で i-node 番号が再利用され、差し替えを検出できないことをテストで確認したため
- `input_hash` は入力から `mode` を除いた正規化 JSON の SHA-256（dry-run と apply で同一入力かを判定するため）
- remediation-log に `mode` と `plan_hash` を追加（契約 §6 への追加。どの計画のどの実行かを一意にするため）

操作は共通インターフェース（`validate_params` / `prepare(ctx, items) -> Step` / `preview(ctx, items)`、Step は `apply(rt)` / `rollback(rt)` と JSON にできる undo）で追加する（`ger/actions/base.py`）。`write_config` / `rotate_secret` はレジストリに登録しない。

Phase 1 で追加したファイル: `ger/fsutil.py`（fd でたどる対象の解決・ツリーハッシュ）、`ger/hazards.py`（表 H / K・保護対象）、
`ger/jsonedit.py`（JSON / JSONC の字句解析と差し替え）、`ger/tomledit.py`（TOML のテーブルヘッダの範囲）、`ger/store.py`（隔離ストアとジャーナル）、
`ger/restore.py`、`ger/actions/{base, quarantine, edit_common, edit_json, edit_toml, remove_line, disable_mcp_server, checklist}.py`、
`schemas/{actions, restore-request}.schema.json`、`tests/{test_remediation.py, zero_exec.py, e2e_zes.py, run-e2e.sh}`。

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
| 監査ログの末尾が壊れている（途中で切れた行など） | 追記せず何も実行しない（64）。`ger verify-log` で確認し、ログを退避して再実行 |
| 同じ dry-run で 2 回目の apply | G-8 で拒否（dry-run 記録は 1 回で使用済み。最初の変更の前に追記する開始の記録で使用済みになる） |
| apply が強制終了された後にもう一度 apply | G-8 で拒否（dry-run 記録は使用済み、未完了のジャーナル）。`ger recover` の後に dry-run と apply（§3.1） |
| 古いジャーナルの上で別の apply が走った後の `ger recover`（以前の GER） | ジャーナルを `superseded` として閉じ、再生しない（§3.1） |
| 実時刻の期限切れの dry-run を `--now` で期限内に見せる | G-8 で拒否（`--now` 付きの apply は `--now` 付きの dry-run だけを数える） |

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


---

## 10. Phase 1 修復操作（修復能力拡張 設計 0.2 の実装）

### 10.1 流れ

1. ZES が検知する（findings 1.0。1.1 の項目は ZES 未実装）
2. `zet draft` が finding ごとに提案（`constraints.suggested_actions`: `auto` と `checklist`）を付ける。判断者が採用する
3. `ger preview` が、採用した action の params を現在のファイルから埋める（quarantine のハッシュ・種類、編集の ops・`before_sha256`・`file_sha256`・`expected_after_sha256`）。拒否されたもの（RECORD の無い dist-info、ドット区切りの TOML など）は理由を `--report` に出す。判断者は checklist に切り替える
4. `zet finalize` → 承認（`approval_token = plan_hash`）→ `ger dry-run` → `ger apply`
5. 残った手作業（checklist と followup）を作業者が行い、`ger confirm` で記録する。ZES で再スキャンする
6. 戻す必要があれば `ger restore`（承認者 2 名）

承認者は「変更後の正確なバイト列」（`expected_after_sha256`）と「隔離するものの正確なハッシュ」を承認することになる。apply は計算し直した結果がこれと違えば止まる。

### 10.2 定義 T（絞るだけ）の表（`ger/hazards.py`、版 `ger-hazards-3`）

| 操作 | H（取り除いてよい単位。ファイルの種類ごと） | K（足してよい定数） |
|---|---|---|
| edit_json / disable_mcp_server | `mcp.server`: MCP 設定（`.mcp.json` / `mcp.json` / `mcp_config.json` / `.claude.json` / `claude_desktop_config.json`）の `/mcpServers/<name>`・`/servers/<name>`・`/projects/<p>/mcpServers/<name>`（値は object）。preview の自動選択は ZES §17 の `MCP_DANGER_RE` を写した `MCP_DANGER`（大文字小文字を区別しない。command の改行で分けた行ごと）に一致するサーバーだけ（ger-hazards-2。-1 はシェル -c・node -e・python -c・powershell -enc だけで、ZES round 3 の `cmd /c`・`deno eval`・`node --eval`・`bash --norc -c`・`-xc`・`perl -e`・`ruby -e`・`pwsh -Command` を自動で取り除けなかった。ger-hazards-3: C ロケールの grep と同じく `\s` と大文字小文字の同一視を ASCII だけにし、pwsh の分岐を線形時間にし、command / args を ZES と同じ形で組み立てる（文字列以外は jq の `tostring`、NUL は落とす。TOML は文字列だけ、制御文字は空白）） | — |
| edit_json | `npm.lifecycle`: `package.json` の `/scripts/(preinstall\|install\|postinstall\|prepare\|…)` | — |
| edit_json | `claude.hook`: `.claude/settings(.local).json` の `/hooks/<Event>/<i>`（と `/hooks/<Event>/<i>/hooks/<j>`） | — |
| edit_json | `vscode.task_run_on`: `.vscode/tasks.json` の `/tasks/<i>/runOptions/runOn`（値が `folderOpen`） | `"default"` |
| edit_toml / disable_mcp_server | `mcp.server.toml`: `.codex/config.toml` の `[mcp_servers.<name>]` | — |
| remove_line | `sh.ld_preload` / `sh.curl_pipe_sh` / `sh.base64_pipe_sh` / `sh.histfile_null`（シェルの rc）、`git.exec_key`（`fsmonitor` / `sshCommand` / `hooksPath`）、`php.auto_prepend`、`ldso.entry`、`cron.fetch_exec`（`/etc/cron.d/*`）。行の全体が一致すること | — |
| quarantine | finding の対象そのもの、または §10.3 の関係で導いた対象 | — |

表に無いもの（`permissions.deny`、`.npmrc` の `ignore-scripts=true`、`disable_functions` など）は取り除けない。T-3 は JSON は `json.loads`、JSONC はコメントと末尾カンマを別の経路で除いてから `json.loads`、TOML は `tomllib`、テキストは取り除いた行以外のバイトの一致で確かめる。dry-run と apply の両方で確かめる。

### 10.3 関係（relation）と G-9

| relation | 字句上の条件（ZET の I-4 と同じ） | GER がファイルシステムで確かめること |
|---|---|---|
| `self` | target == finding_path。dist-info / egg-info・`node_modules/**/package.json`・`Extensions/**/manifest.json`・`skill.contract.json` だけの隔離は拒否（Q-6） | 種類とハッシュ |
| `npm_pkg_dir` | finding_path == target + `/package.json`、target の親が `node_modules`（scoped は親の親） | `package.json` の name / version が `params.subject` と一致し、name がディレクトリ名と一致 |
| `npm_installed` | finding がロックファイルで、target がその隣の `node_modules/<name>`（入れ子を含む） | 同上 |
| `pypi_record` | target == finding_path（`*.dist-info`） | RECORD がある。site-packages の下の各メンバーが通常ファイルで RECORD の sha256 と一致（.pyc 以外でハッシュの無いメンバーは拒否）。site-packages の外のメンバーは移さず preview に一覧で示す |
| `ext_dir` | finding_path が `…/Extensions/<id>[/<ver>]/manifest.json`、target が `…/Extensions/<id>` | manifest.json が JSON としてパースできる |
| `skill_dir` | target == finding_path、または finding_path が target の `skill.contract.json` | `skill.contract.json` か `SKILL.md` がある |
| `none` | target が null（checklist だけ） | — |

group（同じ対象への複数の finding）では、1 件目だけでなく全件の relation を字句上・ファイルシステム上で確かめる（finding_path が違う item が混ざるため）。

### 10.4 隔離ストア（Q-2）

- 場所: `GER_QUARANTINE_DIR`、なければ `$XDG_STATE_HOME/ger/quarantine`、なければ `~/.local/state/ger/quarantine`。起動時に実パスへ解決。所有者は実行ユーザー、mode 0700、マーカー `.ger-quarantine-store`
- 構成: `<store>/<run_id>/<seq>/{payload, manifest.json[, restored.json, rolled_back.json, replaced]}` と `<store>/journal/<run_id>.jsonl`。中の名前は連番だけ（`.pth` などの名前で読み込まれない）
- quarantine: 同一性を照合してから `os.rename(name, "payload", src_dir_fd, dst_dir_fd)`。移した後、ファイルは 0400、ディレクトリは 0500（元の mode はマニフェストに残す）。マニフェスト（0600）は元のパス・`(dev, ino)`・mode・uid / gid・mtime・ハッシュ（ロック後のハッシュも）・plan_id / plan_hash・finding_ids・relation を持ち、その SHA-256 を監査ログに載せる
- 編集: 同じディレクトリに一時ファイルを `O_CREAT|O_EXCL|O_NOFOLLOW` で作り、元の mode（root なら uid / gid も）で書いて fsync → 元のファイルをストアに `os.link`（バックアップ。元の i-node をそのまま残す）→ 同一性を照合して rename。適用後に SHA-256 が `expected_after_sha256` と一致することを確かめる（V）
- 別のデバイスにある対象は拒否（rename / link が原子的でないため）。**逸脱**: デバイスごとのストア（`GER_QUARANTINE_DIRS`）は Phase 1 では実装していない。`GER_QUARANTINE_DIR` で同じデバイスのストアを 1 つ指定する
- GER はストアから何も削除しない。削除（purge）は作業者が `ger quarantine-list` で確かめてから手で行う。消した後は restore もロールバックもできない
- ZES の走査から外すには ZES 側の変更が要る（`.ger-quarantine-store` のあるディレクトリを走査しない。未実装）。それまでは、ストアを ZES の `--root` の外に置く（G-9 で `scope.roots` の下を拒否する）

### 10.5 restore（Q-4）

`restore-request.json`（`schemas/restore-request.schema.json`）は `restore_id`・`entries[{quarantine_id, manifest_sha256}]`・`approval{approved_by（2 名以上）, approved_at, approval_token}` を持つ。`approval_token` は approval と mode を除いた正規化 JSON の SHA-256。dry-run の成功記録が必要で、1 回の apply で使い切る（監査ログの command は `restore-dry-run` / `restore-apply`）。前提: マニフェストの SHA-256 が一致、ストアの中身（ロック後のハッシュ・実体 ID）がマニフェストと一致、隔離したものは元のパスが空いている、編集は現在のファイルが GER の書いた内容（`after_sha256`）のまま。戻す前の編集後のファイルは `replaced` としてストアに残す。途中で失敗したら戻したものを再び隔離する。

### 10.6 保護対象と承認者

- 対象にもその上位にもしない: `/` とトップレベルのシステムディレクトリ、`$HOME` そのもの、GER のインストール先（中も不可）、Python の標準ライブラリ（site-packages を除く。中も不可）、監査ログ・隔離ストアとその上位
- `/etc` の下は `/etc/ld.so.preload`・`/etc/hosts`・`/etc/cron.d/*` だけ。root が必要な対象は承認者 2 名で、計画を root 用とそれ以外に分ける
- 承認者の人数: checklist・self の quarantine・編集・chmod は 1 名、restore・root が必要な対象・不可逆・破壊的な操作（Phase 1 には無い）・diff_anomaly・危険な効果は 2 名

### 10.7 checklist と followup

`checklist` の params は `{template, steps[{id, text, blocking}], verify?}`。自動修復の action は `action.followup`（同じ形の配列）で必須の後続作業（CL-IR・CL-SECRET・CL-LAUNCHD・CL-EXT など）を持つ。どれを必須にするかは ZET が finding から決め、欠けていれば ZET の I-13 で確定させない（GER は findings を読まないため必須かどうかは判断せず、そのまま運んで表示・記録する）。`ger confirm` は apply の成功記録の後にだけ記録でき、作業者が承認者でないこと（G-4）、同じ手順の二重の記録でないことを確かめる。`verify.kind` が `path_absent` / `file_hash_changed` のときは GER が確かめてから記録し（`verified:…`）、外部の作業（ローテーションなど）は `self_attested` とだけ記録する。

### 10.8 ツリーハッシュ ger-tree-v1（ZES と共通の定義）

エントリ（ルート自身を `.` として含む）を相対パスのバイト列の昇順に並べ、各行
`type \0 relpath \0 mode(4 桁の 8 進、0o7777 でマスク) \0 (f: size \0 sha256hex / l: readlink の値 / d: 空) \n`
（type は `f` / `l` / `d`）を連結した SHA-256 を `sha256:<hex>` で表す。mtime / ctime / uid は含めない。エントリが 50,000 を超える、合計が 2 GiB を超える、FIFO・ソケット・デバイスを含む、別の `st_dev` を含む、`st_nlink > 1` の通常ファイルを含むツリーは拒否する。テストベクタは `tests/test_remediation.py` の `TestTreeHashVector`（Linux で `sha256:a0330bed2509e447a89682699b271f59ea236c52316ec21f0e546620de17958e`）。

### 10.9 設計 0.2 からの逸脱

| 項目 | 設計 | 実装 | 理由 |
|---|---|---|---|
| 検査範囲 | `ger-input.scope.roots` | `plan.scope`（`roots` と `home`） | 承認トークン（plan_hash）で束縛するため。ZET が triage-input の `policy.scope`（1.1 では findings の `scan_roots`）から作る |
| evidence が detail の finding | quarantine も編集もしない | params に固定した preview のハッシュ（承認の対象）で照合して実行する | findings 1.0 ではディレクトリ・リンクの evidence が常に detail のため（設計 §3.0 の「1.0 のディレクトリは preview のハッシュを使う」に合わせた） |
| group の evidence.hash の一致 | 必須 | 同じ `finding_path` の item どうしで、内容に基づく evidence（file / tree / symlink）だけ一致を求める。`finding_path` が違う item の間では比べない。どの item の evidence も、それぞれの `finding_path` から導き直して照合する（G-7、item ごと・全件）。group の各 item の relation も 1 件ずつ確かめる（G-9） | detail の evidence は finding ごとの文言のハッシュで一致しないため。findings 1.1 では 1 つの対象に別のファイルの finding がまとまる（skill_dir: ディレクトリの tree と `skill.contract.json` の file、npm: `node_modules/<name>/package.json` とロックファイル）。別のファイルのハッシュは一致しようがなく、一致を求めても何も保証しない。保証（検知時から変わっていない）は item ごとの照合で保つ |
| edit_toml | Phase 2 | Phase 1 の範囲（標準のテーブルヘッダ）で実装 | オーナーの指示 |
| ジャーナル | 全操作 | quarantine と編集（chmod だけの計画はジャーナルを作らない。従来どおりプロセス内でロールバック） | chmod だけの利用者に隔離ストアを作らせないため |
| デバイスごとのストア | `GER_QUARANTINE_DIRS` | 未実装（別のデバイスは拒否） | Phase 1 は拒否で足りる |
| params の検査 | G-7 | G-1（`actions.schema.json` と操作の意味の検査） | 設計 §4.3 の G-1 の行に合わせた |
| INFO の期限 | — | 隔離の group に入れた INFO の `due_at` は LOW の期限 | ポリシーに INFO の期限が無いことが多いため |

### 10.10 ZES の finding と Phase 1 の扱い（E2E の結果）

ZES の `tests/fixtures`（`origin/main` 98ee340）を写して ZES → ZET → GER → ZES を通しで実行した結果は README の「E2E」の表を参照（`tests/run-e2e.sh`）。

### 10.11 ZES 側の変更（findings 1.1。未適用）

ZES は今回変更していない。ZET と GER は findings 1.0 で動き、1.1 の項目は任意で受け付ける。ZES に適用する変更:

1. `schemas/findings.schema.json`: ZET の `schemas/vendor/findings-1.1-draft.schema.json`（ZET 2ab7a53）を正として写す（`$id`・title・description を ZES のものに戻す）。差分は `schema_version` を `"1.1"`、トップレベルに `scan_roots`（`--root` の実パスの配列）、finding に任意の `kind`・`subject`・`locators`・`related`・`evidence`
2. `tests/run-tests.sh`: `REQUIRED_TOP` に `scan_roots` を足す。finding のキーの照合を `(keys - ["skillpact","kind","subject","locators","related","evidence"])` にする
3. `emit()`（`zes-scan.sh` 230-260）: 任意の 6 番目の引数（JSON の断片）で kind / subject / locators / related を足す。id の作り方（`module|campaign|path|detail`）と `evidence_hash` は変えない（`tests/expected` との照合を保つ）。`evidence` を毎回出す: 通常ファイルは `file`（100MB 超は `large_file`）で今の `evidence_hash` と同じ値、シンボリックリンクは `symlink` で readlink の値（バイト列）の SHA-256、ディレクトリは `tree` で ger-tree-v1（§10.8。テストベクタ `sha256:a0330bed…958e` を ZES のテストにも入れる）、それ以外は `detail`
4. モジュールごと（Phase 1 で使うもの）:
   - §15（768-801）: `kind` = `pkg.compromised`（侵害パッケージ）/ `pkg.vulnerable`（脆弱な版）/ `pkg.lockfile_compromised`（ロックファイルにある侵害版）、`subject` = `{ecosystem, package, version, safe_version, fixed_versions}`。ロックファイルの finding は、隣の `node_modules/<name>/package.json` があれば `related: [{relation: "npm_installed", path: "<dir>/node_modules/<name>"}]`
   - §17（2043-2068）: `kind` = `mcp.dangerous_command` / `mcp.unpinned`、`locators` = 該当するサーバーごとに `{format: json|jsonc|toml, pointer: "/mcpServers/<name>"}`（TOML は `"/mcp_servers/<name>"`。今は同じファイルの同じ種類の問題が 1 件にまとまるため、locators で複数を並べる）。SymJack は `evidence.kind = symlink`
   - §7（1601-1612）: hooks は `locators: [{format: json, pointer: "/hooks/<Event>/<i>"}]`、`runOn` は `"/tasks/<i>/runOptions/runOn"`
   - §10 / §31 / §26 / §4 の php.ini: `locators: [{format: text, line, line_sha256}]`（行の SHA-256 は改行・CR・1 行目の BOM を除いたバイト列。GER の remove_line と同じ）
   - §24: `related: [{relation: "ext_dir", path: "…/Extensions/<id>"}]`（**設計 0.2 からの変更**: evidence を ext_dir のツリーハッシュにすると、GER は finding_path（manifest.json）の evidence として照合するため一致しない。evidence は manifest のファイルのまま、ツリーは preview の `tree_sha256` で固定する）
   - §49: divergence（path がスキルのディレクトリ）は `evidence.kind = tree`、`skill.contract.json` の finding は `related: [{relation: "skill_dir", path: <dir>}]`
   - §21 / §22 / §28 / §47 / §3 §5 §6 §16 §37 §41: `kind`（`gha.pwn_request`・`gha.unpinned`・`secret.token`・`runtime.cve`）。ZET の I-13 はこの kind で操作を絞る
5. 隔離ストアを走査しない: すべての `find` で `.ger-quarantine-store` のあるディレクトリを prune する
6. `docs/skill-contracts.md:156` の「親ディレクトリへの遡及禁止」を「`relation` で導ける対象に限り、それ以外へは遡及しない」に改める（`:184` のファイル内容を出さない原則は変えない）
7. ZES が 1.1 を出したら: ZET の `schemas/vendor/findings-1.1-draft.schema.json` を ZES の `schemas/findings.schema.json` の写しに置き換え、VENDOR.json の `status: draft` を外して `source_commit` を入れる（GER は findings を読まないため変更不要）
