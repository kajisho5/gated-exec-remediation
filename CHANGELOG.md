# Changelog

## Unreleased

### Round 5 fixes

- **A killed apply, a second apply and `ger recover` could undo a committed remediation.** A killed apply wrote no audit record, so its dry-run record stayed unused and a second apply with the same input ran (items the first one had done were `already_compliant`). `ger recover` then replayed the first run's journal, moved the quarantined files back and restored the removed MCP servers, and still reported OK. Now apply appends a start record (`command: "apply"`, `result: "started"`, `run_id`) under the log lock before its first change, which uses up the dry-run record (G-8); verify, dry-run and apply are rejected (G-8) while the quarantine store holds an unfinished journal, naming its run and plan; and `ger recover` closes a journal as `superseded` without replaying it when the audit log shows a later apply or restore, and undoes nothing unless every step can be undone exactly (the quarantined object still in the store and its original place free, the edited file still holding GER's bytes, the chmod target still GER's mode). Kill points between a change and its journal line are read from the file system (a chmod intent is now journaled before the change; a stale backup hard link is removed so the target does not keep `st_nlink` 2). When apply, restore or recover stops with a usage error before any change and then cannot record in the audit log, the exit code is 64 rather than 5 (nothing changed). Design §3.1 describes the behaviour; `TestKillPoints` kills apply right after each of its 77 file-system changes and fsyncs, then checks retry, recover, a new dry-run + apply and the audit chain.
- **The other dangerous-command patterns still took quadratic time** (round 4 fixed only the pwsh branch). Every `MCP_DANGER` branch with option tokens (`sh … -c`, `node … -e`, `python … -c`, `perl` / `ruby`, `php`, `osascript` / `lua`) backtracked from every start position: an `.mcp.json` of 128 KB with `"sh"` and `"-/sh"` repeated in `args` kept `ger preview` busy for 50 s, and files up to 1 MB are read. The hook pattern `DANGEROUS_CMD` (`powershell … -enc`) had the same problem. Both are now matched by linear scanners (`hazards.mcp_danger`, `hazards.dangerous_cmd`): a head, then the maximal run of `-` tokens after it matched possessively, with flags that cannot backtrack. The match result is unchanged, so `HAZARD_VERSION` stays `ger-hazards-3`: `tests/test_hazards.py` compares the scanners with the previous regular expressions on random command lines built from the round 5 token pool (60 000 for MCP, 40 000 for hooks; 500 000 checked once while fixing, no difference) and checks that adversarial 1 MB inputs take well under 1 s each (about 0.25 s at most here). The same 128 KB file now previews in 0.6 s, a 1 MB one in 4 s (mostly JSON parsing).

- **`ger preview` crashed (exit 70) on a `.codex/config.toml` whose `mcp_servers` is an array (`[[mcp_servers]]`, `mcp_servers = [...]`) or a plain value**, so no item of the plan was previewed and no `-o` / `--report` file was written. That item is now refused with the reason (nothing GER can remove automatically), the other items are previewed, and the exit code is 3 as for any refused item.
- **A `.codex/config.toml` with a UTF-8 byte order mark could not be remediated** (`cannot tokenize as TOML`: `tomledit.loads` skipped the BOM, the table scanner did not). The BOM is now kept byte for byte and the rest is edited; T-3 re-parses the result as before. Codex reads the file with the `toml` crate (codex-rs pins `toml = "0.9.5"`), whose lexer skips a leading BOM (`crates/toml_parser/src/lexer/mod.rs` at tag `toml-v0.9.5`), so a BOM file is a valid Codex configuration. JSON / JSONC files with a BOM were already handled; a test now covers both.
- **`ger restore` repeated the G-9 prefix** in its rejection message (`G-9: <id>: G-9: …`; the audit log's `gate_failed` was already `G-9`). As in gates.py, the gate comes from the fixed prefix and the message is recorded without it.


### 日本語（round 5 の修正）

- **強制終了された apply・2 回目の apply・`ger recover` の順で、確定した修復が元に戻ることがあった。** 強制終了された apply は監査ログに記録を書かないため dry-run 記録が未使用のまま残り、同じ入力の 2 回目の apply が実行された（1 回目が済ませた item は `already_compliant`）。その後の `ger recover` が 1 回目のジャーナルを再生して、隔離したファイルを戻し、取り除いた MCP サーバーを復元し、それでも OK と報告していた。apply は最初の変更の前に、ログのロックの下で開始の記録（`command: "apply"`、`result: "started"`、`run_id`）を追記し、これで dry-run 記録が使用済みになる（G-8）。隔離ストアに未完了のジャーナルがある間は verify・dry-run・apply を G-8 で拒否し、その実行と計画を示す。`ger recover` は、監査ログに後の apply か restore があればジャーナルを再生せず `superseded` として閉じ、すべてのステップを正確に元に戻せるとき（隔離した物がストアにあり元の場所が空いている、編集したファイルが GER の書いたバイト列のまま、chmod の対象が GER の mode のまま）だけ元に戻す。変更とそのジャーナルの行の間で落ちた場合はファイルシステムから状態を読む（chmod の意図を変更の前にジャーナルに書くようにした。古いバックアップのハードリンクは、対象が `st_nlink` 2 のまま残らないよう外す）。apply・restore・recover が変更の前に引数エラーで止まり、その後監査ログへ記録できなかった場合の終了コードは 5 ではなく 64（何も変えていない）。設計 §3.1 に動作を書いた。`TestKillPoints` は apply をファイルシステムの変更と fsync の 77 か所それぞれの直後で止め、再実行・recover・新しい dry-run と apply・監査ログのチェーンを確かめる
- **ほかの危険なコマンドのパターンも二次時間かかっていた**（round 4 で直したのは pwsh の分岐だけ）。`MCP_DANGER` のオプションを挟む分岐（`sh … -c`、`node … -e`、`python … -c`、`perl` / `ruby`、`php`、`osascript` / `lua`）はすべての開始位置からバックトラックし、`args` に `"sh"` と `"-/sh"` を並べた 128 KB の `.mcp.json` で `ger preview` が 50 秒止まった（読むのは 1 MB まで）。フックのパターン `DANGEROUS_CMD`（`powershell … -enc`）も同じ。どちらも線形の走査（`hazards.mcp_danger`、`hazards.dangerous_cmd`）にした。先頭のコマンド、その後ろの `-` で始まるトークンの最長の並び（所有的に一致させる）、バックトラックしない形のフラグの順に調べる。一致の結果は変わらないため `HAZARD_VERSION` は `ger-hazards-3` のまま。`tests/test_hazards.py` が round 5 のトークンの集まりから作った乱数のコマンド行（MCP は 6 万件、フックは 4 万件）で以前の正規表現と比べ（修正中に 50 万件で 1 回確かめ、差は無し）、1 MB の悪意のある入力がそれぞれ 1 秒を大きく下回ることを確かめる（ここでは最大で約 0.25 秒）。同じ 128 KB のファイルの preview は 0.6 秒、1 MB では 4 秒（ほとんどが JSON の解析）
- **`mcp_servers` が配列（`[[mcp_servers]]`、`mcp_servers = [...]`）か単なる値の `.codex/config.toml` で `ger preview` が落ちていた**（終了コード 70）。計画のどの item も preview されず、`-o` も `--report` も書かれなかった。その item は理由を付けて拒否し（GER が自動で取り除けるものが無い）、ほかの item は preview し、終了コードは拒否した item があるときと同じ 3
- **UTF-8 の BOM 付きの `.codex/config.toml` を修復できなかった**（`cannot tokenize as TOML`。`tomledit.loads` は BOM を飛ばすが、テーブルの走査は飛ばしていなかった）。BOM はバイト単位でそのまま残し、残りを編集する。T-3 の再パースはこれまでどおり。Codex はこのファイルを `toml` crate で読み（codex-rs は `toml = "0.9.5"` に固定）、その字句解析は先頭の BOM を飛ばす（タグ `toml-v0.9.5` の `crates/toml_parser/src/lexer/mod.rs`）ため、BOM 付きのファイルは Codex の設定として有効。BOM 付きの JSON / JSONC はもともと扱えていた。両方をテストで確かめる
- **`ger restore` の拒否メッセージで G-9 の接頭辞が重複していた**（`G-9: <id>: G-9: …`。監査ログの `gate_failed` はもともと `G-9`）。gates.py と同じく、ゲートは固定の接頭辞で決め、メッセージは接頭辞を除いて記録する

### English-first

GER is now English-first, following ZES 0.5.0. Every message a person reads is English: gate rejection reasons, action errors, `ger preview` summaries and reports, CLI output and help, remediation-log `reason` texts and the test harness output. Behaviour does not change apart from the language of these strings.

- **Unchanged**: gate and rule codes (G-1 to G-10, I-*, T-*, Q-*, CL-*), exit codes, JSON keys, enum values, schemas (only GER-owned schema `description` texts are English), `plan_hash` / `input_hash` / approval tokens, the audit log, journal and quarantine manifest formats, and `HAZARD_VERSION` (`ger-hazards-2`).
- T-* violations are still reported as G-10 (see the next entry for how this is decided now).
- Audit log records written by earlier versions may hold a Japanese `error` text (an `-o` clash). Nothing reads that text back, and `ger verify-log` checks the hash chain over the raw bytes, so old logs still verify and old dry-run records still count.
- Plans finalized by the current ZET are accepted as before. GER does not compare checklist step texts, followup templates or notes written by ZET; they only enter `plan_hash`, which GER recomputes over the plan as given. The vendored ZET files (`schemas/vendor/remediation-plan.schema.json`, `ger/jsonschema_lite.py`) are re-vendored from ZET's English-first versions (only comments, docstrings and schema descriptions changed; `schemas/vendor/VENDOR.json` pins the new commits and hashes). The ZET plan fixtures (`tests/fixtures/zet-final-plan*.json`) stay as ZET produced them, Japanese step texts included, and still validate.
- Docs: README (already bilingual), SECURITY, brand README and `docs/design/design.md` are English, with Japanese as `*.ja.md` (`docs/design/flow.ja.svg` for the diagram). SKILL.md is English and tells agents to answer in the user's language. Code comments are English.
- This changelog is bilingual from this entry; earlier entries stay in Japanese.

### 日本語

ZES 0.5.0 に合わせて GER を英語優先にしました。人が読む文（ゲートの拒否理由、操作のエラー、`ger preview` の要約とレポート、CLI の出力とヘルプ、remediation-log の `reason`、テストの出力）はすべて英語です。動作は、これらの文の言語以外は変わりません。

- **変わらないもの**: ゲート・規則のコード（G-1〜G-10、I-*、T-*、Q-*、CL-*）、終了コード、JSON のキー、enum の値、スキーマ（英語にしたのは GER 所有のスキーマの `description` だけ）、`plan_hash` / `input_hash` / 承認トークン、監査ログ・ジャーナル・隔離マニフェストの形式、`HAZARD_VERSION`（`ger-hazards-2`）
- T-* の違反は引き続き G-10 として報告します（いまの判定方法は次の項目を参照）
- 以前の版が書いた監査ログの記録には日本語の `error`（`-o` の衝突）が入っていることがあります。この文を読み返す処理は無く、`ger verify-log` は生のバイト列でハッシュチェーンを確かめるため、古いログもそのまま検証に通り、古い dry-run 記録もそのまま数えます
- 現在の ZET が確定した計画はこれまでどおり受け付けます。GER は ZET が書いたチェックリストの手順・followup のテンプレート・注記の文言を比べません（`plan_hash` に入るだけで、GER は渡された計画のまま計算し直します）。ZET から写したファイル（`schemas/vendor/remediation-plan.schema.json`、`ger/jsonschema_lite.py`）は、英語優先にした ZET の版から写し直しました（変わったのはコメント・docstring・スキーマの説明だけ。`schemas/vendor/VENDOR.json` に新しいコミットとハッシュを固定）。ZET の計画のフィクスチャ（`tests/fixtures/zet-final-plan*.json`）は ZET が出力したまま（日本語の手順を含む）で、引き続き検証に通ります
- 文書: README（もともと英語と日本語）、SECURITY、brand の README、`docs/design/design.md` は英語を正とし、日本語版を `*.ja.md` に置きました（図は `docs/design/flow.ja.svg`）。SKILL.md は英語です（利用者の言語で答えるよう指示）。コードのコメントは英語にしました
- この CHANGELOG はこの項目から英語と日本語の両方で書きます。以前の項目は日本語のままです

### Round 4 fixes (definition T table `ger-hazards-3`)

- **MCP_DANGER took quadratic time** on its pwsh / powershell branch (`(\s+\S+)*\s+` before the flag): an `.mcp.json` with `"pwsh"` repeated in `args` (64 KB) kept `ger preview` busy for 36 s, and files up to 1 MB are read. The branch is now two linear searches with the same result (the first `pwsh` / `powershell` followed by whitespace, then the flag anywhere after it).
- **GER and ZES disagreed on some MCP servers.** `\s` and case-insensitive matching were Unicode-aware in Python (NBSP, U+3000, `ſ`, Kelvin sign), so GER selected servers ZES did not flag; they are ASCII-only now, like grep in the C locale. Non-string `command` / `args` values were joined with Python `str()` and NUL characters were kept, so GER found nothing to remove where ZES reported HIGH; the command line is now built like ZES (jq `tostring`, NUL dropped). In `.codex/config.toml`, only string `command` / `args` count and control characters become spaces, as in ZES's TOML reader.
- **Gate codes came from message text.** Any rejection whose text contained `(T-` was reported as G-10, including G-7 rejections that quote a server name or RECORD path from the scanned content (`evil (T-1)`). T-* violations now carry the gate where they are raised. G-6 and G-9 rejections were recorded as `G-6:` / `G-9:` (with the colon) in the report and the audit log's `gate_failed`; they are `G-6` / `G-9` now. Plans were refused either way; only the reported code was wrong.

### 日本語（round 4 の修正）

- **MCP_DANGER が二次時間かかっていた**（pwsh / powershell の分岐。フラグの前の `(\s+\S+)*\s+`）。`args` に `"pwsh"` を並べた 64 KB の `.mcp.json` で `ger preview` が 36 秒止まった（読むのは 1 MB まで）。同じ結果になる 2 回の線形な検索に分けた（空白が続く最初の `pwsh` / `powershell` と、その後ろのフラグ）
- **一部の MCP サーバーで GER と ZES の判定が食い違っていた。** Python では `\s` と大文字小文字の同一視が Unicode に及び（NBSP、U+3000、`ſ`、ケルビン記号）、ZES が検出しないサーバーを GER が選んでいた。C ロケールの grep と同じく ASCII だけにした。文字列でない `command` / `args` を Python の `str()` でつないでいたことと NUL を残していたことで、ZES が HIGH とするのに GER が取り除く対象を見つけられなかった。ZES と同じ形（jq の `tostring`、NUL は落とす）で組み立てる。`.codex/config.toml` では ZES の TOML 読み取りと同じく文字列の `command` / `args` だけを使い、制御文字は空白にする
- **ゲートのコードをメッセージの文から決めていた。** 文に `(T-` を含む拒否はすべて G-10 になり、スキャン対象から来たサーバー名や RECORD のパス（`evil (T-1)`）を引用する G-7 の拒否も G-10 と報告していた。T-* の違反は発生箇所でゲートを持たせる。G-6 / G-9 の拒否はレポートと監査ログの `gate_failed` にコロン付きの `G-6:` / `G-9:` で記録されていたのを `G-6` / `G-9` にした。どちらの場合も計画は拒否されており、誤っていたのは報告するコードだけ

### MCP の危険判定を ZES §17 に揃える（定義 T の表 `ger-hazards-2`）

- **原因**: `disable_mcp_server` / `edit_json` / `edit_toml` の自動選択（`select: mcp.server`）が使う危険なコマンドの正規表現が ZES round 3 より前のもので、ZES が HIGH とする回避形（`cmd /c`、`deno eval`、`node --eval`、`bash --norc -c`、`bash -xc`、`perl -e`、`ruby -e`、`pwsh -Command`）に一致しなかった。`ger preview` が「取り除く対象が見つかりません」で拒否し、E2E の r3-mcp-evasion の 8 件がチェックリストに落ちていた
- **変更**: MCP サーバーの判定に、ZES の `MCP_DANGER_RE` を写した `MCP_DANGER`（大文字小文字を区別しない。command の改行で分けた行ごと）を使う。エージェントフック（`claude.hook`）の判定は変えない
- テスト: ZES と同じものを危険とし、`npx` / `node server.js` / `mybash -c` などは選ばないこと、`cmd.exe /c` のサーバーだけを取り除くこと
- E2E（ZES v0.4.0）: 53/53、自動 72 → 80 件。README の E2E の表を更新

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
