# gated-exec remediation brand

アプリアイコンとロゴは [fresnel](https://github.com/kajisho5/fresnel) のブランド形式に準拠しています。Liquid Glass の `.icon` バンドル（Apple Icon Composer 形式）を fresnel CLI（[fresnel-icon](https://www.npmjs.com/package/fresnel-icon)、MIT）で `src/spec.json` と 2 枚のレイヤー SVG から生成しています。

ZES / ZET / GER の 3 製品は同じ構成で、形とアクセント色だけが異なります。背面 = アーチ型のゲート、前面 = ✓（承認された修復）。

## 再生成

```bash
cd brand
python3 src/layers.py ger                  # レイヤー SVG（要 shapely。形を変えたときだけ）
python3 src/wordmark.py "gated-exec remediation"   # ワードマーク（要 fonttools と Inter Display SemiBold。文字を変えたときだけ）
npm ci && npm run build                     # .icon と以下の資産をすべて書き出す
```

`npm ci` は `.npmrc` の `ignore-scripts=true` でインストールスクリプトを実行しません。fresnel-icon 0.2.2 はレンダラを公開 API として export していないため、`build.mjs` は同梱の `dist/cli.js` から CLI 起動部を外したモジュールを `node_modules` 内に作って読み込みます。fresnel-icon のバージョンを上げるときは出力を目視で確認してください。

ソーシャル画像の日本語はシステムフォントで描画するため、環境によって画素が変わります（アイコン・ロゴ・favicon は同じ入力から同じ出力になることを確認済み）。

## 資産

| ファイル | 用途 |
|---|---|
| `AppIcon.icon/` | アプリアイコン本体（Icon Composer / fresnel で開ける） |
| `src/spec.json`, `src/gate.svg`, `src/check.svg` | アイコンのソース（背景グラデ＋ガラス 2 グループ） |
| `logo/ger-logo-dark.svg` / `-logo-light.svg` | ロックアップ（暗い背景用 / 明るい背景用） |
| `logo/ger-wordmark-white.svg` / `-wordmark-black.svg` | ワードマークのみ |
| `logo/ger-mark.svg` | アイコン（スクワークル、ベクター） |
| `png/AppIcon-1024.png` / `-dark-1024.png` / `-fullbleed-1024.png` | アイコン PNG（通常 / ダーク / マスクなし） |
| `web/favicon.svg` / `favicon.ico`（16/32/48）/ `favicon-64.png` | ファビコン |
| `web/apple-touch-icon.png`（180、不透明・マスクなし） | iOS ホーム画面 |
| `web/icon-192.png` / `icon-512.png` / `icon-maskable-512.png` | PWA |
| `social/og-image.png`（1200×630） | Open Graph |
| `social/github-social-preview.png`（1280×640） | GitHub の Social preview（リポジトリの Settings → General → Social preview からアップロード） |

## ガイドライン（fresnel と同じ）

- 構成は背景＋ガラス 2 グループ。ハイライトや影はレイヤーに焼き込まない（.icon 側の設定で付ける）
- プラットフォームがマスクを掛ける場所（apple-touch-icon・maskable）にはマスクなし版を使う
- 24 px 未満はワードマークを付けずアイコンだけを使う。最小 16 px
- ワードマークは暗い背景で `#F5F5F7`、明るい背景で `#1D1D1F`。名前は小文字で書く
- ワードマークの書体は Inter Display SemiBold（SIL OFL 1.1）をアウトライン化したもの。Apple の商標は使わない
