// brand/src から全ブランド資産を生成する（fresnel の scripts/brand.ts と同じ資産表）。
//
//   cd brand && npm ci && npm run build
//
// 1. fresnel CLI（fresnel-icon、package-lock でバージョン固定）で src/spec.json → AppIcon.icon
// 2. fresnel のレンダラで logo/*.svg・png/*.png・web/*・social/*.png を書き出す
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const out = (...p) => {
  const f = join(root, ...p);
  mkdirSync(dirname(f), { recursive: true });
  return f;
};
const brand = JSON.parse(readFileSync(join(root, 'src/brand.json'), 'utf8'));
const wm = JSON.parse(readFileSync(join(root, 'src/wordmark.json'), 'utf8'));

// ---------------------------------------------------------------- .icon（fresnel CLI）
const cliPath = createRequire(import.meta.url).resolve('fresnel-icon/dist/cli.js');
rmSync(join(root, 'AppIcon.icon'), { recursive: true, force: true });
execFileSync(process.execPath, [cliPath, 'build', 'spec.json', '-o', '../AppIcon.icon'], { cwd: join(root, 'src'), stdio: 'inherit' });
execFileSync(process.execPath, [cliPath, 'validate', '../AppIcon.icon'], { cwd: join(root, 'src'), stdio: 'inherit' });

// fresnel-icon 0.2.2 はレンダラを公開 API として export していないため、同梱の dist/cli.js から
// CLI 起動部（末尾の main() 呼び出し）を外した ES モジュールを node_modules 内に作って読み込む。
const cliSrc = readFileSync(cliPath, 'utf8').replace(/^#!.*\n/, '');
const mainAt = cliSrc.lastIndexOf('main().catch(');
if (mainAt < 0 || !/function renderSvg\(/.test(cliSrc)) throw new Error('fresnel-icon の dist/cli.js が想定と異なります（バージョンを確認）');
const libPath = join(dirname(cliPath), 'brand-lib.mjs');
writeFileSync(libPath, cliSrc.slice(0, mainAt) + 'export { loadIcon, renderSvg, renderPng, flattenPng, svgToPng };\n');
const { loadIcon, renderSvg, renderPng, flattenPng, svgToPng } = await import(pathToFileURL(libPath).href);
const doc = await loadIcon(join(root, 'AppIcon.icon'));

// ---------------------------------------------------------------- wordmark
const [wx0, wy0, wx1] = wm.bbox;
const asc = -wy0; // アセンダ上端〜ベースライン。降りは無視してベースラインで揃える
const wordmarkWidth = (h) => ((wx1 - wx0) * h) / asc;
/** 高さ h（アセンダ〜ベースライン）、左上 (x, y) */
const wordmark = (x, y, h, fill) => `<path fill="${fill}" transform="translate(${x} ${y + h}) scale(${h / asc}) translate(${-wx0} 0)" d="${wm.d}"/>`;
const iconInline = (x, y, size, prefix, appearance = 'default') => renderSvg(doc, { size, appearance, idPrefix: prefix }).replace('<svg ', `<svg x="${x}" y="${y}" `);

// ---------------------------------------------------------------- logos
function lockup(dark) {
  const h = 120;
  const textH = 50;
  const gap = 36;
  const W = Math.ceil(h + gap + wordmarkWidth(textH) + 8);
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${h}" viewBox="0 0 ${W} ${h}">` +
    `<title>${wm.text}</title>${iconInline(0, 0, h, 'lk_')}${wordmark(h + gap, (h - textH) / 2 - 4, textH, dark ? '#F5F5F7' : '#1D1D1F')}</svg>\n`
  );
}
const id = brand.id;
writeFileSync(out(`logo/${id}-logo-dark.svg`), lockup(true));
writeFileSync(out(`logo/${id}-logo-light.svg`), lockup(false));
for (const [name, fill] of [['white', '#F5F5F7'], ['black', '#1D1D1F']]) {
  const h = 96;
  const d = Math.ceil(h * 0.3); // 降り（g など）の分
  const w = Math.ceil(wordmarkWidth(h)) + 4;
  writeFileSync(out(`logo/${id}-wordmark-${name}.svg`), `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h + d}" viewBox="0 0 ${w} ${h + d}"><title>${wm.text}</title>${wordmark(2, 0, h, fill)}</svg>\n`);
}
writeFileSync(out(`logo/${id}-mark.svg`), renderSvg(doc, { size: 1024 }));

// ---------------------------------------------------------------- app icon PNGs
writeFileSync(out('png/AppIcon-1024.png'), await renderPng(doc, { size: 1024 }));
writeFileSync(out('png/AppIcon-dark-1024.png'), await renderPng(doc, { size: 1024, appearance: 'dark' }));
writeFileSync(out('png/AppIcon-fullbleed-1024.png'), flattenPng(await renderPng(doc, { size: 1024, mask: 'none', rim: false })));

// ---------------------------------------------------------------- favicons & PWA
writeFileSync(out('web/favicon.svg'), renderSvg(doc, { size: 64 }));
writeFileSync(out('web/favicon-64.png'), await renderPng(doc, { size: 64 }));
const ico = [16, 32, 48];
const icoPngs = await Promise.all(ico.map((s) => renderPng(doc, { size: s, rim: s >= 32 })));
writeFileSync(out('web/favicon.ico'), encodeIco(ico.map((s, i) => ({ size: s, png: icoPngs[i] }))));
// Apple touch icon: 不透明・マスクなし（iOS 側がマスクを掛ける）
writeFileSync(out('web/apple-touch-icon.png'), flattenPng(await renderPng(doc, { size: 180, mask: 'none', rim: false })));
writeFileSync(out('web/icon-192.png'), await renderPng(doc, { size: 192 }));
writeFileSync(out('web/icon-512.png'), await renderPng(doc, { size: 512 }));
writeFileSync(out('web/icon-maskable-512.png'), flattenPng(await renderPng(doc, { size: 512, mask: 'none', rim: false })));

// ---------------------------------------------------------------- social images
const FONT = "Inter, 'Noto Sans CJK JP', 'Hiragino Sans', -apple-system, 'Helvetica Neue', Arial, sans-serif";
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
function social(W, H) {
  const icon = Math.round(H * 0.46);
  const ix = Math.round(W * 0.08);
  const iy = Math.round((H - icon) / 2);
  const tx = ix + icon + Math.round(W * 0.05);
  const maxW = W - tx - Math.round(W * 0.05);
  const textH = Math.min(Math.round(H * 0.11), Math.floor((maxW * asc) / (wx1 - wx0)));
  const [c1, c2] = brand.glow;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">` +
    `<defs><radialGradient id="g1" cx="0.22" cy="0.3" r="0.6"><stop offset="0" stop-color="${c1}" stop-opacity="0.34"/><stop offset="1" stop-color="${c1}" stop-opacity="0"/></radialGradient>` +
    `<radialGradient id="g2" cx="0.85" cy="0.9" r="0.6"><stop offset="0" stop-color="${c2}" stop-opacity="0.26"/><stop offset="1" stop-color="${c2}" stop-opacity="0"/></radialGradient>` +
    `<filter id="sh" x="-30%" y="-30%" width="160%" height="170%"><feDropShadow dx="0" dy="${icon * 0.06}" stdDeviation="${icon * 0.07}" flood-color="#000" flood-opacity="0.55"/></filter></defs>` +
    `<rect width="${W}" height="${H}" fill="#0B0C14"/><rect width="${W}" height="${H}" fill="url(#g1)"/><rect width="${W}" height="${H}" fill="url(#g2)"/>` +
    `<g filter="url(#sh)">${iconInline(ix, iy, icon, 'so_')}</g>` +
    wordmark(tx, Math.round(H * 0.31), textH, '#F5F5F7') +
    `<text x="${tx}" y="${Math.round(H * 0.6)}" font-family="${FONT}" font-size="${Math.round(H * 0.056)}" font-weight="600" fill="#F5F5F7">${esc(brand.tagline)}</text>` +
    `<text x="${tx}" y="${Math.round(H * 0.69)}" font-family="${FONT}" font-size="${Math.round(H * 0.038)}" fill="#A1A1A6">${esc(brand.subline)}</text>` +
    `</svg>`
  );
}
writeFileSync(out('social/og-image.png'), await svgToPng(social(1200, 630), 1200));
writeFileSync(out('social/github-social-preview.png'), await svgToPng(social(1280, 640), 1280));
console.log('brand assets written');

function encodeIco(entries) {
  const head = 6 + entries.length * 16;
  const buf = new Uint8Array(head + entries.reduce((s, e) => s + e.png.length, 0));
  const dv = new DataView(buf.buffer);
  dv.setUint16(2, 1, true);
  dv.setUint16(4, entries.length, true);
  let off = head;
  entries.forEach((e, i) => {
    const p = 6 + i * 16;
    buf[p] = e.size >= 256 ? 0 : e.size;
    buf[p + 1] = e.size >= 256 ? 0 : e.size;
    dv.setUint16(p + 4, 1, true);
    dv.setUint16(p + 6, 32, true);
    dv.setUint32(p + 8, e.png.length, true);
    dv.setUint32(p + 12, off, true);
    buf.set(e.png, off);
    off += e.png.length;
  });
  return buf;
}
