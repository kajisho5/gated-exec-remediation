#!/usr/bin/env python3
"""ワードマークを Inter Display SemiBold (SIL OFL 1.1) からアウトライン化して SVG パスにする。
fresnel の brand/src/wordmark.py と同じ手法・同じ tracking。

    python3 brand/src/wordmark.py "<text>" [font.otf]     # 要 fonttools
"""
import json, sys
from pathlib import Path
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

TEXT = sys.argv[1]
FONT = sys.argv[2] if len(sys.argv) > 2 else '/usr/share/fonts/opentype/inter/InterDisplay-SemiBold.otf'
TRACK = -0.02  # em

font = TTFont(FONT)
gs = font.getGlyphSet()
cmap = font.getBestCmap()
upm = font['head'].unitsPerEm
hmtx = font['hmtx']
pen = SVGPathPen(gs)
bounds = BoundsPen(gs)
x = 0
for ch in TEXT:
    name = cmap[ord(ch)]
    tp = (1, 0, 0, -1, x, 0)  # フォント座標は y 上向き
    gs[name].draw(TransformPen(pen, tp))
    gs[name].draw(TransformPen(bounds, tp))
    x += hmtx[name][0] + TRACK * upm
out = Path(__file__).resolve().parent / 'wordmark.json'
out.write_text(json.dumps({'text': TEXT, 'd': pen.getCommands(), 'bbox': list(bounds.bounds), 'upm': upm, 'cap': font['OS/2'].sCapHeight, 'font': Path(FONT).name}))
print('wrote', out)
