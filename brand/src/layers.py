#!/usr/bin/env python3
"""ZES / ZET / GER のアイコンレイヤー SVG（1024×1024・白 1 色・効果なし）を生成する。

    python3 brand/src/layers.py <zes|zet|ger>     # 要 shapely (pip install shapely)

3 製品で共通のファイル。fresnel の brand/src/{lens,rings}.svg と同じく、色・光・影は .icon 側（spec.json）で付ける。
"""
import math, sys
from pathlib import Path
from shapely import affinity
from shapely.geometry import LineString, Point, Polygon, box
from shapely.ops import unary_union


def to_svg(geom):
    d = []
    for g in getattr(geom, 'geoms', [geom]):
        for ring in [g.exterior, *g.interiors]:
            c = list(ring.coords)[:-1]
            d.append('M' + ' L'.join(f'{x:.1f},{y:.1f}' for x, y in c) + ' Z')
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024"><path fill-rule="evenodd" fill="#FFFFFF" d="{" ".join(d)}"/></svg>\n'


def shield(cx, top, w, h):
    """上辺フラット・側辺ストレート・下端が尖る盾（角は半径 40 で丸める）"""
    x0, x1 = cx - w / 2, cx + w / 2
    side = top + h * 0.42
    right = [(x1, top), (x1, side)]
    for i in range(1, 40):
        t = i / 40
        right.append((x1 - (w / 2) * t ** 1.6, side + (h - (side - top)) * math.sin(t * math.pi / 2)))
    left = [(2 * cx - x, y) for x, y in reversed(right)]
    return Polygon([*right, (cx, top + h), *left]).buffer(-40, join_style=1).buffer(40, join_style=1)


def band(g, t):
    return g.difference(g.buffer(-t, join_style=1))


def arch(x0, x1, top, bottom):
    r = (x1 - x0) / 2
    return unary_union([box(x0, top + r, x1, bottom), Point((x0 + x1) / 2, top + r).buffer(r, 128)])


def zes():
    s = shield(512, 140, 640, 752)
    rings = unary_union([band(s, 62), band(s.buffer(-118, join_style=1), 62)])  # fresnel の同心リングを盾に
    slash = affinity.rotate(box(497, 256, 527, 656), -38, origin=(512, 456))
    return {'shield.svg': rings, 'zero.svg': Point(512, 456).buffer(138, 128).difference(slash)}


def zet():
    tiers = unary_union([box(512 - w / 2 + 48, y + 48, 512 + w / 2 - 48, y + 48).buffer(48, 64) for w, y in [(704, 176), (512, 328), (320, 480)]])
    return {'tiers.svg': tiers, 'verdict.svg': Point(512, 740).buffer(108, 128)}


def ger():
    gate = arch(184, 840, 136, 888).difference(arch(292, 732, 244, 889))
    check = LineString([(392, 600), (484, 692), (650, 496)]).buffer(44, 32, join_style=1)
    return {'gate.svg': gate, 'check.svg': check}


if __name__ == '__main__':
    key = sys.argv[1]
    here = Path(__file__).resolve().parent
    for name, geom in {'zes': zes, 'zet': zet, 'ger': ger}[key]().items():
        (here / name).write_text(to_svg(geom))
        print('wrote', here / name)
