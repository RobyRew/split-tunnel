#!/usr/bin/env python3
"""SplitTunnel app icons.

Motif: one stream enters, then SPLITS — the muted branch continues straight out
(your normal traffic, untouched) while the bright branch bends away through the
tunnel (the app you route via the VPS). That is literally what the tool does,
and it stays legible down to 16px in the Windows tray.
"""
from PIL import Image, ImageDraw
import pathlib

OUT = pathlib.Path(__file__).parent.parent / "src-tauri" / "icons"
OUT.mkdir(parents=True, exist_ok=True)
BG    = (13, 16, 22)
MUTED = (71, 85, 105)     # slate — untouched local traffic
A     = (16, 185, 129)    # emerald
B     = (34, 211, 238)    # cyan

def lerp(c1, c2, t):
    return tuple(round(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))

def bezier(p0, p1, p2, n=64):
    out = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        out.append((u*u*p0[0] + 2*u*t*p1[0] + t*t*p2[0],
                    u*u*p0[1] + 2*u*t*p1[1] + t*t*p2[1]))
    return out

def stroke(d, pts, w, c1, c2=None):
    """Smooth stroke: stamp a dense run of dots. Drawing per-segment lines
    leaves visible notches where the segments meet on a curve."""
    n = len(pts) - 1
    for i, (x, y) in enumerate(pts):
        c = c1 if c2 is None else lerp(c1, c2, i / n)
        d.ellipse([x-w/2, y-w/2, x+w/2, y+w/2], fill=c + (255,))

def render(px: int) -> Image.Image:
    S = px * 4
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, S-1, S-1], radius=int(S*0.22), fill=BG + (255,))

    w    = max(3, int(S * 0.075))
    ent  = (S*0.14, S*0.50)
    knot = (S*0.40, S*0.50)

    # shared entry
    stroke(d, bezier(ent, ((ent[0]+knot[0])/2, ent[1]), knot, 40), w, MUTED)

    # untouched branch — carries straight on, dim
    up = bezier(knot, (S*0.64, S*0.50), (S*0.87, S*0.28), 96)
    stroke(d, up, w, MUTED)

    # tunnelled branch — bright, slightly thicker, ends at the remote node
    dn = bezier(knot, (S*0.64, S*0.50), (S*0.83, S*0.75), 96)
    stroke(d, dn, int(w*1.15), A, B)

    # the split point
    r = w * 0.62
    d.ellipse([knot[0]-r, knot[1]-r, knot[0]+r, knot[1]+r], fill=(232, 240, 254, 255))

    # remote node the tunnelled branch terminates at
    nr = S * 0.078
    d.ellipse([dn[-1][0]-nr, dn[-1][1]-nr, dn[-1][0]+nr, dn[-1][1]+nr], fill=B + (255,))
    return img.resize((px, px), Image.LANCZOS)

for size in (16, 32, 48, 64, 128, 256, 512):
    render(size).save(OUT / f"{size}x{size}.png")
render(256).save(OUT / "128x128@2x.png")
render(512).save(OUT / "icon.png")
for n, s in (("Square30x30Logo", 30), ("Square44x44Logo", 44),
             ("Square150x150Logo", 150), ("StoreLogo", 310)):
    render(s).save(OUT / f"{n}.png")
render(256).save(OUT / "icon.ico", format="ICO",
                 sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
print("icons regenerated")
