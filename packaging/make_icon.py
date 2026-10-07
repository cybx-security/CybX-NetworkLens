#!/usr/bin/env python3
"""Draws the CybX NetworkLens app icon and writes it in every format the
build needs: packaging/icon/icon.png (256 px, also the Linux/macOS window
icon), icon.ico (Windows exe, shortcuts, installer) and icon.icns (macOS, via
iconutil).

The artwork is a placeholder - a radar sweep picking out hosts, in the same
blue as the other CybX desktop tools. To use real brand artwork, save a square
1024 px PNG as packaging/icon/icon-1024.png and run this script with
--from-png to regenerate the other files from it.

Only needed when the icon changes: the generated files are kept in the repo so
a build never depends on Pillow. Needs Pillow (pip install pillow); the .icns
step needs macOS.
"""
import math
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon")
SIZE = 1024
SS = 4  # supersampling factor for smooth edges


def draw():
    n = SIZE * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))

    # Background: rounded square, vertical gradient from accent blue to navy.
    top, bottom = (11, 95, 255), (14, 48, 138)
    grad = Image.new("RGBA", (n, n))
    gd = ImageDraw.Draw(grad)
    for y in range(n):
        t = y / (n - 1)
        gd.line([(0, y), (n, y)], fill=tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    mask = Image.new("L", (n, n), 0)
    pad = int(n * 0.06)
    ImageDraw.Draw(mask).rounded_rectangle([pad, pad, n - pad, n - pad], radius=int(n * 0.20), fill=255)
    img.paste(grad, (0, 0), mask)

    cx = cy = n // 2
    radius = int(n * 0.33)

    # Translucent parts go on an overlay and are composited: drawing them
    # straight onto an RGBA image replaces pixels instead of blending them.
    overlay = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    # The sweep: a wedge of the scope that has just been scanned.
    od.pieslice([cx - radius, cy - radius, cx + radius, cy + radius], start=-90, end=-20, fill=(255, 255, 255, 70))
    # Range rings.
    for frac in (1.0, 0.66, 0.33):
        r = int(radius * frac)
        od.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(255, 255, 255, 150), width=int(n * 0.016))
    img = Image.alpha_composite(img, overlay)

    d = ImageDraw.Draw(img)
    # Leading edge of the sweep and the hub it turns on.
    ang = math.radians(-20)
    d.line([(cx, cy), (cx + radius * math.cos(ang), cy + radius * math.sin(ang))],
           fill=(255, 255, 255, 255), width=int(n * 0.022))
    hub = int(n * 0.03)
    d.ellipse([cx - hub, cy - hub, cx + hub, cy + hub], fill=(255, 255, 255, 255))

    # Hosts found: two ordinary, one flagged.
    for (fx, fy, size, color) in [(-0.42, 0.30, 0.036, (255, 255, 255, 255)),
                                  (0.10, 0.52, 0.036, (255, 255, 255, 255)),
                                  (0.36, -0.52, 0.052, (255, 196, 64, 255))]:
        px, py, r = cx + int(radius * fx), cy + int(radius * fy), int(n * size)
        d.ellipse([px - r, py - r, px + r, py + r], fill=color)

    return img.resize((SIZE, SIZE), Image.LANCZOS)


def main():
    os.makedirs(HERE, exist_ok=True)
    master_png = os.path.join(HERE, "icon-1024.png")
    if "--from-png" in sys.argv:
        master = Image.open(master_png).convert("RGBA").resize((SIZE, SIZE), Image.LANCZOS)
    else:
        master = draw()

    # 256 px: the largest size a Windows icon holds, and plenty for a window icon.
    master.resize((256, 256), Image.LANCZOS).save(os.path.join(HERE, "icon.png"))
    master.save(os.path.join(HERE, "icon.ico"),
                sizes=[(s, s) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)])

    if shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "icon.iconset")
            os.makedirs(iconset)
            for pts in (16, 32, 128, 256, 512):
                master.resize((pts, pts), Image.LANCZOS).save(os.path.join(iconset, f"icon_{pts}x{pts}.png"))
                master.resize((pts * 2, pts * 2), Image.LANCZOS).save(os.path.join(iconset, f"icon_{pts}x{pts}@2x.png"))
            subprocess.run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(HERE, "icon.icns")], check=True)
    else:
        print("iconutil not found (not macOS): icon.icns was not regenerated", file=sys.stderr)


if __name__ == "__main__":
    main()
