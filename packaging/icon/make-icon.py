#!/usr/bin/env python3
"""Generate every icon asset from one drawing.

Run from the repository root:

    python packaging/icon/make-icon.py

Writes the PNG sizes, icon.ico for Windows, icon.icns for macOS and splash.png for the
Velopack installer, then copies icon.ico into the app's Assets folder.

Regenerate rather than hand-editing any of the outputs: they are all derived from draw_icon
below, and an edited copy would be silently overwritten the next time this runs.
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
ASSETS = HERE.parent.parent / "src" / "PgpUtility.App" / "Assets"

# Teal rather than the indigo the resume builder uses. Same visual treatment, so the two read as
# a family, different hue so they are not mistaken for each other in a dock or a task bar.
TOP = (20, 184, 166)
BOTTOM = (13, 106, 116)
GLYPH = (255, 255, 255)


def rounded_gradient(size: int) -> Image.Image:
    """A rounded square filled with a vertical gradient."""
    gradient = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(size - 1, 1)
        gradient.putpixel((0, y), tuple(
            round(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3)
        ))
    gradient = gradient.resize((size, size))

    # Supersampled mask, so the corners are smooth at every size rather than stair-stepped at the
    # small ones where it shows most.
    scale = 4
    mask = Image.new("L", (size * scale, size * scale), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, size * scale - 1, size * scale - 1),
        radius=int(size * scale * 0.22),
        fill=255,
    )
    mask = mask.resize((size, size), Image.LANCZOS)

    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(gradient, (0, 0), mask)
    return out


def draw_icon(size: int) -> Image.Image:
    """A padlock, drawn at 4x and downsampled so the strokes stay clean."""
    scale = 4
    s = size * scale
    canvas = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)

    body_w = s * 0.46
    body_h = s * 0.34
    body_x = (s - body_w) / 2
    body_y = s * 0.50

    shackle_w = body_w * 0.62
    shackle_x = (s - shackle_w) / 2
    shackle_top = s * 0.24
    stroke = s * 0.055

    # Shackle: a half circle plus the two straight legs meeting the body.
    draw.arc(
        (shackle_x, shackle_top, shackle_x + shackle_w, shackle_top + shackle_w),
        start=180, end=360, fill=GLYPH, width=round(stroke),
    )
    leg_y = shackle_top + shackle_w / 2
    for x in (shackle_x + stroke / 2, shackle_x + shackle_w - stroke / 2):
        draw.line((x, leg_y, x, body_y + stroke * 0.2), fill=GLYPH, width=round(stroke))

    draw.rounded_rectangle(
        (body_x, body_y, body_x + body_w, body_y + body_h),
        radius=s * 0.045, fill=GLYPH,
    )

    # Keyhole, punched out so the gradient shows through.
    hole_r = s * 0.038
    hole_cx = s / 2
    hole_cy = body_y + body_h * 0.38
    draw.ellipse(
        (hole_cx - hole_r, hole_cy - hole_r, hole_cx + hole_r, hole_cy + hole_r),
        fill=(0, 0, 0, 0),
    )
    draw.polygon(
        [
            (hole_cx - hole_r * 0.55, hole_cy),
            (hole_cx + hole_r * 0.55, hole_cy),
            (hole_cx + hole_r * 0.30, body_y + body_h * 0.76),
            (hole_cx - hole_r * 0.30, body_y + body_h * 0.76),
        ],
        fill=(0, 0, 0, 0),
    )

    glyph = canvas.resize((size, size), Image.LANCZOS)
    icon = rounded_gradient(size)
    icon.alpha_composite(glyph)
    return icon


def write_icns(images: dict[int, Image.Image], path: Path) -> None:
    """Write an .icns container by hand.

    Pillow's ICNS support is read-only on anything that is not macOS, and the release workflow
    packages the Mac build on a runner where this script may not run at all, so the file is
    committed. The modern types are all just embedded PNGs in a typed chunk.
    """
    types = {
        "ic07": 128, "ic08": 256, "ic09": 512,
        "ic10": 1024, "ic11": 32, "ic12": 64,
        "ic13": 256, "ic14": 512,
    }

    chunks = b""
    for code, size in types.items():
        import io
        buffer = io.BytesIO()
        images[size].save(buffer, format="PNG")
        data = buffer.getvalue()
        chunks += code.encode("ascii") + struct.pack(">I", len(data) + 8) + data

    path.write_bytes(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)


def make_splash(path: Path) -> None:
    """The image Velopack shows while a Windows install runs."""
    width, height = 480, 280
    splash = Image.new("RGBA", (width, height), (255, 255, 255, 255))
    icon = draw_icon(96)
    splash.alpha_composite(icon, ((width - 96) // 2, 58))

    draw = ImageDraw.Draw(splash)
    label = "PGP Utility"
    # Default bitmap font: no font file to ship, and the splash is on screen for a few seconds.
    box = draw.textbbox((0, 0), label)
    draw.text(
        ((width - (box[2] - box[0])) / 2, 178),
        label, fill=(30, 41, 59),
    )
    splash.convert("RGB").save(path)


def main() -> None:
    sizes = [16, 32, 48, 64, 128, 256, 512, 1024]
    images = {size: draw_icon(size) for size in sizes}

    for size in (32, 64, 128, 256, 512):
        images[size].save(HERE / f"icon-{size}.png")

    images[1024].save(HERE / "icon-1024.png")

    # Every size Windows picks from, in one file.
    images[256].save(
        HERE / "icon.ico",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    write_icns(images, HERE / "icon.icns")
    make_splash(HERE / "splash.png")

    ASSETS.mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "icon.ico", ASSETS / "icon.ico")
    images[256].save(ASSETS / "icon.png")

    print(f"wrote icons to {HERE} and {ASSETS}")


if __name__ == "__main__":
    main()
