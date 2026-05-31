"""
Generate locker.ico — a clean padlock glyph in the app's indigo theme.
Run once:  python make_icon.py
Produces a multi-resolution .ico (16–256 px) for the exe, dialogs and shortcut.
"""
from PIL import Image, ImageDraw


def rounded(draw, box, r, fill):
    draw.rounded_rectangle(box, radius=r, fill=fill)


def render(size: int) -> Image.Image:
    # Supersample for smooth edges, then downscale.
    S = size * 4
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    indigo      = (99, 102, 241, 255)    # #6366f1
    indigo_dark = (79, 70, 229, 255)     # #4f46e5
    white       = (245, 247, 251, 255)

    # Rounded-square app background
    pad = int(S * 0.06)
    rounded(d, [pad, pad, S - pad, S - pad], int(S * 0.22), indigo)

    # Padlock geometry
    cx = S // 2
    body_w = int(S * 0.46)
    body_h = int(S * 0.34)
    body_top = int(S * 0.46)
    body_left = cx - body_w // 2
    body_right = cx + body_w // 2
    body_bottom = body_top + body_h

    # Shackle (the arch) — drawn as a thick arc
    shackle_w = int(body_w * 0.62)
    shackle_top = int(S * 0.24)
    sx0 = cx - shackle_w // 2
    sx1 = cx + shackle_w // 2
    thick = int(S * 0.075)
    d.arc([sx0, shackle_top, sx1, body_top + int(S * 0.04)],
          start=180, end=360, fill=white, width=thick)
    # straight legs of the shackle down to the body
    d.line([sx0 + thick // 2, (shackle_top + body_top) // 2 + int(S*0.02),
            sx0 + thick // 2, body_top], fill=white, width=thick)
    d.line([sx1 - thick // 2, (shackle_top + body_top) // 2 + int(S*0.02),
            sx1 - thick // 2, body_top], fill=white, width=thick)

    # Lock body
    rounded(d, [body_left, body_top, body_right, body_bottom],
            int(S * 0.05), white)

    # Keyhole
    kh_r = int(S * 0.045)
    d.ellipse([cx - kh_r, body_top + int(body_h * 0.28) - kh_r,
               cx + kh_r, body_top + int(body_h * 0.28) + kh_r],
              fill=indigo_dark)
    d.polygon([
        (cx - int(kh_r * 0.55), body_top + int(body_h * 0.30)),
        (cx + int(kh_r * 0.55), body_top + int(body_h * 0.30)),
        (cx + int(kh_r * 0.30), body_top + int(body_h * 0.68)),
        (cx - int(kh_r * 0.30), body_top + int(body_h * 0.68)),
    ], fill=indigo_dark)

    return img.resize((size, size), Image.LANCZOS)


sizes = [256, 128, 64, 48, 32, 24, 16]
base = render(256)
base.save("locker.ico", format="ICO", sizes=[(s, s) for s in sizes])
print("Wrote locker.ico with sizes", sizes)
