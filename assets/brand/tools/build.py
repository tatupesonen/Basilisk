"""Regenerate the Basilisk brand set in assets/brand from the original scripts.

Runs the same chain that produced the committed files on 2026-11-12:

1. brand2.py / brand.py / word.py write the mark, logo and icon SVGs in the
   first (green) palette;
2. the ember palette is applied by colour substitution (it was a `sed` then);
3. sm.py draws the heavier 16/32 px icon (variant s2 of the ember rebuild);
4. resvg renders the icon PNGs and the mark/logo previews;
5. sheets.py redraws the overview and variants preview sheets.

Usage (from anywhere): python3 assets/brand/tools/build.py [--svg-only]
Needs python3 with Pillow, resvg at ~/.cargo/bin/resvg (or on PATH), and,
for the sheets, macOS's Helvetica. Nothing under variants/ or concepts/ is
written. Run `git status assets/brand` afterwards: on an unchanged design
every file comes out byte-identical.
"""
import os
import shutil
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)

import brand  # noqa: E402
import brand2  # noqa: E402
import sm  # noqa: E402

OUT = brand.OUT
RESVG = shutil.which('resvg') or os.path.expanduser('~/.cargo/bin/resvg')

# The ember palette (owner's choice, variant A4), as substitutions over the
# green palette the drawing scripts emit.
EMBER = {'#B8F03C': '#FF6A2B', '#0F1412': '#150F0D', '#E9EEE2': '#F1ECE6'}
EMBER_DEEP = {'#4A8500': '#E8551A'}  # light-background files only
SOOT = '#150F0D'
SMALL_S2 = dict(th_a=352, tm=38, tn=44, chs=(36, 54, 36), cw=9, cth=(108, 90, 72), pup=(128, 170, 42, 24))


def recolour(svg, table):
    for a, b in table.items():
        svg = svg.replace(a, b)
    return svg


def write_svgs():
    brand.FULL = brand2.FULL
    full = brand2.FULL
    green = {
        'basilisk-mark.svg': brand.mark(brand.VENOM, full),
        'basilisk-mark-light.svg': brand.mark(brand.MOSS, full),
        'basilisk-mark-mono.svg': brand.mark('currentColor', full),
        'basilisk-logo.svg': brand.logo(brand.MOSS, brand.OBSIDIAN, brand.MOSS),
        'basilisk-logo-dark.svg': brand.logo(brand.VENOM, brand.BONE, brand.VENOM),
        'basilisk-icon.svg': brand.icon(full, 0.76, 0),
    }
    ember_files = ('basilisk-mark.svg', 'basilisk-logo-dark.svg', 'basilisk-icon.svg', 'basilisk-logo.svg')
    deep_files = ('basilisk-mark-light.svg', 'basilisk-logo.svg')
    for name, svg in green.items():
        if name in ember_files:
            svg = recolour(svg, EMBER)
        if name in deep_files:
            svg = recolour(svg, EMBER_DEEP)
        brand.w(name, svg)
    brand.w('basilisk-icon-small.svg', sm.small(**SMALL_S2))


def render(src, dst, size, bg=None):
    cmd = [RESVG, '-w', str(size)]
    if bg:
        cmd += ['--background', bg]
    subprocess.run(cmd + [os.path.join(OUT, src), os.path.join(OUT, dst)], check=True)


def write_pngs():
    for sz in (16, 32):
        render('basilisk-icon-small.svg', f'png/basilisk-icon-{sz}.png', sz)
    for sz in (64, 128, 256, 512, 1024):
        render('basilisk-icon.svg', f'png/basilisk-icon-{sz}.png', sz)
    render('basilisk-mark.svg', 'png/preview-mark.png', 1024, SOOT)
    render('basilisk-logo-dark.svg', 'png/preview-logo-dark.png', 1400, SOOT)
    render('basilisk-logo.svg', 'png/preview-logo-light.png', 1400, '#FFFFFF')
    subprocess.run([sys.executable, os.path.join(TOOLS, 'sheets.py')], check=True)


if __name__ == '__main__':
    write_svgs()
    if '--svg-only' not in sys.argv[1:]:
        write_pngs()
