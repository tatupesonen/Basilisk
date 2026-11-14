# Basilisk brand assets

![overview](png/preview-overview.png)

## The idea

The Basilisk is the crowned serpent whose gaze kills. The mark is that
serpent coiled into a ring, and the ring is the iris of an eye: the slit in
the middle is the pupil. A tool that stares into binaries gets an emblem
that is itself a stare. Read small it is an eye with a crown; read large it
is a serpent chasing its tail. The ring and the stroke inside it are also a
0 and a 1.

The body is a perfect circle on the outside and a near-even ring for three
quarters of the way round, then thins into a blade for the tail. The tip of
the crown, the point of the jaw and the pupil sit on one vertical axis
through the centre of the ring, so the mark is symmetrical apart from the
head and the tail. Head, crown, pupil and tail all end in sharp points;
everything else is one circle. In the icon the ring is centred on the tile.

It sits in the same family as Ghidra's dragon (a mythical beast as a flat
emblem, coiled) but shares no shapes or lettering with it: this is a
legless, wingless serpent built from one circle, with an eye in the
middle. It uses no Rust or Ferris artwork.

## Palette

Ember orange was the owner's choice (variant A4 below), replacing the
first, acid-green palette.

| Name       | Hex       | Use                                            |
|------------|-----------|------------------------------------------------|
| Ember      | `#FF6A2B` | The mark on dark backgrounds; accents          |
| Ember deep | `#E8551A` | The mark on light backgrounds                  |
| Soot       | `#150F0D` | Icon tile, dark backgrounds, wordmark on light |
| Bone       | `#F1ECE6` | Wordmark and text on dark                      |

Flat colour only. No gradients, glows, outlines or shadows.

Measured contrast (WCAG ratio): Ember on Soot 6.6:1; Bone on Soot 16.2:1;
Soot on white 19.0:1. Ember on white is only 2.9:1, under the 3:1 a
graphic needs, which is why light backgrounds get Ember deep: 3.7:1 on
white (and 5.2:1 on Soot, so it also survives a dark background).

Ember is hue 18°, a red-orange. Ghidra's dragon and Binary Ninja's mark are
both reds (hue near 0°; recalled, not sampled from their artwork), so of
all the colourways tried this one sits closest to them; Ember deep, being darker, reads a little redder still. If
more distance is wanted, shift both toward amber (hue 30-40°).

## Files

| File                       | Use it for                                                        |
|----------------------------|-------------------------------------------------------------------|
| `basilisk-mark.svg`        | Emblem alone, Ember, transparent. Dark backgrounds (in-app, about box, dark docs). |
| `basilisk-mark-light.svg`  | Emblem alone, Ember deep, transparent. Light backgrounds.         |
| `basilisk-mark-mono.svg`   | Emblem in `currentColor`. One-colour print, UI glyphs, anything that must inherit the text colour. |
| `basilisk-logo.svg`        | Emblem + wordmark for light backgrounds.                          |
| `basilisk-logo-dark.svg`   | Emblem + wordmark for dark backgrounds.                           |
| `basilisk-icon.svg`        | App icon: emblem on the Soot tile.     Source for 64 px and up.   |
| `basilisk-icon-small.svg`  | Simplified icon for 16 and 32 px: heavier, fuller ring, bigger crown and pupil, no head eye, pupil centred on the pixel grid. |
| `png/basilisk-icon-N.png`  | Icon renders at 16, 32, 64, 128, 256, 512, 1024 px (window icon, favicon, bundles). |
| `png/preview-*.png`        | Previews only (mark, both logos, overview and variants sheets). Not for shipping. |
| `variants/`                | The colour, shape and tile variants the palette was chosen from, see below. |
| `concepts/`                | Rejected directions, see below.                                   |

For a README that follows the viewer's theme:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/basilisk-logo-dark.svg">
  <img src="assets/brand/basilisk-logo.svg" alt="basilisk" width="360">
</picture>
```

The wordmark is drawn as strokes and polygons, so no font is needed. The
dots on the two i's repeat the slit pupil.

## Clear space and minimum size

- Clear space: keep a margin of at least a quarter of the ring's diameter
  on every side of the mark or logo. Nothing else goes inside it.
- Mark: 24 px minimum on screen, 8 mm in print. Below 24 px use the icon
  PNGs (16 and 32 px come from the simplified artwork).
- Logo: 120 px wide minimum on screen, 30 mm in print.
- Icon: 16 px minimum. At 16 px it reads as a crowned ring with a slit; the
  serpent's head only resolves from 32 px up.
- Do not recolour outside the palette, rotate, stretch, outline, or put the
  Ember mark on a light background (use Ember deep or mono there).

## Editing and re-rendering

The SVGs are plain paths in a 256-unit box. The ring is a circle of radius
100 centred on (128, 148); its outer edge is one arc command and its inner
edge is nine cubic segments. Head and crown are straight-edged polygons and
the pupil is two circular arcs centred on x = 128, all safe to nudge by
hand.

Regenerate the PNGs with [resvg](https://github.com/linebender/resvg):

```sh
cd assets/brand
for s in 16 32;              do resvg -w $s basilisk-icon-small.svg png/basilisk-icon-$s.png; done
for s in 64 128 256 512 1024; do resvg -w $s basilisk-icon.svg       png/basilisk-icon-$s.png; done
```

### Generator scripts

`tools/` holds the Python scripts that drew this set on 2026-11-12. They
were never committed on the `logo` branch; they were recovered verbatim
from the session transcript of the agent that made the set (its scratch
directory was gone):

- `word.py`: the wordmark geometry (letters as strokes and polygons).
- `brand.py`: the first mark, the logo lock-up (mark + wordmark), the icon
  and file writing; `brand2.py`: the final, centred mark, which reuses
  `brand.py` and writes the set in the first (green) palette.
- `sm.py`: the heavier 16/32 px icon of the ember rebuild (variant `s2`).
- `sheets.py`: the overview and variants preview sheets.

The ember palette was then applied with `sed` over the written SVGs
(`#B8F03C`→`#FF6A2B`, `#0F1412`→`#150F0D`, `#E9EEE2`→`#F1ECE6`, and
`#4A8500`→`#E8551A` in `basilisk-mark-light.svg` and `basilisk-logo.svg`).
`tools/build.py` runs that whole chain, palette step included, and
rewrites the SVGs, the icon PNGs and the previews in place (never
`variants/` or `concepts/`):

```sh
python3 assets/brand/tools/build.py             # SVGs, PNGs and preview sheets
python3 assets/brand/tools/build.py --svg-only  # SVGs only
git status assets/brand                         # only what the edit changed
```

It needs Python 3 with Pillow, `resvg` (on `PATH` or in `~/.cargo/bin`) and,
for the preview sheets, macOS's Helvetica. On an unchanged design every
output comes out byte-identical to the committed file (checked with resvg
0.49.0). Edit the drawing in `word.py`, `brand.py` or `brand2.py`, not in
the SVGs; `brand.py` and `brand2.py` are libraries and refuse to run on
their own. Then copy the logo paths into `site/src/components/Logo.astro`,
which inlines the logo.

## Variants

![variants](png/preview-variants.png)

`variants/` holds alternatives of the same flat mark, each a complete icon
SVG named by the code on the sheet. They are options, not part of the set.
The owner picked **A4, ember**, for the colour; the main files are built
from A4 with the shape and tile unchanged (B1 on the rounded square). Rows
B and C are still drawn in the first green.

- **A, colour** (same shape): A1 Venom green `#B8F03C` on Obsidian
  `#0F1412` (the first palette), A2 inverted, A3 gold, **A4 ember
  (chosen)**, A5 glass cyan, A6 nightshade violet, A7 bone, A8 bone with a
  Venom pupil, A9 Venom with an ember pupil. There is no pure red on
  purpose: that is Ghidra's colour.
- **B, shape** (same colour): B1 even ring with lens pupil (current),
  B2 tapered ring (the first version), B3 gem pupil, B4 iris disc with the
  slit cut out, B5 bar pupil (a literal 0 and 1), B6 bold, B7 fine line,
  B8 closed ring with the tail tucked under the jaw (the most symmetrical),
  B9 five-point crown.
- **C, tile**: C1 round, C2 hexagon, C3 no tile.

A two-tone faceted version was tried and dropped in favour of the flat
mark; it is in the branch history (`a55ab1c`).

## Rejected concepts

Kept in `concepts/` so a different direction can be picked up.

- `01-hooded-eye.svg` — a cobra hood seen head-on with one eye in it (the monocled cobra). Bold at 16 px, but reads as a tulip or a heart, not a serpent.
- `02-lidded-serpent.svg` — a serpent as the eyelids of an almond eye. Reads as a stock eye icon with lashes; the head is an afterthought.
- `03-rearing-b.svg` — a rearing serpent that forms a lowercase b, its coil an eye. The runner-up: the most distinct from Ghidra, but more mascot than emblem and a "6" at 16 px.
- `04-profile-head.svg` — a crowned head in profile. The most literal and the most rooster-like; a blob below 32 px.
- `05-crowned-bit.svg` — a 0 and a 1 as iris and pupil under a crown. Clean, but there is no creature in it; it looks like a token. Its eye survived into the final mark.
- `06-bracket-eye.svg` — angle brackets as eyelids around a slit pupil. Looks like every other developer-tool logo, and the crown floats.
- `07-faceted-mask.svg` — a faceted, horned mask with one eye. Strong silhouette, generic menace; nothing says serpent.
