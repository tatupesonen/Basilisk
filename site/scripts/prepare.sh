#!/usr/bin/env bash
# Gathers the site's inputs from the rest of the repository into
# site/src/generated/ (git-ignored), so nothing is duplicated in git:
#   - the interface screenshots rendered by bk-ui (docs/features/ui-screenshots/),
#     plus cropped detail views of three of them (scripts/crops.mjs),
#   - the brand icon for the favicon (assets/brand/),
#   - the interface's OFL fonts (crates/bk-ui/assets/fonts/), subset to the
#     characters the site uses and converted to WOFF2, with their licences.
# Runs inside the site image (scripts/site.sh); needs fontTools.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=..
out=src/generated
rm -rf "$out"
mkdir -p "$out/screenshots" "$out/fonts" "$out/public/fonts"

cp "$repo"/docs/features/ui-screenshots/*.png "$out/screenshots/"
node scripts/crops.mjs
cp "$repo"/assets/brand/basilisk-icon-small.svg "$out/public/favicon.svg"
cp "$repo"/assets/brand/png/basilisk-icon-32.png "$out/public/favicon-32.png"
cp "$repo"/assets/brand/png/basilisk-icon-256.png "$out/public/apple-touch-icon.png"

# Latin, punctuation, arrows, maths, box drawing and the key symbols the
# key-binding chips use (⌘ ⌥ ⇧ ⏎ ⌫).
unicodes='U+0000-00FF,U+0100-017F,U+0192,U+02C6,U+02DC,U+2000-206F,U+20AC,U+2122,U+2190-21FF,U+2200-22FF,U+2318,U+2325,U+2326,U+232B,U+23CE,U+2500-257F,U+25A0-25FF'
fonts="$repo/crates/bk-ui/assets/fonts"
for f in Inter-Regular Inter-SemiBold JetBrainsMonoNL-Regular JetBrainsMonoNL-SemiBold; do
  python3 -m fontTools.subset "$fonts/$f.ttf" \
    --unicodes="$unicodes" --layout-features='*' --name-IDs='*' \
    --flavor=woff2 --output-file="$out/fonts/$f.woff2"
done
cp "$fonts/Inter-OFL.txt" "$fonts/JetBrainsMono-OFL.txt" "$out/public/fonts/"
echo "prepare: $(ls "$out/screenshots" | wc -l) screenshots, $(ls "$out/fonts" | wc -l) fonts"
