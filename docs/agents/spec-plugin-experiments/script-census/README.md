# Bundled-script census

`classify.pl` flags which APIs each of Ghidra's bundled scripts touches and
puts it in a portability tier (A, B, C; definitions in
`docs/inventory/05-extension-points.md` section 3). `census.tsv` is its
output at Ghidra commit `42db038f3c`.

Reproduce, from `../ghidra`:

    find Ghidra GPL -path '*ghidra_scripts*' \( -name '*.java' -o -name '*.py' \) \
      | LC_ALL=C sort > /tmp/scripts.lst
    perl ../basilisk/docs/agents/spec-plugin-experiments/script-census/classify.pl \
      $(cat /tmp/scripts.lst) > census.tsv

Result: 310 Java scripts, 25 Python scripts, 21 helper classes; tiers
A 94, B 85, C 156.
