# Track `spec-decomp-wave2` — status report

Specification track for D06 (`decomp-symbols`, new document) and the
revision of D05 (`decomp-ir`) of `docs/features/decomp-plan.md`. Writes no
shipping code.

## State

- [x] Rules, plan (with its amendments), ADRs, D00/D04 specs and the
      wave-1 report read; existing crates' APIs read.
- [x] D06 source reading: `database.*`, `rangemap.hh`, `partmap.hh`,
      `comment.*`, `stringmanage.*`, `cpool.*`, `loadimage*.*`,
      `globalcontext.*`, `override.*`, the `ghidra_*` host classes,
      the parts of `architecture.cc`, `sleigh_arch.cc`, `xml_arch.cc`
      that build and fill these.
- [x] D06 oracle prototypes run on both reference builds (W2–W4).
- [x] `docs/features/decomp-symbols.md` (complete draft).
- [ ] D05 revision.
- [ ] Final report.

## Next

D05 revision of `docs/features/decomp-ir.md`: fold the corrections,
check against `varnode.*`, `op.*`, `cover.*`, `BlockBasic`,
`funcdata_*`, align with D00 (as merged) and D04.

## Notes so far (2026-11-15, paused)

- `image_oracle` (data-test `<binaryimage>`, property map, global scope,
  context): run on the Mac and on the build host; after sorting by file
  the two tables are identical (8,435 rows: 93 files, 349 chunks after
  pad, 248 loader symbols, 173 read-only ranges, 403 property change
  points, 658 global-scope entries, 180 context split points, 158
  tracked-set split points, 1,744 load probes of which 432 fail).
- `scope_oracle`: second crash found to be Ghidra's (an entry past the
  end of its space, `addMapSym`); runs clean after avoiding it. Encoding an instantiated function
  without a prototype model crashes in `FuncProto::encode` (null
  `model`, fspec.cc:4569) — confirmed, worked around by hiding the
  Funcdata.
- Defects read so far: `Scope::addUnassigned` use after free
  (database.cc:1294–1297); `Symbol::getMapEntryPosition` tests the
  argument's size instead of each entry's (database.cc:395);
  `CPoolRecord::encode` writes bytes as characters (cpool.cc:67);
  `putRecord` leaves `flags`/`value` uninitialised; hex decoders of
  `LoadImageXml::open` and `StringManager::decode` loop forever with
  unsigned `char` (loadimage_xml.cc:115–135, stringmanage.cc:246–266);
  `ContextInternal::decodeContext` zeroes the default for every `<set>`
  (globalcontext.cc:355–358); `clearCategory`/`clearUnlockedCategory`
  dereference null holes; `ArchitectureGhidra::buildSymbols` resolves
  `next` from the last volatile symbol only; `RawLoadImage::open` opens
  in text mode.
