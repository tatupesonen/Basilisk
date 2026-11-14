# Research notes for the decompiler's second-wave specs (D06, D05)

Evidence behind `docs/features/decomp-symbols.md` and the revision of
`docs/features/decomp-ir.md`. Track report: `docs/agents/spec-decomp-wave2.md`.

| File | What it is |
|---|---|
| `build.sh` | Builds one prototype against a reference build's optimised objects (`com_opt/*.o` minus `consolemain.o`, the bundled zlib), with the Makefile's flags plus `-fno-access-control`: `sh build.sh REF SRC.cc OUT` |
| `image_oracle.cc` | Per data test: the `<binaryimage>` load image after `pad()`, read-only ranges, loader symbols, property map, global scope (`printBounds`, `printEntries`), context variables, split points and tracked sets, and `loadFill` probes around every chunk |
| `scope_oracle.cc` | `ScopeInternal`/`Database` over generated symbol sets (global scope, up to three namespaces, `<mapsym>` decoding, mutations, every query kind, `printEntries`, `encode`) |
| `context_oracle.cc` | `ContextInternal` over generated variables and operations (defaults, change points, regions, tracked sets, look-ups, encode, decode of its own encoding) |
| `runs.md` | What was run, where, and what it printed |
