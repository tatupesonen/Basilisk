# Oracle for `bk-decomp-types`

`types_oracle.cc` is linked with the reference build's objects (Ghidra's
compiled decompiler, `scripts/build-reference.sh`) and prints what Ghidra's
`TypeFactory`, C parser and data organisation give for the declarations in
`decls.txt`, in six languages, plus the data organisation of every
language/compiler pair. The record format is described at the top of the
source.

Regenerate (needs `../reference`, Unix only; about one minute):

    crates/bk-decomp-types/tests/oracle/regen.sh /path/to/reference

It compiles the generator with `c++ -std=c++11 -fno-access-control
-fsigned-char -DLOCAL_ZLIB` against `reference/src/cpp/com_opt/*.o` (all but
`consolemain.o`) and writes `../data/types_oracle.txt.gz` and
`../data/types_orgs.txt.gz`. Nothing is written into `../ghidra` or
`../reference`.
