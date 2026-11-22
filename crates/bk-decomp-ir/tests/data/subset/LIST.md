# The checked-in subset (`tests/subset.rs`, `select_subset`)

Chosen for coverage of opcodes and op/varnode flag bits (rarest first)
among the functions whose dumps all round-trip in a language with a
checked-in table.

- `datatests.floatcast.1`
- `datatests.floatprint.0`
- `datatests.readvolatile.0`
- `datatests.gp.0`
- `datatests.impliedfield.0`
- `datatests.condconstsub.0`
- `datatests.retspecial.0`
- `datatests.statuscmp.0`
- `datatests.bitfields.1`
- `datatests.lzcount.0`
- `datatests.bitfields.2`
- `research.r12_vla.x64-clang-O2.0`
- `datatests.switchmulti.0`
- `datatests.condexesub.0`
- `research.a03_params.a64-gcc-O2.4`
- `datatests.elseif.0`
- `research.r05_divmod.a64-gcc-O2.12`
- `datatests.partialsplit.0`
- `datatests.floatconv.0`
- `datatests.inline.2`

Features in the full capture: 137; covered: 137; not covered (only in functions that cannot be checked in): []
