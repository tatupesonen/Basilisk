# Track `spec-decomp-wave3` — status report

Specification track for D07 (`decomp-core`, crate `bk-decomp-core`) and
D08 (`decomp-typeop`, crate `bk-decomp-typeop`) of
`docs/features/decomp-plan.md`. Writes no shipping code. **In progress.**

## State

- [x] Rules, direction, loop, ADRs (to ADR-048), plan with amendments 11
      and 12, the neighbouring specs (D00 to D06), the wave-2 report, the
      inventory read.
- [ ] D07 source reading (`action.*`, `options.*`, `funcdata*.*`,
      `architecture.*`, `expression.*`, `transform.*`, `FuncCallSpecs`,
      `userop.*`, `pcodeinject.*`, `dynamic.*`).
- [ ] D07 runs against the reference consoles.
- [ ] `docs/features/decomp-core.md`.
- [ ] D08 source reading (`typeop.*`, `cast.*`, `unionresolve.*`, the
      IR-bound methods of `type.cc`).
- [ ] D08 runs and oracle prototype.
- [ ] `docs/features/decomp-typeop.md`.
- [ ] This report, final form.

## Misfits with D05 and D06 found so far (told early)

None yet. This section is committed as soon as one is found.

## Next

Read `action.cc` and `action.hh`; run `list action` for the six roots.
