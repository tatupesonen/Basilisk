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

1. **D05 never tells the owner of high variables that a varnode changed.**
   In Ghidra every `Varnode` setter forwards to its `HighVariable`
   (read, `CPP/varnode.cc`): `setFlags`/`clearFlags` call
   `high->flagsDirty()` and, when the bits include `coverdirty`,
   `high->coverDirty()` (371–393; `setDef` 421–436 and `addDescend`/
   `eraseDescend` reach them with `coverdirty` on every structural edit);
   `updateType` (both forms) and `copySymbol` call `high->typeDirty()`
   (487–537); `setSymbolProperties`, `setSymbolEntry`, `copySymbol` call
   `high->setSymbol(this)` (441–471, 536); `setSymbolReference` calls
   `high->setSymbolReference` (478–484); `clearSymbolLinks` walks the
   high's instances and calls `symbolDirty()` (397–415); the destructor
   calls `high->remove(this)` and deletes an unattached high (645–651).
   `coverDirty` also marks the piece group (`variable.hh` 276–281).
   `decomp-ir.md` 4.1 and 4.5 list the setters and `set_high`, and the
   implementation (`crates/bk-decomp-ir/src/mutate/annotate.rs` on branch
   `decomp-ir`: `varnode_set_flags`, `update_type`, `set_symbol_entry`,
   `copy_symbol`) changes the varnode only. `FunctionEnv` has
   `assign_high` and nothing else for highs. The high table is D07 state
   with D14's algorithms, so D05 cannot do the work itself, but it is the
   only place that sees every change. Without a channel the dirty bits of
   `@highs` (`highflags`) cannot be reproduced from `assignhigh` onwards
   (D14, D15, `setcasts`, the printer's builder).
   **What must change in D05**: every `Ssa` method that corresponds to one
   of the `Varnode` members above records an event for the varnode's high,
   in call order, when the varnode has one: `FlagsDirty`, `CoverDirty`,
   `TypeDirty`, `SymbolDirty`, `SetSymbol(vn)`, `SetSymbolReference(vn,
   entry, offset)`, `Removed(vn)`. Either a queue the `Ssa` owns (`fn
   take_high_events(&mut self) -> impl Iterator<Item = HighEvent>`,
   allocation only when highs exist) or a method on `FunctionEnv` called at
   those points; the queue needs no signature change. D07's function state
   drains it before any read of a high (D07 spec, 4.A.9). Nothing in
   D05's acceptance changes: no event is produced while `high` is unset,
   which is every state D05's tests load before `assignhigh`.
2. **A doubt about a recorded Ghidra defect** (D06's defect 16,
   `docs/GHIDRA-BUGS.md` "Smaller observations", `decomp-symbols.md` 4.17
   and 4.21 row 16: "`Architecture::decodeFlowOverride`
   (`architecture.cc:475–476`) closes its element twice"). Read again
   (`architecture.cc` 452–481): line 465 closes the `<flow>` child, line
   475 the `<calldest>` child, line 480 the list; each opened element is
   closed once. What the loop does get wrong is an unknown child: it is
   opened at 457 and never closed, so the `closeElement(elemId)` at 480
   fails. D06's "closes once" behaviour is unaffected; the bug entry
   should be reworded. Not run.

## Next

Continue the D07 source reading; the plan comparison below grows with it.
