# spec-plugin — status

Specification track for the plugin system (ADR-014). Products:
`docs/inventory/05-extension-points.md`, `docs/features/plugin-api.md`,
`docs/features/plugin-binding-constraints.md`, experiments under
`docs/agents/spec-plugin-experiments/`.

## Done
- Read RULES, DIRECTION, LOOP, the ADRs named in the brief, PLAN, ui-shell,
  the bk-ui data interface and action registry, decomp-plan sections 3 and D06.
- `docs/inventory/05-extension-points.md` written and committed, with the
  bundled-script census (`spec-plugin-experiments/script-census/`).
- PyO3 0.30.1 experiments run and committed (`spec-plugin-experiments/README.md`):
  abi3 module loads in 3.10–3.14; GIL release, callbacks from Rust threads,
  cancellation, exception mapping, transaction context manager all work;
  a binary linking libpython does not start without it.

## In progress
- `docs/features/plugin-api.md`.

## Next
- `docs/features/plugin-binding-constraints.md`, final report.
