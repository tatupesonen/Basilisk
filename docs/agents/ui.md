# Track `ui` — status report

Branch `ui`, worktree `basilisk-wt/ui`. Spec `docs/features/ui-shell.md`,
design `docs/features/ui-design.md`. This file is kept current so the work
can be continued from it alone.

## State (2026-11-13)

Done and committed:
- `crates/bk-ui`: data interface (`model`), off-thread client (`task`),
  demo program `licd` and the synthetic 10 M-row program (`demo`), design
  system (`design`), actions and key map (`actions`), navigation (`nav`),
  shell with Ghidra's layout/menus/tool bar/bindings, docking and native
  pop-out windows, palette, dialogs, options, start screen (`shell`), and
  the views (`views`). `basilisk` (no arguments, or `gui`) opens it.
- Tests: unit, headless flow tests, screenshot renderer (GPU, opt-in),
  10 M-row benchmark (release, `--ignored`), native-window self-test
  (`tests/native-windows.sh`).
- Docs: `ui-design.md`, spec §8 and §9, `PERF.md` numbers.

In progress / next:
1. Windows target `cargo check`; record the result.
2. Run the native-window self-test on macOS; record the result.
3. Final screenshots into `docs/features/ui-screenshots/`.
4. Full gate; final report below.
