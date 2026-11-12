# Performance

Budgets, benchmark commands and measured numbers (ADR-012). Every hot path
lands with a benchmark; record the machine, the command and the result
here, newest first under the crate's heading. Sizes use SI prefixes.

## Budgets

| Area | Budget | Measured against |
|---|---|---|
| SLEIGH language load (`.sla` → ready to decode) | at least as fast as Ghidra's C++ loader for the same file; x86-64 in under 100 ms | reference `sleigh`/`decomp` |
| Instruction decode + p-code lift | at least as fast as Ghidra's C++ `Sleigh::oneInstruction`; no heap allocation per instruction in steady state | reference `decomp` |
| SLEIGH compile (`.slaspec` → `.sla`) | at least as fast as Ghidra's C++ `sleigh` | reference `sleigh` |
| Decompile one function | at least as fast as Ghidra's `decomp` on the same function | data tests, reference `decomp` |
| Whole-program analysis | scales with cores; memory bounded by working set | Ghidra headless (M5) |
| Program store (ADR-003) | bulk insert of 10 million instructions, address-ordered range scans, rollback — figures set by the M4 spike | — |
| UI | no frame blocked by storage or analysis | M7 |

## Measurements

None yet.

### bk-ui

**Scrolling a ten-million-row listing** (budget: 60 frames per second,
16.7 ms a frame). 2026-11-12, Apple M1 Pro (8 cores, shared with other
agents' builds), release build. Command:

    CARGO_BUILD_JOBS=2 cargo test -p bk-ui --release --test perf -- --ignored --nocapture

The synthetic program (`demo::synthetic`, 10,000,026 rows, 94,341
functions) is shown in the full interface at 1440×900 points; each frame
is measured from input through layout to tessellated triangles (the UI
thread's whole share; GPU submission not included). The test asserts the
listing moved (different functions on screen) and that each jump arrived.

| Scenario | Frames | Mean | p95 | Max |
|---|---|---|---|---|
| Wheel scrolling, 60 px (3 rows) a frame | 600 | 0.63 ms | 1.66 ms | 12.26 ms |
| Go to 200 addresses spread over the 10 M rows | 400 | 0.44 ms | 1.40 ms | 11.00 ms |
| Idle redraw of a full screen | 200 | 0.44 ms | 1.63 ms | 2.97 ms |

Why it holds: rows are uniform, so the scroller keeps its position as a
`u64` row plus a pixel offset (no `f32` precision loss at 2·10⁸ px) and
jumping to any row is O(1); only visible rows are touched; rows arrive in
64-row pages from worker threads (the frame draws placeholders, never
waits); each row's text is laid out once into a cached galley and only
re-painted afterwards. The worst frames (≈ 11–12 ms) are the frames in
which several pages arrive and are laid out at once.
