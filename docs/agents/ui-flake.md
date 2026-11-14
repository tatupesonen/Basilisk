# Track ui-flake — status report

Branch `ui-flake`, crate `bk-ui` only.

## Status

- Done: analysis, reproduction, fix, new tests, proof loop, crate checks
  (macOS tests, clippy macOS + Windows cross, fmt).
- Gate: see "Verification".

## The failure

`task::tests::requests_complete_off_thread_and_wake` (`crates/bk-ui/src/task.rs`)
panicked at `assert!(woken.load(Ordering::Relaxed) >= 1)` on a loaded machine.

## Cause

The worker closure built by `DataClient::request` does, in this order:

1. `v = f(src)`
2. `*slot.lock() = Some(v)` — the result is published
3. `waker.lock()` and call the waker
4. `running.fetch_sub(1)`

The test thread spins on `Pending::poll` (which takes the slot's lock) and
asserts on the waker counter as soon as the value is there. Failing
interleaving:

    worker: store result, unlock slot
    test:   poll() sees the value -> wait() returns
    test:   woken.load() == 0     -> assertion fails
    worker: (descheduled until now) call waker -> woken = 1

Nothing orders the waker's `fetch_add` before the test's load; the test
asserted something another thread does "eventually" without waiting for it.

### Is the product ordering wrong?

No. "Store, then wake" is the correct order for a repaint waker: whichever
frame the wake causes is guaranteed to see the stored value (the slot mutex
gives the happens-before). The reverse order would be a real lost wake-up
(the repaint could run before the store and nothing would wake again). The
interleavings of "store", "wake", "UI polls":

- store, wake, poll: normal.
- store, poll, wake: the UI already has the value; the wake costs one extra
  frame. Harmless.
- poll, store, wake: the poll misses, the wake schedules a frame that sees it.

So the flaky assertion is a test bug. Two real, smaller product gaps were
found while checking the remaining interleavings:

- **Waker installed or replaced after the result is stored.** A workspace's
  `DataClient` is created inside a frame (`Tool` opens a program from
  `main_window`), its views issue their first requests in that same frame,
  and `BasiliskApp::frame` calls `install_waker` only afterwards. A request
  that completes in that window reads `None` (or the previous context's
  waker) and wakes nobody. Today this is masked because most views also
  call `request_repaint_after(30–50 ms)` while loading, but nothing in
  `task.rs` guarantees it. Fix: `set_waker` calls the new waker once after
  installing it. Either the worker read the waker after the install (it
  calls the new one) or before it (then its store happened before the
  install, and the install's own wake schedules a frame that sees it).
- **`running` is decremented after the wake**, so the frame the wake causes
  can still see `busy() > 0`. Harmless today (the status-bar spinner
  requests its own repaints) but wrong as a contract. Fix: decrement before
  waking. The waker is also called while holding the waker mutex; it now
  is cloned out and called after the lock is released, so a waker can never
  deadlock against `set_waker`.
- **A panicking task** (ADR-009) kills its worker thread, never decrements
  `running` (spinner stays on, `busy()` leaks) and leaves the `Pending`
  empty forever. Fix (coordinator decision): catch the panic on the worker,
  decrement through a drop guard, deliver an error value to `poll()`.

Verdict: the flaky assertion was a **test bug**; the product's
store-then-wake order is right. The pre-install window and the panic path
were real (if masked) product gaps and are fixed.

## What changed (`crates/bk-ui`)

- `task.rs`
  - Module docs state the wake-up contract (store, then un-count, then
    wake; `set_waker` wakes once; panics become an error value).
  - `set_waker` installs the waker and calls it once.
  - A `Done` drop guard, created when the request is made and moved into
    the work, gives the `running` count back (`Release`; `busy()` loads
    with `Acquire`, so `busy() == 0` implies every result is stored) and
    then calls the waker outside the waker mutex. Because it is a drop
    guard, the count is returned on every path: success, panic, request
    dropped before it ran, work dropped unrun at shutdown. (Note: the
    closure binds `let mut done = done;` explicitly; with edition-2021
    disjoint captures a bare `done.wake = true` captured only the `bool`
    and dropped the guard at once — clippy caught it.)
  - The task runs under `catch_unwind`; a panic is logged with
    `tracing::error!` and the handle receives `T::task_panicked(message)`.
    New public trait `TaskOutput`, implemented for every `SourceResult<T>`;
    `request` and `job` now require `T: TaskOutput`. All callers are in
    `bk-ui` (checked: no other crate uses `DataClient`/`Pending`), and all
    but one already returned `SourceResult`.
  - `job` ends its job through a `JobEnded` drop guard (finished flag set,
    removed from the status bar) — on success, on panic, and when the
    handle is dropped before the job ran (previously that left the job in
    the status bar list for ever).
- `model/source.rs`: new `SourceError::TaskPanicked(String)` (the enum is
  `#[non_exhaustive]`).
- `views/listing/mod.rs`: the "find next unit" request now returns
  `SourceResult<Option<Address>>`; an error is shown as a warning notice.

### Tests

- `requests_complete_off_thread_and_wake`: after the value arrives, waits
  (same 10 s deadline) until the waker has been called **from a worker
  thread** (calls made by `set_waker` on the test thread are not counted,
  so the extra call cannot make the test pass by itself); asserts `busy()`
  was already 0 when the waker ran. Still fails if the waker is never
  called (verified by mutation: it times out with "the waker was not
  called").
- New `a_result_stored_before_the_waker_is_installed_still_wakes` (fails
  without the `set_waker` call — verified by mutation).
- New `a_panicking_request_delivers_an_error_and_frees_its_worker`: one
  panic per worker, then a normal request must still complete; each
  panicked handle yields `TaskPanicked`; count returns to 0; the waker
  fires (fails without `catch_unwind` — verified by mutation).
- New `a_dropped_request_gives_its_count_back`.
- New `a_panicking_job_leaves_the_status_bar`.
- `wait` is now built on a general `wait_until(what, cond)` deadline loop.

## Other tests examined

Searched every test in the crate (`src/**` test modules, `tests/*.rs`,
`tests/common`) for: assertions on something another thread does
eventually, `sleep` used as synchronisation, tight deadlines.

- `task.rs` `apply_bumps_the_revision`: revision is bumped inside the task
  before the result is stored under the slot mutex: correctly ordered.
- `task.rs` `jobs_report_progress_and_cancel`: `jobs().len() == 1` is
  checked right after the synchronous push; `is_finished` and the empty
  list are set before the result is stored: correct. Its 10 s spin limit
  only matters if two adjacent statements are 10 s apart.
- `tests/common::settle`: steps until `busy() == 0` for 7 consecutive
  frames, 30 s deadline. Logic is right (`busy` counts a request from the
  moment it is made until after its result is stored, and each step polls),
  but it read `busy()` with `Relaxed`, which did not formally order the
  result's store before the test's poll; now `Release`/`Acquire`.
- `tests/common::press`, `double_click`: both `settle`; `type_text` does
  not, but every flow that depends on data after typing calls `settle` or
  `press` next (e.g. the palette flow settles before Enter).
- `tests/ui_flows.rs` (21 tests): every assertion on data-derived UI
  follows `settle`/`press`/`double_click`; the remaining immediate
  assertions after `run_steps` are on synchronous layout/prefs state
  (detach/dock, key remap, window menu). No sleeps. Nothing to fix.
- `tests/screenshots.rs`: only runs with `BK_UI_SCREENSHOT_DIR`; shots are
  taken after `settle`/`press` or of synchronous UI (menus, dialogs).
- `tests/perf.rs`: `#[ignore]` benchmark with frame-time budgets; timing
  assertions are inherently load-sensitive, but it is run by hand in
  release, never in the gate. Left as is.
- In-crate unit tests in `demo`, `design`, `actions`, `model`, `nav`,
  `views`, `shell` (palette, overlay, layout, notifications, brand): no
  threads, purely synchronous.
- `shell/selftest.rs` + `tests/native-windows.sh` (manual native-window
  check, not in the gate): every step waits on a condition with a 20 s
  timeout; step 0 waits a fixed 1 s before detaching, but no check depends
  on it, and the script's `sleep`s only pace `osascript` key delivery.
  Left as is; not run (needs a display and accessibility permission).

## Verification

Reproduction (macOS, this Mac, 8 × `perl -e 'alarm N; while(1){}'` busy
loops, test binary run directly with
`<bin> task::tests::requests_complete_off_thread_and_wake --exact`,
script `target/flake-loop.sh`):

| binary | runs | failures | first failure |
|---|---|---|---|
| before | 3000 | 308 | run 10 |
| before (re-check, same session as after) | 1000 | 100 | run 13 |
| after | 5000 | 0 | — |
| after (re-check) | 1000 | 0 | — |
| after, all 7 `task::tests` together | 1000 | 0 | — |

The failing run's message was the reported one:
`panicked at crates/bk-ui/src/task.rs:320:9: assertion failed:
woken.load(Ordering::Relaxed) >= 1`.

Checks:
- macOS: `cargo test -p bk-ui --all-features` — 61 unit + 21 flow + 1
  screenshot (skips without dir) pass, perf ignored.
- macOS: `cargo clippy -p bk-ui --all-targets --all-features -- -D warnings`
  clean; `cargo fmt --all --check` clean.
- Windows: `cargo clippy -p bk-ui --all-targets --all-features --target
  x86_64-pc-windows-msvc -- -D warnings` clean (cross-check only; tests not
  run on Windows or Linux — those rest on CI).
- Gate: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` printed `0`; last line of `gate.log`: `tests: 1823 passed, 0 failed`.

## Follow-ups

- `catch_unwind` relies on `panic = "unwind"` (the workspace default; no
  profile sets `abort`). If a profile ever switches to abort, a panicking
  task takes the process down instead.
- The default panic hook still prints the panic to stderr in addition to
  the `tracing` error; a shell-wide panic hook could route it to the log.
