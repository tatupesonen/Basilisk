# Track ui-flake — status report

Branch `ui-flake`, crate `bk-ui` only.

## Status

- Done: analysis (below).
- In progress: reproduction under load, then the fix.
- Next: fix, proof loop, crate checks, gate.

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

## Other tests examined

(filled in as the work proceeds)
