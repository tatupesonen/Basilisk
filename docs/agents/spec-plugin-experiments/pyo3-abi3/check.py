"""Checks for the bkdemo experiment. Run: python3.X check.py <dir containing bkdemo.so>"""
import sys
import threading
import time

sys.path.insert(0, sys.argv[1])
import bkdemo  # noqa: E402

print("python", sys.version.split()[0], "module", bkdemo.__file__.rsplit("/", 1)[-1])


def timed_pair(fn, ms):
    """Runs fn(ms) in two Python threads at once; returns wall time in ms."""
    t0 = time.perf_counter()
    threads = [threading.Thread(target=fn, args=(ms,)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return (time.perf_counter() - t0) * 1000


holding = timed_pair(bkdemo.busy_holding, 300)
detached = timed_pair(bkdemo.busy_detached, 300)
print(f"two threads x 300 ms: GIL held {holding:.0f} ms, GIL released {detached:.0f} ms")

# Rust threads calling back into Python.
seen = []
lock = threading.Lock()


def cb(i):
    with lock:
        seen.append(threading.get_ident())
    return i * i


t0 = time.perf_counter()
print("parallel_callback:", bkdemo.parallel_callback(cb, 8),
      f"{(time.perf_counter() - t0) * 1000:.0f} ms,", len(set(seen)), "distinct OS threads")

# Python exception inside a callback reaching Rust as a value, then propagating.
print("call_and_catch:", bkdemo.call_and_catch(lambda: 1 / 0))
try:
    bkdemo.parallel_callback(lambda i: 1 // (i - 3), 5)
except ZeroDivisionError as e:
    print("callback exception propagated:", type(e).__name__)

# Rust error -> Python exception hierarchy.
try:
    bkdemo.read_byte(0x401000)
except bkdemo.NoSuchAddress as e:
    print("NoSuchAddress:", e, "| is BasiliskError:", isinstance(e, bkdemo.BasiliskError))

# Cancellation from another thread while Rust runs without the GIL.
m = bkdemo.Monitor()
threading.Timer(0.15, m.cancel).start()
try:
    bkdemo.long_task(m, 1000)
except bkdemo.BasiliskError as e:
    print("long_task:", e, "| progress seen from Python:", m.progress)

# Transactions as context managers.
p = bkdemo.Program()
with p.transaction("Set comment") as tx:
    tx.set_comment(0x10, "kept")
try:
    with p.transaction("Failing script") as tx:
        tx.set_comment(0x20, "dropped")
        raise RuntimeError("script failed")
except RuntimeError:
    pass
print("comments:", p.comments, "| undo stack:", p.undo_stack)
