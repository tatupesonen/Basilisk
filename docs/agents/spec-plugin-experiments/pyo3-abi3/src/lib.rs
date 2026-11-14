//! Throwaway experiment for `docs/features/plugin-api.md`: an abi3 extension
//! module that checks the claims the plugin design rests on.
//!
//! * one build loads in several CPython minor versions (abi3);
//! * long Rust work with the GIL released lets other Python threads run;
//! * Rust worker threads can call a Python callable (an analyzer callback);
//! * cancellation and progress cross the boundary without the GIL;
//! * Rust errors become a Python exception class, Python exceptions raised
//!   in a callback come back to Rust as values;
//! * a transaction is a context manager that commits or rolls back;
//! * a handle type holding an `Arc` is a `frozen` pyclass, `Send + Sync`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(bkdemo, BasiliskError, PyException, "Base of Basilisk's exceptions.");
create_exception!(bkdemo, NoSuchAddress, BasiliskError, "The address is not in memory.");

/// Spins for about `ms` milliseconds of CPU time.
fn spin(ms: u64) -> u64 {
    let start = Instant::now();
    let mut x: u64 = 0;
    while start.elapsed().as_millis() < u128::from(ms) {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    x
}

/// Long native work that keeps the GIL.
#[pyfunction]
fn busy_holding(ms: u64) -> u64 {
    spin(ms)
}

/// Long native work with the GIL released.
#[pyfunction]
fn busy_detached(py: Python<'_>, ms: u64) -> u64 {
    py.detach(|| spin(ms))
}

/// Runs `n` Rust threads, each calling `callback(i)` from Python, and
/// returns the results in index order. The calling thread releases the GIL
/// while it waits, as a parallel analysis pass would.
#[pyfunction]
fn parallel_callback(py: Python<'_>, callback: Py<PyAny>, n: usize) -> PyResult<Vec<i64>> {
    let callback = Arc::new(callback);
    let results: Vec<PyResult<i64>> = py.detach(|| {
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let cb = Arc::clone(&callback);
                    s.spawn(move || {
                        spin(20); // native work outside the GIL
                        Python::attach(|py| cb.call1(py, (i,))?.extract::<i64>(py))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| Err(BasiliskError::new_err("thread panicked"))))
                .collect()
        })
    });
    results.into_iter().collect()
}

/// A task monitor: Python sets `cancel()`, Rust reads it without the GIL.
#[pyclass(frozen)]
struct Monitor {
    cancelled: Arc<AtomicBool>,
    progress: Arc<AtomicU64>,
}

#[pymethods]
impl Monitor {
    #[new]
    fn new() -> Self {
        Self { cancelled: Arc::new(AtomicBool::new(false)), progress: Arc::new(AtomicU64::new(0)) }
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    #[getter]
    fn progress(&self) -> u64 {
        self.progress.load(Ordering::Relaxed)
    }
}

/// Works in steps of 10 ms until `steps` or cancellation; raises
/// `CancelledError`-like `BasiliskError` when cancelled.
#[pyfunction]
fn long_task(py: Python<'_>, monitor: &Monitor, steps: u64) -> PyResult<u64> {
    let cancelled = Arc::clone(&monitor.cancelled);
    let progress = Arc::clone(&monitor.progress);
    let done = py.detach(move || {
        for i in 0..steps {
            if cancelled.load(Ordering::Relaxed) {
                return Err(i);
            }
            spin(10);
            progress.store(i + 1, Ordering::Relaxed);
        }
        Ok(steps)
    });
    done.map_err(|i| BasiliskError::new_err(format!("cancelled after {i} steps")))
}

/// A Rust error, as the binding layer converts it.
#[pyfunction]
fn read_byte(address: u64) -> PyResult<u8> {
    if address < 0x1000 {
        Ok(0x90)
    } else {
        Err(NoSuchAddress::new_err(format!("address {address:08x} is not in the program's memory")))
    }
}

/// Calls `callback()`; if it raises, returns the exception's type name and
/// message instead of propagating, to show Rust receives Python errors as values.
#[pyfunction]
fn call_and_catch(py: Python<'_>, callback: Py<PyAny>) -> PyResult<String> {
    match callback.call0(py) {
        Ok(v) => Ok(format!("ok: {}", v.bind(py).repr()?)),
        Err(e) => Ok(format!("caught {}: {}", e.get_type(py).name()?, e.value(py))),
    }
}

/// The program as a handle: an `Arc` around shared state, no lifetimes.
struct ProgramData {
    comments: Mutex<Vec<(u64, String)>>,
    undo: Mutex<Vec<String>>,
}

#[pyclass(frozen)]
struct Program {
    inner: Arc<ProgramData>,
}

#[pymethods]
impl Program {
    #[new]
    fn new() -> Self {
        Self { inner: Arc::new(ProgramData { comments: Mutex::new(Vec::new()), undo: Mutex::new(Vec::new()) }) }
    }
    fn transaction(&self, name: String) -> Transaction {
        Transaction { program: Arc::clone(&self.inner), name, pending: Mutex::new(Vec::new()) }
    }
    #[getter]
    fn comments(&self) -> Vec<(u64, String)> {
        self.inner.comments.lock().map(|c| c.clone()).unwrap_or_default()
    }
    #[getter]
    fn undo_stack(&self) -> Vec<String> {
        self.inner.undo.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

/// `with program.transaction("name") as tx:` — commits on normal exit,
/// rolls back when the block raises.
#[pyclass(frozen)]
struct Transaction {
    program: Arc<ProgramData>,
    name: String,
    pending: Mutex<Vec<(u64, String)>>,
}

#[pymethods]
impl Transaction {
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
    fn set_comment(&self, address: u64, text: String) {
        if let Ok(mut p) = self.pending.lock() {
            p.push((address, text));
        }
    }
    fn __exit__(
        &self,
        exc_type: Option<Bound<'_, PyAny>>,
        _exc: Option<Bound<'_, PyAny>>,
        _tb: Option<Bound<'_, PyAny>>,
    ) -> bool {
        let pending = self.pending.lock().map(|mut p| std::mem::take(&mut *p)).unwrap_or_default();
        if exc_type.is_none() {
            if let Ok(mut c) = self.program.comments.lock() {
                c.extend(pending);
            }
            if let Ok(mut u) = self.program.undo.lock() {
                u.push(self.name.clone());
            }
        }
        false // never swallow the exception
    }
}

fn _assert_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<Program>();
    check::<Transaction>();
    check::<Monitor>();
}

#[pymodule]
fn bkdemo(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(busy_holding, m)?)?;
    m.add_function(wrap_pyfunction!(busy_detached, m)?)?;
    m.add_function(wrap_pyfunction!(parallel_callback, m)?)?;
    m.add_function(wrap_pyfunction!(long_task, m)?)?;
    m.add_function(wrap_pyfunction!(read_byte, m)?)?;
    m.add_function(wrap_pyfunction!(call_and_catch, m)?)?;
    m.add_class::<Monitor>()?;
    m.add_class::<Program>()?;
    m.add_class::<Transaction>()?;
    m.add("BasiliskError", m.py().get_type::<BasiliskError>())?;
    m.add("NoSuchAddress", m.py().get_type::<NoSuchAddress>())?;
    Ok(())
}
