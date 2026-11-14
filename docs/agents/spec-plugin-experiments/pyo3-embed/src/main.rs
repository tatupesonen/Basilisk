//! Throwaway experiment: a binary that embeds CPython with `auto-initialize`.
//! It prints the interpreter version if Python is wanted, and runs without
//! touching Python otherwise. The question is whether it can start at all
//! when libpython is absent.
use pyo3::prelude::*;

fn main() {
    if std::env::args().any(|a| a == "--python") {
        Python::attach(|py| {
            let v: String = py.import("sys").and_then(|s| s.getattr("version")).and_then(|v| v.extract()).unwrap_or_default();
            println!("embedded python {v}");
        });
    } else {
        println!("running without python");
    }
}
