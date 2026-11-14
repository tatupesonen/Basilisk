// maturin passes these flags itself; a plain `cargo build` of an extension
// module needs them (macOS: `-undefined dynamic_lookup`).
fn main() {
    pyo3_build_config::add_extension_module_link_args();
}
