//! Builds the vendored binutils 2.41 subset (`vendor/binutils-2.41`) and the
//! C shim into one static library.
//!
//! The approach — compiling the sources named in `sources.list` with the
//! `cc` crate against a prepared `config/config.h`, instead of running
//! binutils' `configure` and `make` — and the evidence for it are in
//! `docs/features/gnu-disasm.md`.
//!
//! On Windows nothing is compiled: the crate then builds its stub, which
//! reports that GNU disassembly is unavailable (recorded as a gap in the
//! feature document).

#![expect(
    clippy::print_stderr,
    reason = "a build script reports failures to the developer on stderr"
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The `@name@` placeholders of `bfd/bfd-in2.h` that binutils' `configure`
/// fills in, and the values of a 64-bit BFD with all targets and without
/// plugin (dlopen) support.
const BFD_H_SUBSTITUTIONS: [(&str, &str); 5] = [
    ("@supports_plugins@", "0"),
    ("@wordsize@", "64"),
    ("@bfd_default_target_size@", "64"),
    ("@bfd_file_ptr@", "int64_t"),
    ("@bfd_ufile_ptr@", "uint64_t"),
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bk-binutils-sys: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let crate_dir = PathBuf::from(var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(var("OUT_DIR")?);
    let vendor = crate_dir.join("../../vendor/binutils-2.41");
    let shim = crate_dir.join("shim");
    let config = crate_dir.join("config");
    let list = crate_dir.join("sources.list");

    println!("cargo:rustc-check-cfg=cfg(bk_binutils_built)");
    println!("cargo:rustc-check-cfg=cfg(fuzzing)");
    for path in [&crate_dir.join("build.rs"), &list, &shim, &config, &vendor] {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // No C is built; `src/stub.rs` reports the feature as unavailable.
        return Ok(());
    }

    if !vendor.join("MANIFEST").is_file() {
        return Err(format!(
            "{} is missing; it is produced by scripts/vendor-binutils.sh",
            vendor.display()
        ));
    }

    let generated = out_dir.join("include");
    fs::create_dir_all(&generated).map_err(|e| format!("{}: {e}", generated.display()))?;
    write_bfd_h(&vendor.join("bfd/bfd-in2.h"), &generated.join("bfd.h"))?;

    let mut build = cc::Build::new();
    build
        .warnings(false)
        .extra_warnings(false)
        // First, so that the vendored sources get the shim's <assert.h>.
        .include(shim.join("include"))
        .include(&config)
        .include(&generated)
        .include(vendor.join("include"))
        .include(vendor.join("bfd"))
        .include(vendor.join("opcodes"))
        .include(&shim)
        .define("HAVE_CONFIG_H", None)
        // opcodes/disassemble.c: every disassembler (--enable-targets=all).
        .define("ARCH_all", None)
        // abort() and exit() inside binutils end the shim call, not the process.
        .define("abort", "bk_gdis_abort")
        .define("exit", "bk_gdis_exit");
    for unit in compilation_units(&list)? {
        let path = vendor.join(&unit);
        if !path.is_file() {
            return Err(format!(
                "{unit} is named in sources.list but not vendored; run scripts/vendor-binutils.sh"
            ));
        }
        build.file(path);
    }
    build
        .file(shim.join("bk_gdis.c"))
        .file(shim.join("bfd_nofile.c"));
    build
        .try_compile("bk_binutils")
        .map_err(|e| e.to_string())?;

    println!("cargo:rustc-cfg=bk_binutils_built");
    Ok(())
}

fn var(name: &str) -> Result<String, String> {
    env::var(name).map_err(|e| format!("{name}: {e}"))
}

/// The paths in `sources.list`, without comments and blank lines.
fn compilation_units(list: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(list).map_err(|e| format!("{}: {e}", list.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

/// Generates `bfd.h` from `bfd-in2.h` the way binutils' `configure` does:
/// by filling in its placeholders.
fn write_bfd_h(template: &Path, dest: &Path) -> Result<(), String> {
    let mut text =
        fs::read_to_string(template).map_err(|e| format!("{}: {e}", template.display()))?;
    for (placeholder, value) in BFD_H_SUBSTITUTIONS {
        if !text.contains(placeholder) {
            return Err(format!("{} has no {placeholder}", template.display()));
        }
        text = text.replace(placeholder, value);
    }
    if let Some(left) = find_placeholder(&text) {
        return Err(format!(
            "{}: unhandled placeholder {left}",
            template.display()
        ));
    }
    // Leave an up-to-date file alone so its timestamp does not change.
    if fs::read_to_string(dest).is_ok_and(|old| old == text) {
        return Ok(());
    }
    fs::write(dest, text).map_err(|e| format!("{}: {e}", dest.display()))
}

/// Finds an `@identifier@` that `configure` would have substituted.
fn find_placeholder(text: &str) -> Option<&str> {
    let mut rest = text;
    while let Some(start) = rest.find('@') {
        let after = rest.get(start + 1..)?;
        let ident_len = after
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if ident_len > 0 && after.as_bytes().get(ident_len) == Some(&b'@') {
            return rest.get(start..start + ident_len + 2);
        }
        rest = after;
    }
    None
}
