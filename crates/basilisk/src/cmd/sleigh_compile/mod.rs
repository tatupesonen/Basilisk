//! `basilisk sleigh compile`: Ghidra's SLEIGH compiler command
//! (`features/sleigh-compiler-back.md` 4.6). Messages go to standard error
//! in Ghidra's form (`FILE:LINE - ERROR TEXT`, `WARN  TEXT`,
//! `No output produced`); exit status 0 on success, 2 on failure, 1 for a
//! bad command line; with `-a` every specification is compiled and the
//! status is the number of failures negated modulo 256, as Java's does.

mod args;

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bk_sleigh_compiler::{Diagnostic, compile};
use bk_sleigh_syntax::{FsLoader, Parsed};

pub(crate) use args::{Job, has_extension};

/// The help text.
pub(crate) const USAGE: &str = "\
USAGE: basilisk sleigh compile [options...] <infile.slaspec> [<outfile.sla>]
       basilisk sleigh compile [options...] -a [<directory>]

Compiles a SLEIGH specification into a .sla file, as Ghidra's compiler does.
<infile> without .slaspec gets it appended; without <outfile> the output is
<infile> with .sla in place of .slaspec. With -a, every .slaspec under the
directory (default .) is compiled beside itself.

OPTIONS:
   -a [dir]          compile every .slaspec under the directory
   -x                accepted and ignored (parser debugging in Ghidra)
   -y                write the .sla in the XML debug format
   -u                print warnings for unnecessary pcode instructions
   -l                report pattern conflicts
   -n                print warnings for all NOP constructors
   -t                print warnings for dead temporaries
   -e                enforce use of 'local' keyword for temporaries
   -c                print warnings for all constructors with colliding operands
   -f                print warnings for unused token fields
   -s                treat register names as case sensitive
   -DNAME=VALUE      defines a preprocessor macro NAME with value VALUE
   -dMODULE          defines MODULE as that module's directory under
                     $BASILISK_GHIDRA_DIR
   -i <file>         read options from a file, one per line (# comments)

Exit status: 0 on success, 2 on failure, 1 for a bad command line.
";

/// The file and line Ghidra prints in front of an error: the diagnostic's
/// own location, or the end of the main file (where Ghidra's lexer is when
/// the late passes report).
fn error_location(d: &Diagnostic, parsed: &Parsed) -> (String, u32) {
    if let Some((file, line)) = d.location(&parsed.sources) {
        return (file.to_owned(), line);
    }
    parsed
        .sources
        .files()
        .next()
        .map_or((String::new(), 0), |f| {
            (f.name().to_owned(), f.line_count())
        })
}

/// Writes `bytes` to `output` through a temporary file in the same
/// directory, so a failure leaves no partial file.
fn write_atomically(output: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut temp = tempfile::NamedTempFile::new_in(&dir)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(output).map_err(|e| e.error)?;
    Ok(())
}

/// Compiles one specification; prints its messages. Returns Ghidra's
/// status (0 or 2).
fn compile_one(input: &Path, output: &Path, a: &args::Args) -> u8 {
    if std::fs::File::open(input).is_err() {
        eprintln!("Unable to open specfile: {}", input.display());
        return 2;
    }
    let (parsed, compiled) = compile(input, &a.defines, a.options, &mut FsLoader);
    for d in &parsed.diagnostics {
        let (file, line) = parsed
            .sources
            .locate(d.span.start)
            .and_then(|l| Some((parsed.sources.file(l.file)?.name().to_owned(), l.line)))
            .unwrap_or_default();
        if d.is_error() {
            eprintln!("{file}:{line} - ERROR {}", d.message);
        } else {
            eprintln!("WARN  {}", d.message);
        }
    }
    for d in &compiled.diagnostics {
        if d.is_error() {
            let (file, line) = error_location(d, &parsed);
            eprintln!("{file}:{line} - ERROR {}", d.ghidra_text(&parsed.sources));
        } else {
            eprintln!("WARN  {}", d.ghidra_text(&parsed.sources));
        }
    }
    let Some(sla) = compiled.sla else {
        eprintln!("No output produced");
        return 2;
    };
    let bytes = if a.xml {
        sla.encode_xml().map(String::into_bytes)
    } else {
        sla.write()
    };
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Unrecoverable error: {e}");
            return 2;
        }
    };
    if let Err(e) = write_atomically(output, &bytes) {
        eprintln!(
            "Unrecoverable error: Unable to open output file: {} ({e})",
            output.display()
        );
        return 2;
    }
    0
}

/// Every `.slaspec` under `dir`, in sorted order, not following links to
/// directories.
fn find_specs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let path = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => find_specs(&path, out),
            Ok(_) if has_extension(&path, ".slaspec") => out.push(path),
            _ => {}
        }
    }
}

/// `-a`: compile every specification, continue after failures.
fn compile_all(dir: &Path, a: &args::Args) -> u8 {
    let mut specs = Vec::new();
    find_specs(dir, &mut specs);
    println!(
        "Compiling {} slaspec files in {}",
        specs.len(),
        dir.display()
    );
    let mut failures = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        println!(
            "Compiling ({} of {}) {}",
            i + 1,
            specs.len(),
            spec.display()
        );
        let output = spec.with_extension("sla");
        if compile_one(spec, &output, a) != 0 {
            failures.push(spec.clone());
        }
    }
    println!(
        "{} languages successfully compiled",
        specs.len() - failures.len()
    );
    if !failures.is_empty() {
        for f in &failures {
            println!("{} failed to compile", f.display());
        }
        println!("{} languages total failed to compile", failures.len());
    }
    (failures.len() % 256).wrapping_neg() as u8
}

/// Runs `basilisk sleigh compile` with the arguments after `compile`.
pub(crate) fn run(rest: &[OsString]) -> ExitCode {
    if rest.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let root = std::env::var_os("BASILISK_GHIDRA_DIR").map(PathBuf::from);
    let a = match args::parse(rest, root.as_deref()) {
        Ok(a) => a,
        Err(args::Refused(message)) => {
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };
    let status = match &a.job {
        Job::One { input, output } => compile_one(input, output, &a),
        Job::All(dir) => compile_all(dir, &a),
    };
    ExitCode::from(status)
}
