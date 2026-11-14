//! `basilisk disasm`: a linear sweep over raw bytes with p-code, written in
//! `pcodedump`'s record format byte for byte (`features/sleigh-pcode.md`
//! 4.7, ADR-023) or as a human listing.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::dump::{self, SweepCounts};
use bk_sleigh::{Decoder, Language};

/// The help text.
pub(crate) const USAGE: &str = "\
USAGE: basilisk disasm --language <id> [options] [--hex HEXBYTES | <file> | -]

Decodes the bytes as a linear sweep from the base address and prints every
instruction with its p-code.

OPTIONS:
  --language <id>        language id, for example x86:LE:64:default
  --root <dir>           Ghidra tree or reference directory with the language
                         files (default: $BASILISK_GHIDRA_DIR)
  --sla-dir <dir>        directory mirroring the root's layout that holds the
                         compiled .sla files (when the root has none)
  --base <addr>          address of the first byte (default 0; 0x… for hex)
  --context NAME=VALUE   set a context variable over the whole code space
                         (repeatable)
  --hex HEXBYTES         decode these bytes instead of a file
  --format pcodedump|text
                         pcodedump's record format (default) or a listing
  --no-pcode             leave out the p-code
  --quiet                decode and lift, print only the H and T records
  --timing               print load and decode times on standard error
  -h, --help             print this help

Reads standard input when neither a file nor --hex is given, or with -.
Exit status: 0 when the sweep ran, 1 when the language cannot be loaded,
2 for a bad command line.
";

/// The output form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Pcodedump,
    Text,
}

/// The parsed command line.
#[derive(Debug)]
struct Options {
    language: String,
    root: Option<PathBuf>,
    sla_dir: Option<PathBuf>,
    base: u64,
    context: Vec<(String, u32)>,
    hex: Option<String>,
    file: Option<PathBuf>,
    format: Format,
    pcode: bool,
    quiet: bool,
    timing: bool,
}

/// What the command line asked for.
enum Parsed {
    Run(Box<Options>),
    Help,
}

/// A number as C's `strtoull(text, 0)` reads it: `0x` hex, leading `0`
/// octal, decimal otherwise.
fn number(text: &str, what: &str) -> Result<u64, String> {
    let bad = || format!("bad {what}: {text}");
    if text.is_empty() {
        return Err(format!("missing {what}"));
    }
    let (digits, radix) =
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (hex, 16)
        } else if let Some(octal) = text.strip_prefix('0').filter(|rest| !rest.is_empty()) {
            (octal, 8)
        } else {
            (text, 10)
        };
    u64::from_str_radix(digits, radix).map_err(|_cause| bad())
}

fn parse(args: &[OsString]) -> Result<Parsed, String> {
    let mut language = None;
    let mut opt = Options {
        language: String::new(),
        root: None,
        sla_dir: None,
        base: 0,
        context: Vec::new(),
        hex: None,
        file: None,
        format: Format::Pcodedump,
        pcode: true,
        quiet: false,
        timing: false,
    };
    let mut it = args.iter();
    let text = |arg: Option<&OsString>, what: &str| -> Result<String, String> {
        arg.and_then(|a| a.to_str())
            .map(str::to_owned)
            .ok_or_else(|| format!("{what} needs a value"))
    };
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(Parsed::Help),
            Some("--language") => language = Some(text(it.next(), "--language")?),
            Some("--root") => {
                opt.root = Some(PathBuf::from(it.next().ok_or("--root needs a directory")?));
            }
            Some("--sla-dir") => {
                opt.sla_dir = Some(PathBuf::from(
                    it.next().ok_or("--sla-dir needs a directory")?,
                ));
            }
            Some("--base") => opt.base = number(&text(it.next(), "--base")?, "base address")?,
            Some("--context") => {
                let pair = text(it.next(), "--context")?;
                let (name, value) = pair
                    .split_once('=')
                    .filter(|(n, _)| !n.is_empty())
                    .ok_or("--context needs NAME=VALUE")?;
                let value = number(value, "context value")?;
                let value =
                    u32::try_from(value).map_err(|_cause| format!("bad context value: {value}"))?;
                opt.context.push((name.to_owned(), value));
            }
            Some("--hex") => opt.hex = Some(text(it.next(), "--hex")?),
            Some("--format") => {
                opt.format = match text(it.next(), "--format")?.as_str() {
                    "pcodedump" => Format::Pcodedump,
                    "text" => Format::Text,
                    other => return Err(format!("unknown format {other}")),
                };
            }
            Some("--no-pcode") => opt.pcode = false,
            Some("--quiet") => opt.quiet = true,
            Some("--timing") => opt.timing = true,
            Some("-") => opt.file = None,
            Some(flag) if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => {
                if opt.file.is_some() {
                    return Err("more than one input file".to_owned());
                }
                opt.file = Some(PathBuf::from(arg));
            }
        }
    }
    opt.language = language.ok_or("--language is required")?;
    if opt.hex.is_some() && opt.file.is_some() {
        return Err("give either --hex or a file, not both".to_owned());
    }
    Ok(Parsed::Run(Box::new(opt)))
}

/// `pcodedump`'s hex reading: white space and `_` ignored.
fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | '_'))
        .map(|c| {
            c.to_digit(16)
                .map(|d| d as u8)
                .ok_or_else(|| "bad hex digit in --hex argument".to_owned())
        })
        .collect::<Result<_, _>>()?;
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits in --hex argument".to_owned());
    }
    Ok(digits
        .chunks(2)
        .map(|p| p.iter().fold(0u8, |acc, d| (acc << 4) | d))
        .collect())
}

/// The registry over `root`: a Ghidra tree, or a directory with Ghidra's
/// layout but without module manifests (the reference directory).
fn registry(root: &Path, sla_dir: Option<&Path>) -> Result<LanguageRegistry, String> {
    let with_overlay = |b: bk_lang::RegistryBuilder| match sla_dir {
        Some(dir) => b.sla_overlay(dir),
        None => b,
    };
    let tree = with_overlay(
        LanguageRegistry::builder()
            .include_hidden(true)
            .ghidra_root(root),
    )
    .build();
    if let Ok(r) = tree
        && !r.languages().is_empty()
    {
        return Ok(r);
    }
    let processors = root.join("Ghidra").join("Processors");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&processors)
        .map_err(|e| format!("{}: {e}", processors.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    let mut builder = with_overlay(LanguageRegistry::builder().include_hidden(true));
    for dir in dirs {
        builder = builder.module(dir);
    }
    builder.build().map_err(|e| e.to_string())
}

fn load(opt: &Options) -> Result<Arc<Language>, String> {
    let root = opt
        .root
        .clone()
        .or_else(bk_lang::spec_root_from_env)
        .ok_or("no language root: give --root or set BASILISK_GHIDRA_DIR")?;
    let registry = registry(&root, opt.sla_dir.as_deref())?;
    let id = LanguageId::new(&opt.language).map_err(|e| e.to_string())?;
    let lang =
        Language::load(&registry, &id).map_err(|e| format!("cannot load {}: {e}", opt.language))?;
    Ok(Arc::new(lang))
}

fn input(opt: &Options) -> Result<Vec<u8>, String> {
    if let Some(hex) = &opt.hex {
        return hex_bytes(hex);
    }
    if let Some(path) = &opt.file {
        return std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
    }
    let mut data = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut data)
        .map_err(|e| format!("standard input: {e}"))?;
    Ok(data)
}

/// Rewrites `pcodedump` records as a listing.
fn listing(records: &str, out: &mut String) {
    for line in records.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["I", addr, _, _, bytes, mnemonic, body, ..] => {
                let spaced: Vec<&str> = (0..bytes.len() / 2)
                    .filter_map(|i| bytes.get(2 * i..2 * i + 2))
                    .collect();
                let _ = writeln!(out, "{addr}  {:<24} {mnemonic} {body}", spaced.join(" "));
            }
            ["P", opcode, output, inputs @ ..] => {
                let inputs = inputs.join(", ");
                if *output == "-" {
                    let _ = writeln!(out, "    {opcode} {inputs}");
                } else {
                    let _ = writeln!(out, "    {output} = {opcode} {inputs}");
                }
            }
            ["U", kind, message @ ..] => {
                let _ = writeln!(out, "    !! {kind}: {}", message.join(" "));
            }
            ["E", addr, _, bytes, kind, message, ..] => {
                let _ = writeln!(out, "{addr}  {bytes:<24} ?? {kind}: {message}");
            }
            _ => {}
        }
    }
}

/// Runs `basilisk disasm` with the arguments after the subcommand.
pub(crate) fn run(args: &[OsString]) -> ExitCode {
    let opt = match parse(args) {
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Run(opt)) => opt,
        Err(e) => {
            eprintln!("basilisk disasm: {e}");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let data = match input(&opt) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("basilisk disasm: {e}");
            return ExitCode::from(2);
        }
    };
    let load_start = Instant::now();
    let lang = match load(&opt) {
        Ok(lang) => lang,
        Err(e) => {
            eprintln!("basilisk disasm: {e}");
            return ExitCode::from(1);
        }
    };
    let mut context = lang.initial_context();
    for (name, value) in &opt.context {
        if !lang.set_context_everywhere(&mut context, name, *value) {
            eprintln!(
                "basilisk disasm: cannot load {}: unknown context variable {name}",
                opt.language
            );
            return ExitCode::from(1);
        }
    }
    let load_seconds = load_start.elapsed().as_secs_f64();
    let space = lang
        .spaces()
        .space(lang.default_space())
        .map_or("ram", bk_core::Space::name)
        .to_owned();
    let mut records = String::new();
    dump::write_header(&mut records, &opt.language, &space, opt.base, data.len());
    let mut decoder = Decoder::new(Arc::clone(&lang));
    let decode_start = Instant::now();
    let counts: SweepCounts = dump::sweep(
        &mut decoder,
        &mut context,
        opt.base,
        &data,
        opt.quiet,
        &mut records,
        &mut (),
    );
    let decode_seconds = decode_start.elapsed().as_secs_f64();
    dump::write_trailer(&mut records, &counts);
    if !opt.pcode {
        records = records
            .lines()
            .filter(|l| !l.starts_with('P') && !l.starts_with('U'))
            .fold(String::new(), |mut s, l| {
                s.push_str(l);
                s.push('\n');
                s
            });
    }
    let text = match opt.format {
        Format::Pcodedump => records,
        Format::Text => {
            let mut out = String::new();
            listing(&records, &mut out);
            out
        }
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        eprintln!("basilisk disasm: writing the output: {e}");
        return ExitCode::FAILURE;
    }
    if opt.timing {
        eprintln!(
            "timing\tload_seconds={load_seconds:.6}\tdecode_seconds={decode_seconds:.6}\tinstructions={}\tops={}\terrors={}\tbytes={}",
            counts.instructions,
            counts.ops,
            counts.errors,
            data.len()
        );
    }
    ExitCode::SUCCESS
}
