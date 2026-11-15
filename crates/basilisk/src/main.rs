//! basilisk command-line entry point. With no arguments, or with `gui`, it
//! opens the desktop interface (`bk-ui`); further subcommands arrive with
//! the milestones in `docs/PLAN.md`.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the binary's job is to print"
)]

use std::process::ExitCode;

mod cmd {
    pub(crate) mod sleigh_compile;
    pub(crate) mod sleigh_decode;
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("gui") => match bk_ui::run_native() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("basilisk: cannot open the interface: {e}");
                ExitCode::FAILURE
            }
        },
        Some("disasm") => {
            // The name is kept for the flow-following disassembler (M5).
            eprintln!(
                "basilisk: disasm is not available yet; for a linear decode of raw bytes use `basilisk sleigh decode`"
            );
            ExitCode::from(2)
        }
        Some("sleigh") => {
            let rest: Vec<std::ffi::OsString> = std::env::args_os().skip(3).collect();
            if args.get(1).map(String::as_str) == Some("compile") {
                cmd::sleigh_compile::run(&rest)
            } else if args.get(1).map(String::as_str) == Some("decode") {
                cmd::sleigh_decode::run(&rest)
            } else {
                eprintln!("basilisk sleigh: expected a subcommand: compile or decode");
                eprint!("{}", cmd::sleigh_compile::USAGE);
                ExitCode::from(2)
            }
        }
        Some("--version" | "-V" | "version") => {
            println!("basilisk {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!(
                "basilisk: unknown command {other:?}; run without arguments for the interface"
            );
            ExitCode::from(2)
        }
    }
}
