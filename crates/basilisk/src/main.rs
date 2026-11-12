//! basilisk command-line entry point. With no arguments, or with `gui`, it
//! opens the desktop interface (`bk-ui`); further subcommands arrive with
//! the milestones in `docs/PLAN.md`.

#![expect(clippy::print_stdout, clippy::print_stderr, reason = "the binary's job is to print")]

use std::process::ExitCode;

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
        Some("--version" | "-V" | "version") => {
            println!("basilisk {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("basilisk: unknown command {other:?}; run without arguments for the interface");
            ExitCode::from(2)
        }
    }
}
