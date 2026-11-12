//! basilisk command-line entry point. Subcommands arrive with the milestones in `docs/PLAN.md`.

#![expect(clippy::print_stdout, reason = "the binary's job is to print")]

fn main() {
    println!("basilisk {}", env!("CARGO_PKG_VERSION"));
}
