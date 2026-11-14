//! Fuzz target for `bk-sleigh-compiler`: parse and elaborate.
//!
//! The first byte chooses the compiler switches (one bit each for `-u`,
//! `-l`, `-c`, `-n`, `-t`, `-e`, `-s`) and, with its top bit, whether the
//! rest is a whole specification or the semantic body of a constructor
//! placed after a fixed prelude (which reaches the p-code builder, macros
//! and the checks with far fewer bytes). Nothing may panic, hang or
//! allocate without bound (ADR-009).

#![no_main]

use bk_sleigh_compiler::{Options, canon, elaborate};
use bk_sleigh_syntax::{Defines, parse_str};
use libfuzzer_sys::fuzz_target;

const PRELUDE: &str = "define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 r2 r3 ];
define register offset=0x40 size=2 [ h0 h1 ];
define register offset=0x80 size=1 [ c0 c1 ];
define register offset=0x100 size=4 [ ctx ];
define context ctx mode=(0,1) flag=(2,2) noflow;
define token instr(16) op=(8,15) reg=(0,1) imm=(0,7) simm=(0,7) signed;
define bitrange rbit=r0[3,2];
define pcodeop sync;
macro m(a, b) { a = b; <l> if (b == 0) goto <l>; }
sub: r0 is reg=0 & r0 { export r0; }
sub: imm is reg=1 & imm { export *[ram]:4 imm; }
:x r0, sub is op=1 & r0 & sub [ mode = 1; ] {
";

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    let source = if first & 0x80 != 0 {
        format!("{PRELUDE}{text}\n}}\n")
    } else {
        text.into_owned()
    };
    let switches: Vec<&str> = ["-u", "-l", "-c", "-n", "-t", "-e", "-s"]
        .iter()
        .enumerate()
        .filter(|(i, _)| first & (1 << i) != 0)
        .map(|(_, s)| *s)
        .collect();
    let parsed = parse_str("f.slaspec", &source, &Defines::new());
    let outcome = elaborate(&parsed, Options::from_switches(switches));
    if let Some(spec) = &outcome.spec {
        let _ = canon::of_elaborated(spec);
    }
});
