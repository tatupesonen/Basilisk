//! Fuzz target for `bk-sleigh-compiler`: the whole pipeline (parse,
//! elaborate, patterns, decision trees, lowering) and `bk_sla`'s validation
//! of the result. Whatever compiles must be a valid model: it re-reads
//! through the validating reader and re-encodes to the same bytes.
//!
//! The first byte chooses the compiler switches (one bit each for `-u`,
//! `-l`, `-c`, `-n`, `-t`, `-e`, `-s`) and, with its top bit, whether the
//! rest is a whole specification or the pattern and body of constructors
//! after a fixed prelude (which reaches the pattern algebra and the
//! decision trees with few bytes).

#![no_main]

use bk_sla::{Limits, Sla};
use bk_sleigh_compiler::{Options, compile_parsed};
use bk_sleigh_syntax::{Defines, parse_str};
use libfuzzer_sys::fuzz_target;

const PRELUDE: &str = "define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 r2 r3 ];
define register offset=0x100 size=4 [ ctx ];
define context ctx mode=(0,1) flag=(2,2) noflow;
define token instr(16) op=(8,15) reg=(0,1) imm=(0,7) simm=(0,7) signed;
define token extra(8) x8=(0,7) lo=(0,3);
attach variables [ reg ] [ r0 r1 r2 r3 ];
sub: reg is reg & op=1 { export reg; }
sub: imm is op=2 & imm { export *[ram]:4 imm; }
sub: x8 is op=3 ; x8 { }
:nop is op=0 { }
";

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    let source = if first & 0x80 != 0 {
        format!("{PRELUDE}{text}\n")
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
    if parsed.has_errors() {
        return;
    }
    let compiled = compile_parsed(&parsed, Options::from_switches(switches));
    if let Some(sla) = &compiled.sla {
        let stream = sla.encode_packed().expect("a compiled model encodes");
        let again = Sla::decode_packed(&stream, &Limits::default())
            .expect("whatever compiles is a valid model");
        assert_eq!(again.encode_packed().expect("re-encodes"), stream);
    }
});
