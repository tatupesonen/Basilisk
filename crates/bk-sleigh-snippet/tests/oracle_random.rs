//! Generated snippets compared with Ghidra's compiler: bodies built from the
//! grammar with every kind of name, then often corrupted (a token dropped,
//! duplicated or replaced), so that both accepted and refused text is
//! covered. Needs the `snippetdump` oracle; deterministic (a fixed seed).
//! `SNIPPET_RANDOM_CASES` sets the number of bodies (default 3,000).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

mod common;

use bk_sleigh_snippet::{Options, Parameter, SnippetCompiler};
use common::oracle::{Base, Record, escape, run_basilisk, run_oracle};

/// A small deterministic generator (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const VARNODES: &[&str] = &["EAX", "EBX", "AX", "AL", "ES", "R64", "XMM0", "contextreg"];
const PARAMS: &[&str] = &["in1", "in2", "out1"];
const JUMPS: &[&str] = &[
    "inst_start",
    "inst_next",
    "inst_next2",
    "inst_dest",
    "inst_ref",
];
const SPACES: &[&str] = &["ram", "register", "io", "const", "unique", "OTHER"];
const INVISIBLE: &[&str] = &["TMode", "op", "reg", "mode", "sub", "instruction", "m1"];
const UNKNOWN: &[&str] = &["foo", "t", "x", "build", "popcount", "export"];
const NUMBERS: &[&str] = &[
    "0",
    "1",
    "2",
    "4",
    "8",
    "16",
    "32",
    "64",
    "0x10",
    "010",
    "0xffffffffffffffff",
    "0x1ffffffffffffffff",
];
const BINARY: &[&str] = &[
    "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "s>>", "==", "!=", "<", ">", "<=", ">=",
    "s<", "s>", "s<=", "s>=", "f<", "f>", "f==", "f!=", "f+", "f-", "f*", "f/", "s/", "s%", "&&",
    "||", "^^",
];
const UNARY: &[&str] = &["-", "~", "!", "f-"];
const BUILTIN1: &[&str] = &[
    "zext",
    "sext",
    "abs",
    "sqrt",
    "nan",
    "ceil",
    "floor",
    "round",
    "int2float",
    "float2float",
    "trunc",
];
const BUILTIN2: &[&str] = &["carry", "scarry", "sborrow"];
const USEROPS: &[&str] = &["segment", "syscall", "in"];
const PUNCT: &[&str] = &[
    "(", ")", "[", "]", ",", ":", ";", "=", "<", ">", "*", "&", "#", "@", "borrow", "local",
    "goto", "call", "return", "if",
];

struct Gen {
    rng: Rng,
    labels: Vec<String>,
    temps: Vec<String>,
}

impl Gen {
    fn name(&mut self) -> String {
        let r = self.rng.below(20);
        let set = match r {
            0..=7 => VARNODES,
            8..=10 => PARAMS,
            11 => JUMPS,
            12 => SPACES,
            13 => INVISIBLE,
            14..=15 if !self.temps.is_empty() => {
                let i = self.rng.below(self.temps.len());
                return self.temps[i].clone();
            }
            _ => UNKNOWN,
        };
        self.rng.pick(set).to_owned()
    }

    fn number(&mut self) -> String {
        self.rng.pick(NUMBERS).to_owned()
    }

    fn expr(&mut self, depth: u32) -> String {
        if depth > 3 {
            return self.primary(depth);
        }
        match self.rng.below(10) {
            0..=3 => self.primary(depth),
            4..=6 => format!(
                "{} {} {}",
                self.expr(depth + 1),
                self.rng.pick(BINARY),
                self.expr(depth + 1)
            ),
            7 => format!("{}{}", self.rng.pick(UNARY), self.expr(depth + 1)),
            8 => format!("({})", self.expr(depth + 1)),
            _ => format!("{} {}", self.star(), self.expr(depth + 1)),
        }
    }

    fn star(&mut self) -> String {
        match self.rng.below(4) {
            0 => "*".to_owned(),
            1 => format!("*:{}", self.number()),
            2 => format!("*[{}]", self.rng.pick(SPACES)),
            _ => format!("*[{}]:{}", self.rng.pick(SPACES), self.number()),
        }
    }

    fn primary(&mut self, depth: u32) -> String {
        match self.rng.below(12) {
            0..=3 => self.name(),
            4..=5 => self.number(),
            6 => format!("{}:{}", self.number(), self.number()),
            7 => format!("{}:{}", self.name(), self.number()),
            8 => format!("{}[{},{}]", self.name(), self.number(), self.number()),
            9 => format!("{}({})", self.name(), self.number()),
            10 => {
                let size = if self.rng.chance(50) {
                    format!(":{} ", self.number())
                } else {
                    String::new()
                };
                format!("&{size}{}", self.name())
            }
            _ => match self.rng.below(3) {
                0 => format!("{}({})", self.rng.pick(BUILTIN1), self.expr(depth + 1)),
                1 => format!(
                    "{}({}, {})",
                    self.rng.pick(BUILTIN2),
                    self.expr(depth + 1),
                    self.expr(depth + 1)
                ),
                _ => {
                    let n = self.rng.below(3);
                    let args: Vec<String> = (0..n).map(|_| self.expr(depth + 1)).collect();
                    format!("{}({})", self.rng.pick(USEROPS), args.join(", "))
                }
            },
        }
    }

    fn label(&mut self) -> String {
        if !self.labels.is_empty() && self.rng.chance(60) {
            let i = self.rng.below(self.labels.len());
            return self.labels[i].clone();
        }
        let l = format!("L{}", self.rng.below(4));
        self.labels.push(l.clone());
        l
    }

    fn dest(&mut self) -> String {
        match self.rng.below(6) {
            0 => self.rng.pick(JUMPS).to_owned(),
            1 => self.number(),
            2 => format!("{}[{}]", self.number(), self.rng.pick(SPACES)),
            3 => format!("<{}>", self.label()),
            4 => self.name(),
            _ => format!("[{}]", self.expr(1)),
        }
    }

    fn statement(&mut self) -> String {
        match self.rng.below(14) {
            0..=3 => format!("{} = {};", self.name(), self.expr(0)),
            4 => {
                let t = format!("t{}", self.rng.below(5));
                self.temps.push(t.clone());
                format!("{t} = {};", self.expr(0))
            }
            5 => {
                let t = format!("t{}", self.rng.below(5));
                self.temps.push(t.clone());
                match self.rng.below(4) {
                    0 => format!("local {t};"),
                    1 => format!("local {t}:{};", self.number()),
                    2 => format!("local {t} = {};", self.expr(0)),
                    _ => format!("{t}:{} = {};", self.number(), self.expr(0)),
                }
            }
            6 => format!("{} {} = {};", self.star(), self.expr(1), self.expr(0)),
            7 => format!(
                "{}[{},{}] = {};",
                self.name(),
                self.number(),
                self.number(),
                self.expr(0)
            ),
            8 => format!("goto {};", self.dest()),
            9 => format!("call {};", self.dest()),
            10 => format!("if {} goto {};", self.expr(0), self.dest()),
            11 => format!("return [{}];", self.expr(1)),
            12 => format!("<{}>", self.label()),
            _ => {
                let n = self.rng.below(3);
                let args: Vec<String> = (0..n).map(|_| self.expr(1)).collect();
                format!("{}({});", self.rng.pick(USEROPS), args.join(", "))
            }
        }
    }

    fn body(&mut self) -> String {
        self.labels.clear();
        self.temps.clear();
        let n = 1 + self.rng.below(4);
        let mut tokens: Vec<String> = Vec::new();
        for _ in 0..n {
            tokens.extend(self.statement().split(' ').map(str::to_owned));
        }
        // Corrupt about half of the bodies.
        if self.rng.chance(50) {
            for _ in 0..=self.rng.below(2) {
                let i = self.rng.below(tokens.len());
                match self.rng.below(3) {
                    0 => {
                        tokens.remove(i);
                    }
                    1 => {
                        let t = tokens[i].clone();
                        tokens.insert(i, t);
                    }
                    _ => tokens[i] = self.rng.pick(PUNCT).to_owned(),
                }
                if tokens.is_empty() {
                    break;
                }
            }
        }
        tokens.join(" ")
    }
}

/// The value of a number token as the snippet lexer reads it.
fn number(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if text.len() > 1 && text.starts_with('0') {
        let digits: String = text
            .chars()
            .take_while(|c| ('0'..='7').contains(c))
            .collect();
        return u64::from_str_radix(&digits, 8).ok();
    }
    text.parse().ok()
}

/// Whether `body` has a bit range `[low,width]` whose arithmetic wraps in
/// Ghidra's 32-bit unsigned integers: `createBitRange`, `assignBitRange`
/// and `buildTruncatedVarnode` (`pcodecompile.cc` 702–916) take both as
/// `uint4` (`pcodeparse.y` 114, 187) and compute `(numbits+7)/8`,
/// `bitoffset+numbits` and `byteoffset+numbytes` in 32 bits, while
/// `bk_sleigh_compiler`'s builder computes them without wrapping (a
/// follow-up for that crate).
fn wraps_32_bits(body: &str) -> bool {
    let mut rest = body;
    while let Some(open) = rest.find('[') {
        rest = &rest[open + 1..];
        let Some(close) = rest.find(']') else { break };
        let inside = &rest[..close];
        if let Some((a, b)) = inside.split_once(',') {
            if let (Some(low), Some(width)) = (number(a.trim()), number(b.trim())) {
                let (low, width) = (low as u32, width as u32);
                if low.checked_add(width).is_none()
                    || width.checked_add(7).is_none()
                    || (low / 8).checked_add(width / 8).is_none()
                {
                    return true;
                }
            }
        }
    }
    false
}

#[test]
fn generated_snippets_match_ghidra() {
    let Some(reference) = bk_testkit::skip::require_reference() else {
        return;
    };
    let Some(tool) = common::snippetdump(&reference) else {
        return;
    };
    let count: usize = std::env::var("SNIPPET_RANDOM_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000);
    let mut generator = Gen {
        rng: Rng(0x5eed_0f5a_1e16_4b17),
        labels: Vec::new(),
        temps: Vec::new(),
    };
    let params = vec![
        Parameter::new("in1", 0),
        Parameter::new("in2", 1),
        Parameter::new("out1", 2),
    ];
    let bodies: Vec<String> = (0..count).map(|_| generator.body()).collect();
    let records: Vec<Record> = bodies
        .iter()
        .enumerate()
        .map(|(i, body)| Record {
            source: format!("gen{i}"),
            base: Base::Start(0x1_0000),
            body: body.clone(),
            params: params.clone(),
        })
        .collect();
    let sla = common::fixture::sla();
    let compiler = SnippetCompiler::new(&sla, &Options::default());
    let root = common::fixture::write_root(
        &std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("snippet-fixture-random"),
    );
    let expected = run_oracle(&tool, &root, common::fixture::LANGUAGE_ID, &records);
    let actual = run_basilisk(&compiler, 0x1_0000, &records);
    let mut accepted = 0;
    let mut wrapped = 0;
    let mut differences = Vec::new();
    for ((body, exp), act) in bodies.iter().zip(&expected).zip(&actual) {
        if matches!(exp, common::oracle::Outcome::Ok { .. }) {
            accepted += 1;
        }
        if exp != act && wraps_32_bits(body) {
            wrapped += 1;
            continue;
        }
        if exp != act {
            differences.push(format!(
                "{}\n  ghidra:   {exp:?}\n  basilisk: {act:?}",
                escape(body)
            ));
        }
    }
    eprintln!(
        "generated: {count} bodies, {accepted} compiled by Ghidra, {} differ, {wrapped} \
         tolerated (bit range arithmetic that wraps at 32 bits in Ghidra)",
        differences.len()
    );
    for d in differences.iter().take(15) {
        eprintln!("{d}");
    }
    assert_eq!(differences.len(), 0, "differences from Ghidra");
}
