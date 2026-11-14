//! Recorded oracle output (checked in under `tests/data/`), so that the
//! comparison can be replayed without the reference tools. Format: a
//! `stream<TAB>base<TAB>name=value,...` line, a `bytes<TAB>hex` line, the
//! oracle's output without its `H` record, and `end`. Comment lines start
//! with `#`.

use std::fmt::Write as _;
use std::sync::Arc;

use bk_sleigh::Language;

use super::{Tolerated, compare, parse_oracle, sweep};

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Records one stream with `run` (which returns `None` when the oracle
/// crashed); where Ghidra's engine crashes on an instruction, the stream is
/// split around it.
pub(crate) fn record(
    out: &mut String,
    run: &dyn Fn(u64, &[(String, u32)], &[u8]) -> Option<String>,
    base: u64,
    config: &[(String, u32)],
    bytes: &[u8],
) {
    if bytes.is_empty() {
        return;
    }
    let Some(text) = run(base, config, bytes) else {
        let (mut ok, mut bad) = (0usize, bytes.len());
        while bad - ok > 1 {
            let mid = ok + (bad - ok) / 2;
            if run(base, config, &bytes[..mid]).is_none() {
                bad = mid;
            } else {
                ok = mid;
            }
        }
        let before = parse_oracle(&run(base, config, &bytes[..bad - 1]).unwrap_or_default());
        let start = before
            .lines
            .last()
            .filter(|l| l.contains("\ttruncated\t"))
            .map_or(bad - 1, |l| {
                (u64::from_str_radix(l.split('\t').nth(1).unwrap().trim_start_matches("0x"), 16).unwrap() - base) as usize
            });
        let _ = writeln!(out, "# oracle crash at {:#x}: {}", base + start as u64, hex(&bytes[start..bad]));
        record(out, run, base, config, &bytes[..start]);
        record(out, run, base + bad as u64, config, &bytes[bad..]);
        return;
    };
    let names: Vec<String> = config.iter().map(|(n, v)| format!("{n}={v}")).collect();
    let _ = writeln!(out, "stream\t{base:#x}\t{}", names.join(","));
    let _ = writeln!(out, "bytes\t{}", hex(bytes));
    for line in text.lines().filter(|l| !l.starts_with('H')) {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("end\n");
}

/// What a replay saw.
#[derive(Debug, Default)]
pub(crate) struct Replay {
    pub(crate) streams: usize,
    pub(crate) instructions: u64,
    pub(crate) tolerated: Tolerated,
}

/// Replays a recording against basilisk; panics on a difference.
pub(crate) fn replay(text: &str, lang: &Arc<Language>) -> Replay {
    let mut lines = text.lines().filter(|l| !l.starts_with('#'));
    let mut seen = Replay::default();
    while let Some(head) = lines.next() {
        let mut fields = head.split('\t');
        assert_eq!(fields.next(), Some("stream"), "{head}");
        let base = u64::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
        let config: Vec<(String, u32)> = fields
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|c| !c.is_empty())
            .map(|c| {
                let (n, v) = c.split_once('=').unwrap();
                (n.to_owned(), v.parse().unwrap())
            })
            .collect();
        let bytes = unhex(lines.next().unwrap().strip_prefix("bytes\t").unwrap());
        let mut recorded = String::new();
        for line in lines.by_ref() {
            if line == "end" {
                break;
            }
            recorded.push_str(line);
            recorded.push('\n');
        }
        let theirs = parse_oracle(&recorded);
        let ours = sweep(lang, base, &bytes, &config);
        let cmp = compare(&theirs, &ours);
        for f in &cmp.failures {
            eprintln!("stream at {base:#x} {config:?}: {f}");
        }
        assert!(cmp.failures.is_empty(), "records differ from the recording");
        seen.tolerated.add(&cmp.tolerated);
        seen.instructions += theirs.instructions;
        seen.streams += 1;
    }
    seen
}
