//! Benchmarks, as `#[ignore]` tests that print the time per operation.
//! Run them in release mode:
//!
//! ```text
//! CARGO_BUILD_JOBS=2 cargo test -p bk-decomp-types --release --test bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Numbers are recorded in `docs/PERF.md` under `bk-decomp-types`.
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

use std::hint::black_box;
use std::time::Instant;

use bk_decomp_types::{Field, Metatype, TypeId};
use common::x86_64_factory;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

const METAS: [Metatype; 5] = [
    Metatype::Int,
    Metatype::Uint,
    Metatype::Unknown,
    Metatype::Float,
    Metatype::Bool,
];

/// One million pointer/array/base requests of which about 90 % ask for a
/// type that already exists.
#[test]
#[ignore = "benchmark"]
fn intern_one_million() {
    let mut f = x86_64_factory();
    let mut rng = Rng(7);
    let mut pool: Vec<TypeId> = vec![f.find_by_name("int4").unwrap()];
    let start = Instant::now();
    let n = 1_000_000;
    for _ in 0..n {
        let r = rng.next();
        let fresh = r.is_multiple_of(10);
        let base = pool[(r >> 8) as usize % pool.len()];
        let t = match (r >> 4) % 3 {
            0 => f
                .base(1 << ((r >> 32) % 4), METAS[(r >> 40) as usize % 5])
                .unwrap(),
            1 => {
                // Repeats come from a small working set; fresh ones from the
                // whole pool, so the set of types keeps growing.
                let target = if fresh {
                    base
                } else {
                    pool[(r >> 8) as usize % pool.len().min(64)]
                };
                f.pointer(8, target, 1).unwrap()
            }
            _ => {
                let el = if fresh {
                    base
                } else {
                    pool[(r >> 8) as usize % pool.len().min(64)]
                };
                if f.get(el).unwrap().align_size() == 0 || f.get(el).unwrap().size() > 4096 {
                    f.pointer(8, el, 1).unwrap()
                } else {
                    f.array(1 + ((r >> 48) % if fresh { 64 } else { 4 }) as i32, el)
                        .unwrap()
                }
            }
        };
        if fresh {
            pool.push(t);
        }
        black_box(t);
    }
    let el = start.elapsed();
    eprintln!(
        "intern: {n} requests in {:.1} ms, {:.0} ns/request, {} types in the factory",
        el.as_secs_f64() * 1e3,
        el.as_secs_f64() * 1e9 / f64::from(n),
        f.len()
    );
}

/// Decodes a `<typegrp>` of 10,000 types (structures, pointers, arrays,
/// enumerations, typedefs).
#[test]
#[ignore = "benchmark"]
fn decode_ten_thousand() {
    let mut f = x86_64_factory();
    let int4 = f.find_by_name("int4").unwrap();
    let char_t = f.find_by_name("char").unwrap();
    let mut prev = int4;
    let mut k = 0;
    while f.len() < 10_000 {
        let s = f.structure_stub(&format!("s{k}")).unwrap();
        let ps = f.pointer_named(8, prev, 1, &format!("p{k}")).unwrap();
        let arr = f.array(3, char_t).unwrap();
        let fields = vec![
            Field {
                ident: 0,
                offset: -1,
                name: "a".into(),
                ty: int4,
            },
            Field {
                ident: 0,
                offset: -1,
                name: "b".into(),
                ty: ps,
            },
            Field {
                ident: 0,
                offset: -1,
                name: "c".into(),
                ty: arr,
            },
        ];
        f.assign_raw_struct_fields(s, fields, Vec::new()).unwrap();
        f.typedef(s, &format!("t{k}"), 0, 0).unwrap();
        let e = f.enum_stub(&format!("e{k}")).unwrap();
        let mut map = std::collections::BTreeMap::new();
        map.insert(1u64, "A".into());
        map.insert(2u64, format!("B{k}").into());
        f.set_enum_values(e, map).unwrap();
        prev = s;
        k += 1;
    }
    let mut enc = bk_marshal::XmlEncoder::new(false);
    f.encode(&mut enc).unwrap();
    let text = enc.into_string();
    let types = f.len();
    let start = Instant::now();
    let rounds = 5;
    for _ in 0..rounds {
        let mut g = x86_64_factory();
        g.decode_text(&text).unwrap();
        black_box(g.len());
    }
    let el = start.elapsed() / rounds;
    eprintln!(
        "decode: {types} types, {} bytes of XML, {:.1} ms per decode, {:.0} ns/type",
        text.len(),
        el.as_secs_f64() * 1e3,
        el.as_secs_f64() * 1e9 / types as f64
    );
}
