//! The context oracle's generator (`tests/oracle/context.cc`) driving
//! Basilisk's `ContextNames`: the same draws, operations and row texts.

use std::fmt::Write as _;

use bk_context::TrackedValue;
use bk_core::{Address, SpaceId, SpaceManager, VarnodeData};
use bk_decomp_symbols::{ContextNames, SymbolError, ids};
use bk_marshal::{Document, XmlDecoder, XmlEncoder};

use super::scope_gen::Rng;

pub struct ContextGen<'a> {
    pub spaces: &'a SpaceManager,
    pub ram: SpaceId,
    pub reg: SpaceId,
    pub rng: Rng,
    pub out: String,
    pub kase: i64,
}

impl ContextGen<'_> {
    fn row(&mut self, kind: &str, text: &str) {
        let _ = writeln!(self.out, "{}\t{kind}\t{text}", self.kase);
    }

    fn name(&self, a: Address) -> &str {
        self.spaces.space_of(a).map_or("?", bk_core::Space::name)
    }

    fn rand_addr(&mut self) -> Address {
        let off = 0x1000 + u64::from(self.rng.r(0x40));
        if self.rng.r(8) == 0 {
            Address::new(self.reg, off)
        } else {
            Address::new(self.ram, off)
        }
    }

    fn encode_of(&self, ctx: &ContextNames) -> Result<String, SymbolError> {
        let mut enc = XmlEncoder::new(true);
        ctx.encode(&mut enc, self.spaces)?;
        Ok(enc.into_string().replace('\n', ""))
    }

    pub fn one_case(&mut self) {
        if let Err(e) = self.one() {
            self.row("!case", &e.to_string());
        }
    }

    fn one(&mut self) -> Result<(), SymbolError> {
        let mut ctx = ContextNames::new();
        ctx.set_space_limits(self.spaces);
        let mut vars: Vec<(String, u32, u32)> = Vec::new();
        let nv = 1 + self.rng.r(6);
        for i in 0..nv {
            let word = self.rng.r(2);
            let start = self.rng.r(32);
            let len = 1 + self.rng.r(32 - start);
            let name = format!("v{i}");
            let (s, e) = (word * 32 + start, word * 32 + start + len - 1);
            ctx.register_variable(&name, s, e)?;
            self.row("var", &format!("{name} {s} {e}"));
            vars.push((name, s, e));
        }
        let nops = self.rng.r(12);
        for _ in 0..nops {
            let v = vars[self.rng.r(vars.len() as u32) as usize].0.clone();
            let val = self.rng.rnd() as u32;
            let text = match self.rng.r(5) {
                0 => {
                    ctx.set_variable_default(&v, val)?;
                    format!("default {v} {val:x}")
                }
                1 => {
                    let a = self.rand_addr();
                    ctx.set_variable(&v, a, val)?;
                    format!("set {v} {} {:x} {val:x}", self.name(a), a.offset())
                }
                2 => {
                    let a = self.rand_addr();
                    let b = if self.rng.r(4) != 0 {
                        Some(a.add(self.spaces, i64::from(1 + self.rng.r(0x20))))
                    } else {
                        None
                    };
                    ctx.set_variable_region(&v, a, b, val)?;
                    let bt = b.map_or("- -".to_owned(), |b| {
                        format!("{} {}", self.name(b), b.offset())
                    });
                    format!("region {v} {} {:x} {bt} {val:x}", self.name(a), a.offset())
                }
                3 => {
                    let a = self.rand_addr();
                    let b = a.add(self.spaces, i64::from(1 + self.rng.r(0x20)));
                    let n = self.rng.r(3);
                    let mut s = format!("track {} {:x} {:x}", self.name(a), a.offset(), b.offset());
                    let mut set = Vec::new();
                    for _ in 0..n {
                        let offset = 8 * u64::from(self.rng.r(4));
                        let size = 1u32 << self.rng.r(4);
                        let value = self.rng.rnd();
                        set.push(TrackedValue {
                            space: self.reg,
                            offset,
                            size,
                            big_endian: false,
                            value,
                        });
                        let _ = write!(s, " ({offset:x},{size:x},{value:x})");
                    }
                    ctx.create_set(a, b, set);
                    s
                }
                _ => {
                    let a = self.rand_addr();
                    let w = self.rng.r(ctx.size() as u32);
                    let mask = self.rng.rnd() as u32;
                    let value = (self.rng.rnd() as u32) & mask;
                    ctx.set_context_change_point(a, w as usize, mask, value);
                    format!(
                        "change {} {:x} {w:x} {mask:x} {value:x}",
                        self.name(a),
                        a.offset()
                    )
                }
            };
            self.row("op", &text);
        }
        for _ in 0..16 {
            let a = self.rand_addr();
            let (words, range) = ctx.context(a);
            let mut s = format!("{} {:x} -> ", self.name(a), a.offset());
            let joined: Vec<String> = words.iter().map(|w| format!("{w:x}")).collect();
            let _ = write!(s, "{} {:x} {:x}", joined.join(","), range.first, range.last);
            for (name, _, _) in &vars {
                let _ = write!(s, " {:x}", ctx.variable_at(name, a)?);
            }
            self.row("get", &s);
            let off = u64::from(self.rng.r(32));
            let size = 1u32 << self.rng.r(4);
            let tv = ctx.tracked_value(VarnodeData::new(self.reg, off, size), a);
            let t = format!(
                "{} {:x} {off:x} {size:x} -> {tv:x}",
                self.name(a),
                a.offset()
            );
            self.row("tracked", &t);
        }
        let e = self.encode_of(&ctx)?;
        self.row("encode", &e);
        if !e.is_empty() {
            let mut ctx2 = ContextNames::new();
            ctx2.set_space_limits(self.spaces);
            for (name, s, en) in &vars {
                ctx2.register_variable(name, *s, *en)?;
            }
            let doc = Document::parse(&e).map_err(bk_marshal::DecodeError::from)?;
            let table = ids::id_table();
            let mut dec = XmlDecoder::new(&doc, &table, self.spaces);
            ctx2.decode(&mut dec, self.spaces)?;
            let e2 = self.encode_of(&ctx2)?;
            self.row("redecode", &e2);
        }
        Ok(())
    }
}
