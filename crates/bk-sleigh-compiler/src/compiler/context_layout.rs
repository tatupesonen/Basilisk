//! The context layout (`calcContextLayout`, `calcContextVarLayout`,
//! `slgh_compile.cc` 2025-2080, 2515-2542): context fields become symbols
//! when the layout is locked, at the first constructor, `attach` or `with`.

use bk_sla::Field;
use bk_sleigh_syntax::Span;

use super::{Compiler, PendingField};
use crate::pattern::PatValue;
use crate::symbols::SymbolKind;

impl Compiler<'_> {
    /// Locks the context layout (once) and creates the context symbols.
    /// `at` is the position of the token that triggers it.
    pub(crate) fn lock_context_at(&mut self, at: Span) {
        if self.context_locked {
            return;
        }
        self.context_locked = true;
        let mut fields = std::mem::take(&mut self.pending_context);
        // A stable sort by (register name, low bit), as `FieldContext::operator<`.
        let names: Vec<String> = fields
            .iter()
            .map(|f| {
                self.symbols
                    .get(f.varnode)
                    .map_or_else(String::new, |s| self.text(s.name).to_owned())
            })
            .collect();
        let mut order: Vec<usize> = (0..fields.len()).collect();
        order.sort_by(|&a, &b| {
            let (na, nb) = (names.get(a), names.get(b));
            na.map(|s| s.as_bytes())
                .cmp(&nb.map(|s| s.as_bytes()))
                .then_with(|| {
                    let la = fields.get(a).map(|f| f.low as u32);
                    let lb = fields.get(b).map(|f| f.low as u32);
                    la.cmp(&lb)
                })
        });
        let sorted: Vec<PendingField> = order.iter().filter_map(|&i| fields.get(i).copied()).collect();
        fields.clear();
        let mut bits = 0_i32;
        let mut begin = 0;
        while begin < sorted.len() {
            let Some(first) = sorted.get(begin) else { break };
            let mut size = 1;
            while sorted
                .get(begin + size)
                .is_some_and(|f| f.varnode == first.varnode)
            {
                size += 1;
            }
            bits = self.layout_register(sorted.get(begin..begin + size).unwrap_or_default(), bits, at);
            begin += size;
        }
    }

    /// Locks the layout at an `attach` (no better position is known).
    pub(crate) fn lock_context(&mut self) {
        self.lock_context_at(Span::default());
    }

    /// `calcContextVarLayout`: places the fields of one context register.
    fn layout_register(&mut self, fields: &[PendingField], mut bits: i32, at: Span) -> i32 {
        let Some(first) = fields.first() else { return bits };
        let varnode = first.varnode;
        let (reg_name, reg_size) = match self.symbols.get(varnode) {
            Some(s) => {
                let size = match s.kind {
                    SymbolKind::Varnode(vn) => vn.size,
                    _ => 0,
                };
                (self.text(s.name).to_owned(), size)
            }
            None => (String::new(), 0),
        };
        if reg_size % 4 != 0 {
            self.diags.error_at(at, format!("Invalid size of context register '{reg_name}': must be a multiple of 4 bytes"));
        }
        let max_bits = reg_size.wrapping_mul(8).wrapping_sub(1);
        let mut i = 0;
        while i < fields.len() {
            let Some(field) = fields.get(i) else { break };
            let min = field.low as i32;
            let mut max = field.high as i32;
            let name = self.text(field.name).to_owned();
            if max.wrapping_sub(min) > 32 {
                self.diags.error_at(at, format!("Size of bitfield '{name}' larger than 32 bits"));
            }
            if max > max_bits {
                self.diags.error_at(at, format!("Scope of bitfield '{name}' extends beyond the size of context register"));
            }
            let mut j = i + 1;
            while let Some(next) = fields.get(j) {
                if next.low as i32 <= max {
                    if next.high as i32 > max {
                        max = next.high as i32;
                    }
                } else {
                    break;
                }
                j += 1;
            }
            let alloc = max.wrapping_sub(min).wrapping_add(1);
            let start_word = bits / 32;
            let end_word = bits.wrapping_add(alloc).wrapping_sub(1) / 32;
            if start_word != end_word {
                bits = end_word.wrapping_mul(32);
            }
            let low = bits;
            bits = bits.wrapping_add(alloc);
            while i < j {
                let Some(f) = fields.get(i) else { break };
                let start = (f.low as i32).wrapping_sub(min).wrapping_add(low);
                let end = bits.wrapping_sub(1).wrapping_sub(max.wrapping_sub(f.high as i32));
                let value = PatValue::Context(Field {
                    big_endian: false,
                    sign_bit: f.signed,
                    start_bit: start,
                    end_bit: end,
                    start_byte: start / 8,
                    end_byte: end / 8,
                    shift: 7 - end % 8,
                });
                let kind = SymbolKind::Context {
                    varnode,
                    low: f.low as u32,
                    high: f.high as u32,
                    flow: f.flow,
                    field: value,
                };
                self.add_symbol(f.name, kind, at);
                i += 1;
            }
        }
        bits
    }
}
