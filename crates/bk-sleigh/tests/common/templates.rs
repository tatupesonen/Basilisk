//! Template coverage of the differential test (`features/sleigh-pcode.md`
//! 6.2): constructors whose main template was built, op templates built,
//! and one column per construct, with what the `.sla` contains.

use std::collections::BTreeSet;

use bk_pcode::OpCode;
use bk_sla::{ConstTpl, HandleSelect};
use bk_sleigh::Language;

use super::sweep::{Built, FEATURE_NAMES};

/// The template side of one language's coverage.
#[derive(Clone, Debug, Default)]
pub(crate) struct TemplateCoverage {
    /// Constructors with a main template.
    pub(crate) with_template: usize,
    /// Op templates in the language (every section).
    pub(crate) op_templates: usize,
    /// Constructors whose main template was built in a confirmed record.
    pub(crate) built: BTreeSet<u32>,
    /// Op templates built in confirmed records.
    pub(crate) ops_built: BTreeSet<(u32, u32, u32)>,
    /// Per feature: how often it was met in confirmed records.
    pub(crate) features: [u64; 8],
    /// Per feature: whether the `.sla` contains the construct (the last,
    /// `unset`, is never required).
    pub(crate) present: [bool; 8],
}

impl TemplateCoverage {
    /// What `lang` contains. Loads, stores and truncations count as
    /// present when an op template uses an operand whose subtable has a
    /// constructor with a dynamic export (in that position: input, output,
    /// truncated).
    pub(crate) fn of(lang: &Language) -> Self {
        let sla = lang.sla();
        let mut out = Self::default();
        let dynamic = |ctor: &bk_sla::Constructor| {
            sla.main_template(ctor)
                .and_then(|t| t.result().copied())
                .is_some_and(|h| !matches!(h.ptr_space, ConstTpl::Real(_) | ConstTpl::Space(0)))
        };
        // Operand `index` of `ctor` is a subtable with a dynamic export.
        let dynamic_operand = |ctor: &bk_sla::Constructor, index: u32| {
            let Some(&symbol) = sla.operands(ctor).get(index as usize) else {
                return false;
            };
            let Some(bk_sla::SymbolKind::Operand(operand)) = sla.symbol(symbol).map(|s| s.kind)
            else {
                return false;
            };
            let Some(table) = operand.defining_symbol.and_then(|d| sla.subtable(d)) else {
                return false;
            };
            (0..table.num_constructors())
                .filter_map(|i| table.constructor(i))
                .filter_map(|id| sla.constructor(id))
                .any(dynamic)
        };
        for ctor in sla.constructors() {
            if sla.main_template(ctor).is_some() {
                out.with_template += 1;
            }
            for t in sla.template_ids(ctor).filter_map(|id| sla.template(id)) {
                out.op_templates += t.ops().len();
                if t.header().section.is_some() {
                    out.present[2] = true;
                }
                for op in t.ops() {
                    match op.opcode {
                        OpCode::Indirect => out.present[0] = true,
                        OpCode::PtrSub => out.present[1] = true,
                        _ => {}
                    }
                    if matches!(
                        t.inputs(op).first().map(|v| v.offset),
                        Some(ConstTpl::Relative(_))
                    ) {
                        out.present[3] = true;
                    }
                    let output = t.output(op).into_iter().map(|v| (v, true));
                    for (vn, is_output) in output.chain(t.inputs(op).iter().map(|v| (v, false))) {
                        let ConstTpl::Handle {
                            index,
                            select,
                            plus,
                        } = vn.offset
                        else {
                            continue;
                        };
                        if !dynamic_operand(ctor, index) {
                            continue;
                        }
                        out.present[if is_output { 5 } else { 4 }] = true;
                        if select == HandleSelect::OffsetPlus && plus & 0xffff != 0 {
                            out.present[6] = true;
                        }
                    }
                }
            }
        }
        out
    }

    /// Adds what a confirmed record built.
    pub(crate) fn add(&mut self, built: &Built) {
        self.built.extend(built.templates.iter().copied());
        self.ops_built.extend(built.ops.iter().copied());
        for (sum, n) in self.features.iter_mut().zip(built.features) {
            *sum += n;
        }
    }

    /// The share of constructors with a main template whose template was
    /// built.
    pub(crate) fn rate(&self) -> f64 {
        self.built.len() as f64 / self.with_template.max(1) as f64
    }

    /// Features the `.sla` contains that no confirmed record exercised.
    pub(crate) fn missing(&self) -> Vec<&'static str> {
        FEATURE_NAMES
            .iter()
            .zip(self.present.iter().zip(self.features))
            .take(7)
            .filter(|(_, (present, n))| **present && *n == 0)
            .map(|(name, _)| *name)
            .collect()
    }

    /// The table columns.
    pub(crate) fn columns(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!(
            "templates {}/{}\top-templates {}/{}",
            self.built.len(),
            self.with_template,
            self.ops_built.len(),
            self.op_templates
        );
        for ((name, n), present) in FEATURE_NAMES.iter().zip(self.features).zip(self.present) {
            let mark = if present { "" } else { "-" };
            let _ = write!(s, "\t{name} {n}{mark}");
        }
        s
    }
}
