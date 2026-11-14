//! Finishing a constructor's sections (inventory 9.8;
//! `SleighCompile::finalizeSections`, `forceExportSize`, `findSize`;
//! `ConstructTpl::fillinBuild`).

use bk_sla::ConstTpl;

use super::Compiler;
use super::sections::{Section, Sections};
use crate::ids::CtorId;
use crate::pcode::propagate_size;
use crate::symbols::SymbolKind;
use crate::template::{BUILD, Op, Tpl, Vn, const_eq, is_unique_space, is_zero, real};

/// `findSize`: the first temporary with the given offset in `ops`.
fn find_size(offset: &ConstTpl, ops: &[Op]) -> Option<ConstTpl> {
    for op in ops {
        if let Some(out) = &op.output
            && out.is_local_temp()
            && const_eq(&out.offset, offset)
        {
            return Some(out.size);
        }
        for input in &op.inputs {
            if input.is_local_temp() && const_eq(&input.offset, offset) {
                return Some(input.size);
            }
        }
    }
    None
}

/// `forceExportSize`: an export of unknown size takes the size of a use of
/// its temporary. False if none is found.
fn force_export_size(tpl: &mut Tpl) -> bool {
    let Some(result) = tpl.result.as_mut() else {
        return true;
    };
    if is_unique_space(&result.ptr_space) && is_zero(&result.ptr_size) {
        match find_size(&result.ptr_offset, &tpl.ops) {
            Some(size) => result.ptr_size = size,
            None => return false,
        }
    } else if is_unique_space(&result.space) && is_zero(&result.size) {
        match find_size(&result.ptr_offset, &tpl.ops) {
            Some(size) => result.size = size,
            None => return false,
        }
    }
    true
}

/// `fillinBuild`: 0 on success, 1 for a duplicate `build`, 2 for a `build`
/// of an operand that is not a subtable. Missing `BUILD`s are inserted at
/// the front, in ascending operand order each at position 0.
fn fill_in_build(tpl: &mut Tpl, check: &mut [u8]) -> u8 {
    for op in &tpl.ops {
        if op.opcode == BUILD {
            let index = op.inputs.first().map_or(0, |v| real(&v.offset)) as usize;
            match check.get_mut(index) {
                Some(slot) if *slot != 0 => return *slot,
                Some(slot) => *slot = 1,
                // Ghidra indexes out of bounds here; an operand index that
                // does not exist is reported as an unnecessary build.
                None => return 2,
            }
        }
    }
    for (i, &state) in check.iter().enumerate() {
        if state == 0 {
            tpl.ops
                .insert(0, Op::new(BUILD, vec![Vn::constant(i as u64, 4)]));
        }
    }
    0
}

impl Compiler<'_> {
    /// `markSubtableOperands`.
    fn subtable_operands(&self, ctor: CtorId) -> Vec<u8> {
        let Some(c) = self.ctors.get(ctor.slot()) else {
            return Vec::new();
        };
        c.operands
            .iter()
            .map(|op| {
                let sub = self
                    .operands
                    .get(op.slot())
                    .and_then(|o| o.def_symbol)
                    .is_some_and(|s| matches!(self.kind(s), Some(SymbolKind::Subtable(_))));
                if sub { 0 } else { 2 }
            })
            .collect()
    }

    /// Finishes one section; problems go to `errors` prefixed by `label`.
    fn finish_section(
        &mut self,
        ctor: CtorId,
        section: &mut Section,
        label: &str,
        errors: &mut Vec<String>,
    ) {
        if !section.labels.is_empty() {
            errors.push(format!("{label}{}", section.labels));
            return;
        }
        if !self.expand_macros(&mut section.tpl) {
            errors.push(format!("{label}Could not expand macros"));
        }
        let mut check = self.subtable_operands(ctor);
        match fill_in_build(&mut section.tpl, &mut check) {
            1 => errors.push(format!("{label}Duplicate BUILD statements")),
            2 => errors.push(format!("{label}Unnecessary BUILD statements")),
            _ => {}
        }
        match propagate_size(&mut section.tpl.ops) {
            Ok(true) => {}
            Ok(false) => errors.push(format!("{label}Could not resolve at least 1 variable size")),
            Err(e) => {
                self.diags.error(Some(self.ctor_at(ctor)), e.to_string());
                self.fatal = true;
            }
        }
    }

    /// `finalizeSections`: returns the finished main and named templates,
    /// or `None` after reporting the problems.
    pub(crate) fn finalize_sections(
        &mut self,
        ctor: CtorId,
        sections: Sections,
    ) -> Option<(Tpl, Vec<Option<Tpl>>)> {
        let Sections { mut main, named } = sections;
        let mut errors = Vec::new();
        let root = self
            .ctors
            .get(ctor.slot())
            .is_some_and(|c| c.table.slot() == 0);
        self.finish_section(ctor, &mut main, "   Main section: ", &mut errors);
        if main.tpl.result.is_some() {
            if root {
                errors.push("   Cannot have export statement in root constructor".to_owned());
            } else if !force_export_size(&mut main.tpl) {
                errors.push("   Size of export is unknown".to_owned());
            }
        }
        self.note_delay(ctor, main.tpl.delay, root);
        let mut named_out = Vec::with_capacity(named.len());
        for (number, section) in named.into_iter().enumerate() {
            let Some(mut section) = section else {
                named_out.push(None);
                continue;
            };
            let name = self
                .sections
                .get(number)
                .and_then(|s| self.symbols.get(*s))
                .map_or_else(String::new, |s| self.text(s.name).to_owned());
            let label = format!("   {name} section: ");
            self.finish_section(ctor, &mut section, &label, &mut errors);
            self.note_delay(ctor, section.tpl.delay, root);
            named_out.push(Some(section.tpl));
        }
        if self.fatal {
            return None;
        }
        if !errors.is_empty() {
            let at = self.ctor_at(ctor);
            let info = self.ctor_info(ctor);
            self.diags.error_at(at, format!("in {info}"));
            for e in errors {
                self.diags.error_at(at, e);
            }
            return None;
        }
        Some((main.tpl, named_out))
    }

    /// The delay-slot checks of one section.
    fn note_delay(&mut self, ctor: CtorId, delay: u32, root: bool) {
        if delay == 0 {
            return;
        }
        if !root {
            let at = self.ctor_at(ctor);
            let info = self.ctor_info(ctor);
            self.diags.warning_at(
                at,
                format!("Delay slot used in non-root constructor {info}\n"),
            );
        }
        self.max_delay = self.max_delay.max(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_are_inserted_in_descending_order() {
        let mut tpl = Tpl::default();
        let mut check = vec![0, 2, 0];
        assert_eq!(fill_in_build(&mut tpl, &mut check), 0);
        let order: Vec<u64> = tpl
            .ops
            .iter()
            .map(|op| real(&op.inputs[0].offset))
            .collect();
        assert_eq!(order, vec![2, 0]);
        let mut check = vec![0];
        tpl.ops = vec![
            Op::new(BUILD, vec![Vn::constant(0, 4)]),
            Op::new(BUILD, vec![Vn::constant(0, 4)]),
        ];
        assert_eq!(fill_in_build(&mut tpl, &mut check), 1);
        let mut check = vec![2];
        tpl.ops = vec![Op::new(BUILD, vec![Vn::constant(0, 4)])];
        assert_eq!(fill_in_build(&mut tpl, &mut check), 2);
    }
}
