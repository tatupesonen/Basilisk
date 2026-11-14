//! Truncation fix-up (`ConsistencyChecker::testTruncations`,
//! `checkSectionTruncations`, `checkVarnodeTruncation`;
//! `VarnodeTpl::adjustTruncation`) and the consistency driver
//! (`SleighCompile::checkConsistency`).

use bk_sla::{ConstTpl, HandleSelect};

use super::CheckFatal;
use super::sizes::{Checker, section_mut};
use crate::compiler::Compiler;
use crate::ids::{CtorId, TableId};
use crate::template::{Op, Vn, real};

/// `adjustTruncation`: the final form of a truncated handle given the
/// size `size` of the operand and the endianness.
pub(crate) fn adjust_truncation(vn: &mut Vn, size: i32, big_endian: bool) -> bool {
    let ConstTpl::Real(bytes) = vn.size else {
        return false;
    };
    let ConstTpl::Handle { index, plus, .. } = vn.offset else {
        return false;
    };
    let num_bytes = bytes as i32;
    let byte_offset = plus as i32;
    if num_bytes.wrapping_add(byte_offset) > size {
        return false;
    }
    let mut value = (byte_offset as u64) << 16;
    if big_endian {
        value |= size.wrapping_sub(num_bytes.wrapping_add(byte_offset)) as u64;
    } else {
        value |= byte_offset as u64;
    }
    vn.offset = ConstTpl::Handle {
        index,
        select: HandleSelect::OffsetPlus,
        plus: value,
    };
    true
}

impl Compiler<'_> {
    /// `checkVarnodeTruncation` on `slot` of `op`.
    fn check_truncation(&mut self, checker: &Checker, op: &mut Op, slot: i32, ctor: CtorId) -> Result<bool, CheckFatal> {
        let Some(vn) = op.slot(slot).copied() else { return Ok(true) };
        let ConstTpl::Handle {
            select: HandleSelect::OffsetPlus,
            ..
        } = vn.offset
        else {
            return Ok(true);
        };
        if !matches!(vn.size, ConstTpl::Real(_) | ConstTpl::Handle { .. }) {
            self.op_error(op, ctor, slot, slot, "Bad truncation expression");
            return Ok(false);
        }
        let size = self.recover_size(checker, &vn.offset, ctor)?;
        if size <= 0 {
            self.op_error(op, ctor, slot, slot, "Could not recover size");
            return Ok(false);
        }
        let big = self.big_endian;
        let ok = op.slot_mut(slot).is_some_and(|v| adjust_truncation(v, size, big));
        if !ok {
            self.op_error(op, ctor, slot, slot, "Truncation operator out of bounds");
            return Ok(false);
        }
        Ok(true)
    }

    /// `testTruncations`.
    fn test_truncations(&mut self, checker: &Checker) -> Result<bool, CheckFatal> {
        let mut ok = true;
        for table in checker.postorder.clone() {
            for ctor in self.table_ctors(table) {
                let sections = self.ctors.get(ctor.slot()).map_or(0, |c| c.named.len() as i32);
                for k in -1..sections {
                    let Some(mut tpl) = self.ctors.get_mut(ctor.slot()).and_then(|c| section_mut(c, k)).map(std::mem::take) else {
                        continue;
                    };
                    let mut result = Ok(());
                    'ops: for op in &mut tpl.ops {
                        let inputs = op.inputs.len() as i32;
                        for slot in -1..inputs {
                            if slot == -1 && op.output.is_none() {
                                continue;
                            }
                            match self.check_truncation(checker, op, slot, ctor) {
                                Ok(passed) => ok &= passed,
                                Err(e) => {
                                    result = Err(e);
                                    break 'ops;
                                }
                            }
                        }
                    }
                    if let Some(slot) = self.ctors.get_mut(ctor.slot()).and_then(|c| section_mut(c, k)) {
                        *slot = tpl;
                    }
                    result?;
                }
            }
        }
        Ok(ok)
    }

    /// The constructors of a table.
    pub(crate) fn table_ctors(&self, table: TableId) -> Vec<CtorId> {
        self.tables.get(table.slot()).map(|t| t.ctors.clone()).unwrap_or_default()
    }

    /// `checkLargeTemporaries` over every section of the post order.
    fn test_large_temporaries(&mut self, checker: &Checker) {
        for table in checker.postorder.clone() {
            for ctor in self.table_ctors(table) {
                let Some(c) = self.ctors.get(ctor.slot()) else { continue };
                let big = |tpl: &crate::template::Tpl| {
                    tpl.ops.iter().any(|op| {
                        op.output.iter().chain(op.inputs.iter()).any(|v| v.is_local_temp() && real(&v.size) > 256)
                    })
                };
                let count = c.main.iter().chain(c.named.iter().flatten()).filter(|t| big(t)).count();
                let at = c.at;
                for _ in 0..count {
                    self.diags.error_at(at, "Constructor uses temporary varnode larger than 256 bytes.");
                }
            }
        }
    }

    /// `checkConsistency`.
    pub(crate) fn check_consistency(&mut self) -> Result<(), CheckFatal> {
        let mut checker = Checker::default();
        if !self.test_size_restrictions(&mut checker)? {
            return Ok(());
        }
        if !self.test_truncations(&checker)? {
            return Ok(());
        }
        if !self.options.warn_unnecessary_pcode && checker.unnecessary > 0 {
            self.diags.warning(None, format!("{} unnecessary extensions/truncations were converted to copies", checker.unnecessary));
            self.diags.warning(None, "Use -u switch to list each individually");
        }
        self.optimize_all(&mut checker)?;
        if checker.read_no_write > 0 {
            return Ok(());
        }
        if !self.options.warn_dead_temps && checker.write_no_read > 0 {
            self.diags.warning(None, format!("{} operations wrote to temporaries that were not read", checker.write_no_read));
            self.diags.warning(None, "Use -t switch to list each individually");
        }
        self.test_large_temporaries(&checker);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_is_encoded_by_endianness() {
        let mut vn = Vn::new(
            crate::template::handle(0, HandleSelect::Space),
            ConstTpl::Handle {
                index: 0,
                select: HandleSelect::OffsetPlus,
                plus: 1,
            },
            ConstTpl::Real(2),
        );
        let mut le = vn;
        assert!(adjust_truncation(&mut le, 4, false));
        assert_eq!(real(&le.offset), (1 << 16) | 1);
        assert!(adjust_truncation(&mut vn, 4, true));
        assert_eq!(real(&vn.offset), (1 << 16) | 1);
        let mut too_far = Vn {
            offset: ConstTpl::Handle {
                index: 0,
                select: HandleSelect::OffsetPlus,
                plus: 3,
            },
            ..vn
        };
        assert!(!adjust_truncation(&mut too_far, 4, false));
    }
}
