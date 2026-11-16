//! Whether an op's `setOpcode`-owned flag bits (`op.cc:299`–`308`) are the
//! opcode table's, up to the changes Ghidra makes afterwards:
//! `Funcdata::opMarkNoCollapse` adds `nocollapse` (`funcdata.hh:493`),
//! `markReturnCopy` adds `return_copy` to a `COPY` (`funcdata.hh:461`), and
//! the `stringdata` `CALLOTHER` loses `call` (`funcdata_varnode.cc:1497`).

use bk_decomp_ir::flags::oflags;
use bk_decomp_ir::props::props;
use bk_pcode::OpCode;

pub(crate) fn table_explains(opc: OpCode, flags: u32) -> bool {
    let want = props(opc).flags;
    let got = flags & oflags::OPCODE_BITS;
    let mut may_add = oflags::NOCOLLAPSE;
    if opc == OpCode::Copy {
        may_add |= oflags::RETURN_COPY;
    }
    let may_drop = if opc == OpCode::CallOther {
        oflags::CALL
    } else {
        0
    };
    got & !want & !may_add == 0 && want & !got & !may_drop == 0
}
