//! The flag words of varnodes and ops, with Ghidra's numeric values (dumps
//! print the words in hexadecimal, so every bit keeps its value).

/// `Varnode::varnode_flags` (varnode.hh:79–115).
pub mod vflags {
    /// `mark`: prevents infinite loops.
    pub const MARK: u32 = 0x01;
    /// `constant`.
    pub const CONSTANT: u32 = 0x02;
    /// `annotation`: no data-flow.
    pub const ANNOTATION: u32 = 0x04;
    /// `input`: no ancestor.
    pub const INPUT: u32 = 0x08;
    /// `written`: has a defining op.
    pub const WRITTEN: u32 = 0x10;
    /// `insert`: inserted in the SSA tree.
    pub const INSERT: u32 = 0x20;
    /// `implied`: a temporary variable.
    pub const IMPLIED: u32 = 0x40;
    /// `explict`: cannot be a temporary.
    pub const EXPLICIT: u32 = 0x80;
    /// `typelock`.
    pub const TYPELOCK: u32 = 0x100;
    /// `namelock`.
    pub const NAMELOCK: u32 = 0x200;
    /// `nolocalalias`.
    pub const NOLOCALALIAS: u32 = 0x400;
    /// `volatil`.
    pub const VOLATILE: u32 = 0x800;
    /// `externref`.
    pub const EXTERNREF: u32 = 0x1000;
    /// `readonly`.
    pub const READONLY: u32 = 0x2000;
    /// `persist`.
    pub const PERSIST: u32 = 0x4000;
    /// `addrtied`.
    pub const ADDRTIED: u32 = 0x8000;
    /// `unaffected`.
    pub const UNAFFECTED: u32 = 0x10000;
    /// `spacebase`.
    pub const SPACEBASE: u32 = 0x20000;
    /// `indirectonly`.
    pub const INDIRECTONLY: u32 = 0x40000;
    /// `directwrite`.
    pub const DIRECTWRITE: u32 = 0x80000;
    /// `addrforce`.
    pub const ADDRFORCE: u32 = 0x10_0000;
    /// `mapped`.
    pub const MAPPED: u32 = 0x20_0000;
    /// `indirect_creation`.
    pub const INDIRECT_CREATION: u32 = 0x40_0000;
    /// `return_address`.
    pub const RETURN_ADDRESS: u32 = 0x80_0000;
    /// `coverdirty`.
    pub const COVERDIRTY: u32 = 0x100_0000;
    /// `precislo`.
    pub const PRECISLO: u32 = 0x200_0000;
    /// `precishi`.
    pub const PRECISHI: u32 = 0x400_0000;
    /// `indirectstorage`.
    pub const INDIRECTSTORAGE: u32 = 0x800_0000;
    /// `hiddenretparm`.
    pub const HIDDENRETPARM: u32 = 0x1000_0000;
    /// `incidental_copy`.
    pub const INCIDENTAL_COPY: u32 = 0x2000_0000;
    /// `autolive_hold`.
    pub const AUTOLIVE_HOLD: u32 = 0x4000_0000;
    /// `proto_partial`.
    pub const PROTO_PARTIAL: u32 = 0x8000_0000;
}

/// `Varnode::addl_flags` (varnode.hh:118–133).
pub mod vaddl {
    /// `activeheritage`.
    pub const ACTIVEHERITAGE: u16 = 0x01;
    /// `writemask`.
    pub const WRITEMASK: u16 = 0x02;
    /// `vacconsume`.
    pub const VACCONSUME: u16 = 0x04;
    /// `lisconsume`.
    pub const LISCONSUME: u16 = 0x08;
    /// `symcheck_incomplete`.
    pub const SYMCHECK_INCOMPLETE: u16 = 0x20;
    /// `symcheck_complete`.
    pub const SYMCHECK_COMPLETE: u16 = 0x30;
    /// `ptrflow`.
    pub const PTRFLOW: u16 = 0x40;
    /// `unsignedprint`.
    pub const UNSIGNEDPRINT: u16 = 0x80;
    /// `longprint`.
    pub const LONGPRINT: u16 = 0x100;
    /// `stack_store`.
    pub const STACK_STORE: u16 = 0x200;
    /// `locked_input`.
    pub const LOCKED_INPUT: u16 = 0x400;
    /// `spacebase_placeholder`.
    pub const SPACEBASE_PLACEHOLDER: u16 = 0x800;
    /// `stop_uppropagation`.
    pub const STOP_UPPROPAGATION: u16 = 0x1000;
    /// `has_implied_field`.
    pub const HAS_IMPLIED_FIELD: u16 = 0x2000;
}

/// `PcodeOp` flags (op.hh:72–106).
pub mod oflags {
    /// `startbasic`.
    pub const STARTBASIC: u32 = 1;
    /// `branch`.
    pub const BRANCH: u32 = 2;
    /// `call`.
    pub const CALL: u32 = 4;
    /// `returns`.
    pub const RETURNS: u32 = 0x8;
    /// `nocollapse`.
    pub const NOCOLLAPSE: u32 = 0x10;
    /// `dead`.
    pub const DEAD: u32 = 0x20;
    /// `marker`.
    pub const MARKER: u32 = 0x40;
    /// `booloutput`.
    pub const BOOLOUTPUT: u32 = 0x80;
    /// `boolean_flip`.
    pub const BOOLEAN_FLIP: u32 = 0x100;
    /// `fallthru_true`.
    pub const FALLTHRU_TRUE: u32 = 0x200;
    /// `indirect_source`.
    pub const INDIRECT_SOURCE: u32 = 0x400;
    /// `coderef`.
    pub const CODEREF: u32 = 0x800;
    /// `startmark`.
    pub const STARTMARK: u32 = 0x1000;
    /// `mark`.
    pub const MARK: u32 = 0x2000;
    /// `commutative`.
    pub const COMMUTATIVE: u32 = 0x4000;
    /// `unary`.
    pub const UNARY: u32 = 0x8000;
    /// `binary`.
    pub const BINARY: u32 = 0x10000;
    /// `special`.
    pub const SPECIAL: u32 = 0x20000;
    /// `ternary`.
    pub const TERNARY: u32 = 0x40000;
    /// `return_copy`.
    pub const RETURN_COPY: u32 = 0x80000;
    /// `nonprinting`.
    pub const NONPRINTING: u32 = 0x10_0000;
    /// `halt`.
    pub const HALT: u32 = 0x20_0000;
    /// `badinstruction`.
    pub const BADINSTRUCTION: u32 = 0x40_0000;
    /// `unimplemented`.
    pub const UNIMPLEMENTED: u32 = 0x80_0000;
    /// `noreturn`.
    pub const NORETURN: u32 = 0x100_0000;
    /// `missing`.
    pub const MISSING: u32 = 0x200_0000;
    /// `spacebase_ptr`.
    pub const SPACEBASE_PTR: u32 = 0x400_0000;
    /// `indirect_creation`.
    pub const INDIRECT_CREATION: u32 = 0x800_0000;
    /// `calculated_bool`.
    pub const CALCULATED_BOOL: u32 = 0x1000_0000;
    /// `has_callspec`.
    pub const HAS_CALLSPEC: u32 = 0x2000_0000;
    /// `ptrflow`.
    pub const PTRFLOW: u32 = 0x4000_0000;
    /// `indirect_store`.
    pub const INDIRECT_STORE: u32 = 0x8000_0000;

    /// The bits `PcodeOp::setOpcode` replaces with the new opcode's
    /// (op.cc:302–305).
    pub const OPCODE_BITS: u32 = BRANCH
        | CALL
        | CODEREF
        | COMMUTATIVE
        | RETURNS
        | NOCOLLAPSE
        | MARKER
        | BOOLOUTPUT
        | UNARY
        | BINARY
        | TERNARY
        | SPECIAL
        | HAS_CALLSPEC
        | RETURN_COPY;

    /// The halt bits (`getHaltType`).
    pub const HALT_BITS: u32 = HALT | BADINSTRUCTION | UNIMPLEMENTED | NORETURN | MISSING;
}

/// `PcodeOp` additional flags (op.hh:108–121).
pub mod oaddl {
    /// `special_prop`.
    pub const SPECIAL_PROP: u32 = 1;
    /// `special_print`.
    pub const SPECIAL_PRINT: u32 = 2;
    /// `modified` (the debug trace's mark; this crate's trace recorder keeps
    /// it in the recorder, never in the op).
    pub const MODIFIED: u32 = 4;
    /// `warning`.
    pub const WARNING: u32 = 8;
    /// `incidental_copy`.
    pub const INCIDENTAL_COPY: u32 = 0x10;
    /// `is_cpool_transformed`.
    pub const IS_CPOOL_TRANSFORMED: u32 = 0x20;
    /// `stop_type_propagation`.
    pub const STOP_TYPE_PROPAGATION: u32 = 0x40;
    /// `hold_output`.
    pub const HOLD_OUTPUT: u32 = 0x80;
    /// `concat_root`.
    pub const CONCAT_ROOT: u32 = 0x100;
    /// `no_indirect_collapse`.
    pub const NO_INDIRECT_COLLAPSE: u32 = 0x200;
    /// `store_unmapped`.
    pub const STORE_UNMAPPED: u32 = 0x400;
    /// `immed_copy`.
    pub const IMMED_COPY: u32 = 0x800;
    /// `store_aliasupdate`.
    pub const STORE_ALIASUPDATE: u32 = 0x1000;
}
