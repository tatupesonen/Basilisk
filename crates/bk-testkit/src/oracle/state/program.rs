//! The records of the state dump's sections from `@proto` on: prototypes,
//! call specs, jump tables, the local scope, heritage, highs, types, C.

use super::codec::{Addr, Dec, Flag, Hex, List, Opt, Text, record};
use super::ids::{
    CallRef, EntryStorage, HighRef, IndexPair, JumpRef, OracleRange, SeqNum, SymbolRef, TypeRef,
    VarnodeId,
};
use crate::oracle::graph::OracleAddress;

record! {
    /// `M`: a prototype (`FuncProto`).
    ProtoRecord = "M" {
        /// The model's name, or `-`.
        model: String = Text,
        /// `extrapop`; absent without a model (Ghidra leaves it
        /// uninitialised until `setModel`).
        extrapop: Option<i32> = Opt<Dec<i32>>,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `injectid`.
        inject_id: i32 = Dec<i32>,
        /// `returnBytesConsumed`.
        return_bytes_consumed: i32 = Dec<i32>,
    }
}

record! {
    /// `Q`: a parameter of the preceding prototype.
    ParamRecord = "Q" {
        /// `in` or `out`.
        direction: String = Text,
        /// Input position (0 for the output).
        index: i32 = Dec<i32>,
        /// The name.
        name: String = Text,
        /// Storage.
        addr: Option<OracleAddress> = Opt<Addr>,
        /// Size.
        size: i32 = Dec<i32>,
        /// Data type.
        data_type: Option<TypeRef> = Opt<TypeRef>,
        /// `t` type lock, `n` name lock, `z` size lock, `h` this, `i`
        /// indirect storage, `r` hidden return, `u` name undefined; or `-`.
        flags: String = Text,
    }
}

record! {
    /// `X` in a prototype: an effect record.
    EffectRecord = "X" {
        /// `EffectRecord::type`.
        kind: i32 = Dec<i32>,
        /// Storage.
        addr: OracleAddress = Addr,
        /// Size.
        size: i32 = Dec<i32>,
    }
}

record! {
    /// `Y` in a prototype: a likely-trash location.
    TrashRecord = "Y" {
        /// Storage.
        addr: OracleAddress = Addr,
        /// Size.
        size: i32 = Dec<i32>,
    }
}

record! {
    /// `A` in `@proto` and `@callspecs`: a `ParamActive`.
    ActiveRecord = "A" {
        /// `in` or `out`.
        direction: String = Text,
        /// `slotbase`.
        slot_base: i32 = Dec<i32>,
        /// `stackplaceholder`.
        stack_placeholder: i32 = Dec<i32>,
        /// `numpasses`.
        num_passes: i32 = Dec<i32>,
        /// `maxpass`.
        max_pass: i32 = Dec<i32>,
        /// `isfullychecked`.
        fully_checked: bool = Flag,
        /// `needsfinalcheck`.
        needs_final_check: bool = Flag,
        /// `recoversubcall`.
        recover_subcall: bool = Flag,
        /// `joinMostSigFirst`.
        join_most_sig_first: bool = Flag,
    }
}

record! {
    /// `T` after an `A`: a parameter trial.
    TrialRecord = "T" {
        /// Storage.
        addr: Option<OracleAddress> = Opt<Addr>,
        /// Size.
        size: i32 = Dec<i32>,
        /// `ParamTrial::flags`.
        flags: u32 = Hex<u32>,
        /// The model entry, by storage (`<space>:0x<base>:<size>`), or `-`.
        entry: String = Text,
        /// `slot`.
        slot: i32 = Dec<i32>,
        /// `offset`.
        offset: i32 = Dec<i32>,
        /// `fixedPosition`.
        fixed_position: i32 = Dec<i32>,
    }
}

record! {
    /// `C` in `@callspecs`: a call specification.
    CallSpecRecord = "C" {
        /// Its name.
        call: CallRef = CallRef,
        /// The call op.
        op: Option<SeqNum> = Opt<SeqNum>,
        /// The callee's name.
        name: String = Text,
        /// The callee's entry.
        entry: Option<OracleAddress> = Opt<Addr>,
        /// `effective_extrapop`.
        effective_extrapop: i32 = Dec<i32>,
        /// `stackoffset`.
        stack_offset: u64 = Hex<u64>,
        /// `stackPlaceholderSlot`.
        stack_placeholder_slot: i32 = Dec<i32>,
        /// `paramshift`.
        param_shift: i32 = Dec<i32>,
        /// `isinputactive`.
        input_active: bool = Flag,
        /// `isoutputactive`.
        output_active: bool = Flag,
        /// `isbadjumptable`.
        bad_jump_table: bool = Flag,
        /// `isstackoutputlock`.
        stack_output_lock: bool = Flag,
        /// `inputConsume`.
        input_consume: Vec<i32> = List<Dec<i32>>,
    }
}

record! {
    /// `J`: a jump table.
    JumpTableRecord = "J" {
        /// Its name.
        table: JumpRef = JumpRef,
        /// The `BRANCHIND`.
        op: Option<SeqNum> = Opt<SeqNum>,
        /// `opaddress`.
        op_address: Option<OracleAddress> = Opt<Addr>,
        /// `addresstable`.
        addresses: Vec<OracleAddress> = List<Addr>,
        /// `block2addr`: out-edge position and address index.
        block_to_address: Vec<IndexPair> = List<IndexPair>,
        /// `label`.
        labels: Vec<u64> = List<Hex<u64>>,
        /// `defaultBlock`.
        default_block: i32 = Dec<i32>,
        /// `lastBlock`.
        last_block: i32 = Dec<i32>,
        /// `switchVarConsume`.
        switch_var_consume: u64 = Hex<u64>,
        /// `recoverCount`.
        recover_count: i32 = Dec<i32>,
        /// `displayFormat`.
        display_format: u32 = Hex<u32>,
        /// `partialTable`.
        partial: bool = Flag,
        /// `collectloads`.
        collect_loads: bool = Flag,
        /// `defaultIsFolded`.
        default_is_folded: bool = Flag,
        /// The model's kind (`basic`, `basic2`, `basicoverride`, `assisted`, `trivial`, `-`).
        model: String = Text,
        /// The original model's kind.
        original_model: String = Text,
        /// `isOverride()`.
        is_override: bool = Flag,
    }
}

record! {
    /// `D` in `@jumptables`: a load table of the preceding jump table.
    LoadTableRecord = "D" {
        /// `addr`.
        addr: OracleAddress = Addr,
        /// `size`.
        size: i32 = Dec<i32>,
        /// `num`.
        num: i32 = Dec<i32>,
    }
}

record! {
    /// `Z` in `@scope`: the local scope.
    ScopeRecord = "Z" {
        /// Its name.
        name: String = Text,
        /// The stack space, or `-`.
        space: String = Text,
        /// `stackGrowsNegative`.
        stack_grows_negative: bool = Flag,
        /// `rangeLocked`.
        range_locked: bool = Flag,
        /// `overlapProblems`.
        overlap_problems: bool = Flag,
        /// `openParamRefs`.
        open_param_refs: bool = Flag,
        /// `minParamOffset`.
        min_param_offset: u64 = Hex<u64>,
        /// `maxParamOffset`.
        max_param_offset: u64 = Hex<u64>,
        /// `rangetree`.
        ranges: Vec<OracleRange> = List<OracleRange>,
    }
}

record! {
    /// `N`: a name recommendation.
    NameRecommendRecord = "N" {
        /// Storage.
        addr: Option<OracleAddress> = Opt<Addr>,
        /// Use point.
        use_addr: Option<OracleAddress> = Opt<Addr>,
        /// Size.
        size: i32 = Dec<i32>,
        /// Name.
        name: String = Text,
        /// Original symbol id.
        symbol_id: u64 = Hex<u64>,
    }
}

record! {
    /// `D` in `@scope`: a dynamic name recommendation.
    DynamicRecommendRecord = "D" {
        /// Use point.
        use_addr: Option<OracleAddress> = Opt<Addr>,
        /// Hash.
        hash: u64 = Hex<u64>,
        /// Name.
        name: String = Text,
        /// Original symbol id.
        symbol_id: u64 = Hex<u64>,
    }
}

record! {
    /// `Y` in `@scope`: a type recommendation.
    TypeRecommendRecord = "Y" {
        /// Storage.
        addr: Option<OracleAddress> = Opt<Addr>,
        /// Data type.
        data_type: Option<TypeRef> = Opt<TypeRef>,
    }
}

record! {
    /// `S` in `@scope`: a symbol.
    SymbolRecord = "S" {
        /// Its id.
        id: SymbolRef = SymbolRef,
        /// `name`.
        name: String = Text,
        /// `displayName`.
        display_name: String = Text,
        /// `type`.
        data_type: Option<TypeRef> = Opt<TypeRef>,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `dispflags`.
        disp_flags: u32 = Hex<u32>,
        /// `category`.
        category: i32 = Dec<i32>,
        /// `catindex`.
        cat_index: u32 = Dec<u32>,
        /// `nameDedup`.
        name_dedup: u32 = Dec<u32>,
        /// `function`, `equate`, `unionfacet`, `label`, `externref` or `symbol`.
        kind: String = Text,
        /// `wholeCount`.
        whole_count: u32 = Dec<u32>,
    }
}

record! {
    /// `M` in `@scope`: a map entry of the preceding symbol.
    MapEntryRecord = "M" {
        /// Storage.
        storage: EntryStorage = EntryStorage,
        /// `size`.
        size: i32 = Dec<i32>,
        /// `offset`.
        offset: i32 = Dec<i32>,
        /// `uselimit`.
        use_limit: Vec<OracleRange> = List<OracleRange>,
        /// `extraflags`.
        extra_flags: u32 = Hex<u32>,
        /// `properties`.
        properties: u32 = Hex<u32>,
    }
}

record! {
    /// `G`: a symbol of another scope that the function refers to.
    ForeignSymbolRecord = "G" {
        /// Its id.
        id: SymbolRef = SymbolRef,
        /// Its name.
        name: String = Text,
        /// Its scope's name.
        scope: String = Text,
        /// Its first entry's storage.
        storage: EntryStorage = EntryStorage,
    }
}

record! {
    /// `Z` in `@heritage`.
    HeritageRecord = "Z" {
        /// `pass`.
        pass: i32 = Dec<i32>,
        /// `maxdepth`.
        max_depth: i32 = Dec<i32>,
    }
}

record! {
    /// `I`: a heritaged space (`HeritageInfo`).
    HeritageInfoRecord = "I" {
        /// The space.
        space: String = Text,
        /// `delay`.
        delay: i32 = Dec<i32>,
        /// `deadcodedelay`.
        deadcode_delay: i32 = Dec<i32>,
        /// `deadremoved`.
        dead_removed: i32 = Dec<i32>,
        /// `loadGuardSearch`.
        load_guard_search: bool = Flag,
        /// `warningissued`.
        warning_issued: bool = Flag,
        /// `hasCallPlaceholders`.
        has_call_placeholders: bool = Flag,
    }
}

record! {
    /// `M` in `@heritage`: an entry of `globaldisjoint`.
    DisjointRecord = "M" {
        /// Start.
        addr: OracleAddress = Addr,
        /// Size.
        size: i32 = Dec<i32>,
        /// Pass.
        pass: i32 = Dec<i32>,
    }
}

record! {
    /// `L` in `@heritage`: a load or store guard.
    GuardRecord = "L" {
        /// `load` or `store`.
        kind: String = Text,
        /// The guarded op.
        op: Option<SeqNum> = Opt<SeqNum>,
        /// The space.
        space: String = Text,
        /// `pointerBase`.
        pointer_base: u64 = Hex<u64>,
        /// `minimumOffset`.
        minimum: u64 = Hex<u64>,
        /// `maximumOffset`.
        maximum: u64 = Hex<u64>,
        /// `step`.
        step: i32 = Dec<i32>,
        /// `analysisState`.
        state: i32 = Dec<i32>,
    }
}

record! {
    /// `C` in `@heritage`: `loadCopyOps`.
    LoadCopyRecord = "C" {
        /// The ops.
        ops: Vec<SeqNum> = List<SeqNum>,
    }
}

record! {
    /// `H`: a high variable.
    HighRecord = "H" {
        /// Its name.
        high: HighRef = HighRef,
        /// Members in `inst` order.
        members: Vec<VarnodeId> = List<VarnodeId>,
        /// `numMergeClasses`.
        merge_classes: i32 = Dec<i32>,
        /// `highflags`.
        high_flags: u32 = Hex<u32>,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `type` (a cache: see `high_flags`).
        data_type: Option<TypeRef> = Opt<TypeRef>,
        /// `nameRepresentative`.
        name_representative: Option<VarnodeId> = Opt<VarnodeId>,
        /// `symbol`.
        symbol: Option<SymbolRef> = Opt<SymbolRef>,
        /// `symboloffset`.
        symbol_offset: i32 = Dec<i32>,
        /// The piece: `<first high of the group>:<offset>:<size>:<group size>:<group symbol offset>`, or `-`.
        piece: String = Text,
    }
}

record! {
    /// `T`: a data type.
    TypeRecord = "T" {
        /// Its name in the dump.
        data_type: TypeRef = TypeRef,
        /// Ghidra's type id.
        id: u64 = Hex<u64>,
        /// Its metatype.
        metatype: String = Text,
        /// Its size.
        size: i32 = Dec<i32>,
        /// Its name.
        name: String = Text,
        /// `Datatype::encode`, on one line.
        xml: String = Text,
    }
}

record! {
    /// `C` in `@c`: a line of `print C`.
    CLineRecord = "C" {
        /// The line.
        line: String = Text,
    }
}
