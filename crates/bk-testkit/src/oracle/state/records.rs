//! The records of the state dump, one struct per record kind
//! (`tools/reference/README.md`, "State dumps"). Field names follow
//! Ghidra's members.

use super::codec::{Addr, Dec, Flag, Hex, List, Opt, Text, Token, record};
use super::ids::{
    BlockRef, CallRef, EntryRef, EntryStorage, HighRef, IndexPair, JumpRef, OracleRange, SeqNum,
    SymbolRef, TypeRef, VarnodeId, VarnodeOffset,
};
use crate::oracle::graph::OracleAddress;

record! {
    /// `F`: the function (`Funcdata`).
    FunctionRecord = "F" {
        /// `name`.
        name: String = Text,
        /// `displayName`.
        display_name: String = Text,
        /// `baseaddr`.
        entry: OracleAddress = Addr,
        /// `size`.
        size: i32 = Dec<i32>,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `clean_up_index`.
        clean_up_index: u32 = Hex<u32>,
        /// `high_level_index`.
        high_level_index: u32 = Hex<u32>,
        /// `cast_phase_index`.
        cast_phase_index: u32 = Hex<u32>,
        /// `minLanedSize`.
        min_laned_size: i32 = Dec<i32>,
    }
}

record! {
    /// `K`: the counters that decide what is created next.
    CounterRecord = "K" {
        /// `vbank.create_index`: the next varnode's create index.
        next_create_index: u32 = Hex<u32>,
        /// `vbank.uniqbase`.
        uniq_base: u64 = Hex<u64>,
        /// `vbank.uniqid`: the next `unique` offset.
        next_unique: u64 = Hex<u64>,
        /// `obank.uniqid`: the next op time.
        next_op_time: u64 = Hex<u64>,
    }
}

record! {
    /// `W`: a comment of the function (warnings included).
    CommentRecord = "W" {
        /// `Comment::type`.
        kind: u32 = Hex<u32>,
        /// The address it is attached to.
        addr: Option<OracleAddress> = Opt<Addr>,
        /// `Comment::uniq`.
        uniq: i32 = Dec<i32>,
        /// The text.
        text: String = Text,
    }
}

record! {
    /// `O`: the function's local overrides, as `Override::encode` writes them.
    OverrideRecord = "O" {
        /// The XML, on one line.
        xml: String = Text,
    }
}

record! {
    /// `X` in `@function`: one entry of `lanedMap`.
    LanedRecord = "X" {
        /// The storage.
        addr: OracleAddress = Addr,
        /// Its size.
        size: i32 = Dec<i32>,
        /// `LanedRegister::wholeSize`.
        whole_size: i32 = Dec<i32>,
        /// `LanedRegister::sizeBitMask`.
        size_mask: u32 = Hex<u32>,
    }
}

record! {
    /// `U`: one entry of `unionMap`.
    UnionRecord = "U" {
        /// `ResolveEdge::typeId`.
        type_id: u64 = Hex<u64>,
        /// `ResolveEdge::opTime`.
        op_time: u64 = Hex<u64>,
        /// `ResolveEdge::encoding`.
        encoding: i32 = Dec<i32>,
        /// `ResolvedUnion::baseType`.
        base_type: Option<TypeRef> = Opt<TypeRef>,
        /// `ResolvedUnion::resolve`.
        resolve: Option<TypeRef> = Opt<TypeRef>,
        /// `ResolvedUnion::fieldNum`.
        field: i32 = Dec<i32>,
        /// `ResolvedUnion::lock`.
        lock: bool = Flag,
    }
}

record! {
    /// `A` in `@actions`: an action.
    ActionRecord = "A" {
        /// Position in `list action`.
        position: u32 = Dec<u32>,
        /// Full path.
        path: String = Text,
        /// `Action::status`.
        status: u32 = Hex<u32>,
        /// `count`.
        count: i32 = Dec<i32>,
        /// `lcount`.
        lcount: i32 = Dec<i32>,
        /// `count_tests`.
        count_tests: u32 = Dec<u32>,
        /// `count_apply`.
        count_apply: u32 = Dec<u32>,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `breakpoint`.
        breakpoint: u32 = Hex<u32>,
        /// Where a restart group, group or pool stands (`restart:<n>`,
        /// `child:<i>`, `op:<seqnum>/<rule index>`).
        state: Vec<String> = List<Token>,
    }
}

record! {
    /// `R` in `@actions`: a rule of a pool.
    RuleRecord = "R" {
        /// Position in `list action`.
        position: u32 = Dec<u32>,
        /// Full path.
        path: String = Text,
        /// `Rule::flags` (bit 0: disabled).
        flags: u32 = Hex<u32>,
        /// `count_tests`.
        count_tests: u32 = Dec<u32>,
        /// `count_apply`.
        count_apply: u32 = Dec<u32>,
        /// `breakpoint`.
        breakpoint: u32 = Hex<u32>,
    }
}

record! {
    /// `P`: an address space.
    SpaceRecord = "P" {
        /// Its index.
        index: i32 = Dec<i32>,
        /// Its name.
        name: String = Text,
        /// `spacetype`.
        kind: i32 = Dec<i32>,
        /// The shortcut character, or `-`.
        shortcut: String = Text,
        /// Word size.
        word_size: u32 = Dec<u32>,
        /// Address size.
        addr_size: u32 = Dec<u32>,
        /// `AddrSpace::flags`.
        flags: u32 = Hex<u32>,
        /// Heritage delay.
        delay: i32 = Dec<i32>,
        /// Dead-code delay.
        deadcode_delay: i32 = Dec<i32>,
    }
}

record! {
    /// `V`: a varnode.
    VarnodeRecord = "V" {
        /// Its name.
        id: VarnodeId = VarnodeId,
        /// Its space.
        space: String = Text,
        /// Its offset, pointers named.
        offset: VarnodeOffset = VarnodeOffset,
        /// `size`.
        size: i32 = Dec<i32>,
        /// `flags` (`varnode_flags`).
        flags: u32 = Hex<u32>,
        /// `addlflags`.
        addl_flags: u32 = Hex<u32>,
        /// `mergegroup`.
        merge_group: i32 = Dec<i32>,
        /// The defining op.
        def: Option<SeqNum> = Opt<SeqNum>,
        /// Reading ops in `descend` order.
        readers: Vec<SeqNum> = List<SeqNum>,
        /// The data type.
        data_type: Option<TypeRef> = Opt<TypeRef>,
        /// `consumed`.
        consumed: u64 = Hex<u64>,
        /// `nzm` (a pointer-valued constant's is its canonical key).
        nzm: u64 = Hex<u64>,
        /// The high variable.
        high: Option<HighRef> = Opt<HighRef>,
        /// The symbol entry.
        entry: Option<EntryRef> = Opt<EntryRef>,
    }
}

record! {
    /// `O` in `@locorder` and `@deforder`: a bank order.
    OrderRecord = "O" {
        /// Every varnode, in the order.
        varnodes: Vec<VarnodeId> = List<VarnodeId>,
    }
}

record! {
    /// `O` in `@ops`: a p-code op.
    OpRecord = "O" {
        /// Its sequence number.
        seq: SeqNum = SeqNum,
        /// `SeqNum::order` (position in its block).
        order: u32 = Dec<u32>,
        /// The opcode's name.
        opcode: String = Text,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `addlflags`.
        addl_flags: u32 = Hex<u32>,
        /// The output.
        output: Option<VarnodeId> = Opt<VarnodeId>,
        /// The inputs in slot order.
        inputs: Vec<VarnodeId> = List<VarnodeId>,
        /// The parent block.
        parent: Option<BlockRef> = Opt<BlockRef>,
        /// `alive` or `dead`.
        liveness: String = Text,
        /// `main` (`obank.optree`) or `alt` (`obank.alttree`).
        tree: String = Text,
        /// The op as `print raw` prints it.
        text: String = Text,
    }
}

record! {
    /// `L` in `@oplists`: one list of `PcodeOpBank`.
    OpListRecord = "L" {
        /// `alive`, `dead`, `store`, `load`, `return` or `userop`.
        name: String = Text,
        /// The ops in list order.
        ops: Vec<SeqNum> = List<SeqNum>,
    }
}

record! {
    /// `B`: a basic block.
    BlockRecord = "B" {
        /// Its name.
        block: BlockRef = BlockRef,
        /// Its position in `bblocks`.
        position: u32 = Dec<u32>,
        /// `flags`.
        flags: u32 = Hex<u32>,
        /// `immed_dom`.
        idom: Option<BlockRef> = Opt<BlockRef>,
        /// `numdesc`.
        numdesc: i32 = Dec<i32>,
        /// `BlockBasic::cover`.
        cover: Vec<OracleRange> = List<OracleRange>,
        /// Its ops in block order.
        ops: Vec<SeqNum> = List<SeqNum>,
    }
}

record! {
    /// `E`: an in-edge of the preceding block.
    EdgeRecord = "E" {
        /// The source block.
        source: BlockRef = BlockRef,
        /// The source's out-slot.
        slot: i32 = Dec<i32>,
        /// The label.
        label: u32 = Hex<u32>,
    }
}

record! {
    /// `M`: a prototype (`FuncProto`).
    ProtoRecord = "M" {
        /// The model's name, or `-`.
        model: String = Text,
        /// `extrapop`.
        extrapop: i32 = Dec<i32>,
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
        /// `matchCallCount`.
        match_call_count: i32 = Dec<i32>,
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
