//! The records of the state dump, one struct per record kind
//! (`tools/reference/README.md`, "State dumps"). Field names follow
//! Ghidra's members.

use super::codec::{Addr, Dec, Flag, Hex, List, Opt, Text, Token, record};
use super::ids::{
    BlockRef, EntryRef, HighRef, OracleRange, SeqNum, TypeRef, VarnodeId, VarnodeOffset,
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
        min_laned_size: u32 = Dec<u32>,
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
        /// `count`; absent before the action first started (Ghidra leaves it
        /// uninitialised until then).
        count: Option<i32> = Opt<Dec<i32>>,
        /// `lcount`; absent until the action first went on from a start.
        lcount: Option<i32> = Opt<Dec<i32>>,
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

pub use super::program::*;
