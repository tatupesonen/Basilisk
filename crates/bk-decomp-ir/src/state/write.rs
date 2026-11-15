//! An [`Ssa`] written back into a dump: the sections this crate holds are
//! regenerated, the rest come from the dump it was loaded from.

use bk_core::Address;
use bk_testkit::oracle::StateDump;
use bk_testkit::oracle::graph::OracleAddress;
use bk_testkit::oracle::state::{
    BlockEntry, BlockRecord, BlockRef, CallRef, EdgeRecord, EntryRef as DumpEntry, HighRef,
    OpListRecord, OpRecord, OracleRange, OrderRecord, SeqNum as DumpSeq, SymbolRef, TypeRef,
    VarnodeId as DumpVn, VarnodeOffset, VarnodeRecord,
};

use super::{StateError, dangling, inconsistent};
use crate::bank::keys::{KeyParts, SEQ_MIN};
use crate::flags::oflags;
use crate::ids::{CallSpecId, OpId, VarnodeId};
use crate::print::RawNames;
use crate::ssa::{CodeList, Ssa};
use crate::varnode::OffsetKind;

/// The canonical key of call specs at the time of writing: a call spec's
/// position in `Funcdata::qlst`, or `None` when it is no longer there
/// (written `call:-`, sorting last). A loaded state's ids are their
/// positions, which [`CanonicalCalls::Identity`] gives.
#[derive(Clone, Debug, Default)]
pub enum CanonicalCalls {
    /// Every id is its own position; [`CallSpecId::DEAD`] is gone.
    #[default]
    Identity,
    /// Positions by id (D07's `qlst`).
    Positions(std::collections::HashMap<u32, u32>),
}

impl CanonicalCalls {
    fn position(&self, c: CallSpecId) -> Option<u32> {
        if c == CallSpecId::DEAD {
            return None;
        }
        match self {
            Self::Identity => Some(c.get()),
            Self::Positions(m) => m.get(&c.get()).copied(),
        }
    }
}

fn oaddr(ssa: &Ssa, a: Address) -> Result<OracleAddress, StateError> {
    let s = ssa
        .spaces
        .space_of(a)
        .ok_or_else(|| inconsistent("address without a space", format!("{a:?}")))?;
    Ok(OracleAddress {
        space: s.name().to_owned(),
        offset: a.offset(),
    })
}

fn seq(ssa: &Ssa, op: OpId) -> Result<DumpSeq, StateError> {
    let pc = ssa.op_addr(op);
    Ok(DumpSeq {
        addr: if pc.is_invalid() {
            None
        } else {
            Some(oaddr(ssa, pc)?)
        },
        time: u64::from(ssa.op_time(op)),
    })
}

fn vname(ssa: &Ssa, vn: VarnodeId) -> DumpVn {
    DumpVn(ssa.varnode_create_index(vn))
}

fn block_ref(ssa: &Ssa, n: crate::NodeId) -> Result<BlockRef, StateError> {
    let i = ssa.cfg.index(n).ok_or_else(|| dangling("block", n))?;
    u32::try_from(i)
        .map(BlockRef)
        .map_err(|_| StateError::Range {
            what: "block index",
            value: i.to_string(),
        })
}

fn varnode_record(ssa: &Ssa, vn: VarnodeId, calls: &CanonicalCalls) -> Result<VarnodeRecord, StateError> {
    let addr = ssa.varnode_addr(vn);
    let space = ssa
        .spaces
        .space_of(addr)
        .ok_or_else(|| inconsistent("varnode without a space", ssa.varnode_create_index(vn)))?;
    let offset = match ssa.varnode_offset_kind(vn) {
        OffsetKind::Plain(v) => VarnodeOffset::Plain(v),
        OffsetKind::Op(op) => VarnodeOffset::Op(seq(ssa, op)?),
        OffsetKind::Call(c) => match calls.position(c) {
            Some(k) => VarnodeOffset::Call(CallRef(k)),
            None => VarnodeOffset::DeadCall,
        },
        OffsetKind::Space(i) => VarnodeOffset::Space(
            ssa.spaces
                .space_at(i)
                .ok_or_else(|| dangling("space index", i))?
                .name()
                .to_owned(),
        ),
    };
    let readers = ssa
        .readers(vn)
        .into_iter()
        .map(|op| seq(ssa, op))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VarnodeRecord {
        id: vname(ssa, vn),
        space: space.name().to_owned(),
        offset,
        size: ssa.varnode_size(vn),
        flags: ssa.varnode_flags(vn),
        addl_flags: u32::from(ssa.varnode_addl(vn)),
        merge_group: i32::from(ssa.varnode_merge_group(vn)),
        def: ssa.varnode_def(vn).map(|op| seq(ssa, op)).transpose()?,
        readers,
        data_type: ssa.varnode_type(vn).map(|t| TypeRef(t.raw())),
        consumed: ssa.varnode_consume(vn),
        nzm: ssa.varnode_nzm(vn),
        high: ssa.varnode_high(vn).map(|h| HighRef(h.get())),
        entry: ssa.varnode_entry(vn).map(|e| DumpEntry {
            symbol: SymbolRef(e.symbol),
            position: e.position,
        }),
    })
}

/// The bank orders with the canonical keys (spec 4.2, D00 4.3): the
/// internal keys with an `fspec` offset replaced by its call spec's current
/// position (a gone one sorting last).
fn canonical_orders(ssa: &Ssa, calls: &CanonicalCalls) -> (Vec<DumpVn>, Vec<DumpVn>) {
    let mut keyed: Vec<(KeyParts, VarnodeId)> = ssa
        .loc_order()
        .filter_map(|vn| {
            let mut k = ssa.key_parts(vn)?;
            if let OffsetKind::Call(c) = ssa.varnode_offset_kind(vn)
                && let Some(s) = k.addr.space()
            {
                let key = calls.position(c).map_or(u64::MAX, u64::from);
                k.addr = Address::new(s, key);
            }
            Some((k, vn))
        })
        .collect();
    keyed.sort_by_key(|(k, _)| k.loc());
    let loc = keyed.iter().map(|(_, v)| vname(ssa, *v)).collect();
    keyed.sort_by_key(|(k, _)| k.def());
    let def = keyed.iter().map(|(_, v)| vname(ssa, *v)).collect();
    let _ = SEQ_MIN;
    (loc, def)
}

/// Writes `ssa` into a copy of `base` (the dump it was loaded from, or any
/// dump of the same function) and returns the dump's text.
pub fn write(
    ssa: &Ssa,
    base: &StateDump,
    names: &dyn RawNames,
    calls: &CanonicalCalls,
) -> Result<String, StateError> {
    let mut d = base.clone();
    let k = &mut d.function.counters;
    k.next_create_index = ssa.next_create_index();
    k.uniq_base = u64::from(ssa.unique_base());
    k.next_unique = u64::from(ssa.next_unique());
    k.next_op_time = u64::from(ssa.next_op_time());

    let mut vns: Vec<VarnodeId> = ssa.loc_order().collect();
    vns.sort_by_key(|&v| ssa.varnode_create_index(v));
    d.varnodes = vns
        .iter()
        .map(|&v| varnode_record(ssa, v, calls))
        .collect::<Result<_, _>>()?;
    let (loc, def) = canonical_orders(ssa, calls);
    d.loc_order = OrderRecord { varnodes: loc };
    d.def_order = OrderRecord { varnodes: def };

    let mut ops: Vec<OpId> = ssa.ops_main().chain(ssa.ops_alt()).collect();
    ops.sort_by_key(|&op| (ssa.op_addr(op), ssa.op_time(op)));
    d.ops = ops
        .iter()
        .map(|&op| {
            let inputs = ssa
                .op_inputs(op)
                .into_iter()
                .map(|v| {
                    v.map(|v| vname(ssa, v))
                        .ok_or_else(|| inconsistent("empty input slot", ssa.seq_text(op)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(OpRecord {
                seq: seq(ssa, op)?,
                order: ssa.op_order(op),
                opcode: ssa
                    .op_opcode(op)
                    .ok_or_else(|| inconsistent("op without opcode", ssa.seq_text(op)))?
                    .name()
                    .to_owned(),
                flags: ssa.op_flags(op),
                addl_flags: ssa.op_addl(op),
                output: ssa.op_output(op).map(|v| vname(ssa, v)),
                inputs,
                parent: ssa.op_parent(op).map(|b| block_ref(ssa, b)).transpose()?,
                liveness: if ssa.op_flags(op) & oflags::DEAD != 0 { "dead" } else { "alive" }
                    .to_owned(),
                tree: if ssa.op_in_alt_tree(op) { "alt" } else { "main" }.to_owned(),
                text: ssa.op_text(op, names),
            })
        })
        .collect::<Result<_, StateError>>()?;

    let list = |name: &str, ops: Vec<OpId>| -> Result<OpListRecord, StateError> {
        Ok(OpListRecord {
            name: name.to_owned(),
            ops: ops.into_iter().map(|o| seq(ssa, o)).collect::<Result<_, _>>()?,
        })
    };
    d.op_lists = vec![
        list("alive", ssa.ops_alive())?,
        list("dead", ssa.ops_dead())?,
        list("store", ssa.ops_of(CodeList::Store))?,
        list("load", ssa.ops_of(CodeList::Load))?,
        list("return", ssa.ops_of(CodeList::Return))?,
        list("userop", ssa.ops_of(CodeList::Userop))?,
    ];

    let mut blocks = Vec::new();
    for (pos, &n) in ssa.cfg.nodes().iter().enumerate() {
        let cover = ssa
            .block_ranges(n)
            .map(|c| {
                c.iter()
                    .map(|r| {
                        let space = ssa
                            .spaces
                            .space(r.space())
                            .map_or_else(String::new, |s| s.name().to_owned());
                        OracleRange {
                            space,
                            first: r.first(),
                            last: r.last(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let in_edges = ssa
            .ins(n)
            .into_iter()
            .map(|e| {
                Ok(EdgeRecord {
                    source: block_ref(ssa, e.node)?,
                    slot: e.rev as i32,
                    label: e.label,
                })
            })
            .collect::<Result<_, StateError>>()?;
        blocks.push(BlockEntry {
            block: BlockRecord {
                block: block_ref(ssa, n)?,
                position: pos as u32,
                flags: ssa.cfg.flags(n).unwrap_or(0),
                idom: ssa.cfg.idom(n).map(|i| block_ref(ssa, i)).transpose()?,
                numdesc: ssa.cfg.numdesc(n).unwrap_or(0),
                cover,
                ops: ssa
                    .block_ops(n)
                    .into_iter()
                    .map(|o| seq(ssa, o))
                    .collect::<Result<_, _>>()?,
            },
            in_edges,
        });
    }
    d.blocks = blocks;
    Ok(d.write())
}
