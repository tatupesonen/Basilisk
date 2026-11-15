//! Per-function overrides (Ghidra `Override` and its record kinds;
//! override.cc; spec 4.17). Applying them to a function is D07's and D09's.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bk_core::{Address, SpaceId, SpaceManager};
use bk_cspec::FuncProto;
use bk_marshal::ids::{ATTRIB_SPACE, ATTRIB_TYPE};
use bk_marshal::{Decoder, Encoder};

use crate::error::{Result, SymbolError};
use crate::ids::{
    ELEM_CALLDEST, ELEM_DEADCODEDELAY, ELEM_FLOW, ELEM_FLOWOVERRIDELIST, ELEM_FORCEGOTO,
    ELEM_MULTISTAGEJUMP, ELEM_OVERRIDE, ELEM_PROTOOVERRIDE,
};

/// One p-code override record (Ghidra `Override::Record` subclasses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OverrideRecord {
    /// `branch`: a call or return becomes a branch.
    Branch,
    /// `call`: a branch or return becomes a call.
    Call,
    /// `callreturn`: a branch becomes a call followed by a return.
    CallReturn,
    /// `return`: an indirect branch or call becomes a return.
    Return,
    /// `callother_call`: a user op becomes a call to the address.
    CallotherCall(Address),
    /// `callother_branch`: a user op becomes a branch to the address.
    CallotherBranch(Address),
    /// `call_call`: a call goes to a new address.
    CallCall(Address),
}

impl OverrideRecord {
    /// Ghidra `allocateFlow`.
    pub fn flow(name: &str) -> Result<Self> {
        Ok(match name {
            "branch" => Self::Branch,
            "call" => Self::Call,
            "callreturn" => Self::CallReturn,
            "return" => Self::Return,
            _ => return Err(SymbolError::UnknownFlowOverride { name: name.to_owned() }),
        })
    }

    /// Ghidra `allocateCallDest`.
    pub fn call_dest(name: &str, dest: Address) -> Result<Self> {
        Ok(match name {
            "callother_call" => Self::CallotherCall(dest),
            "callother_branch" => Self::CallotherBranch(dest),
            "call_call" => Self::CallCall(dest),
            _ => return Err(SymbolError::UnknownCallDestOverride { name: name.to_owned() }),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Branch => "branch",
            Self::Call => "call",
            Self::CallReturn => "callreturn",
            Self::Return => "return",
            Self::CallotherCall(_) => "callother_call",
            Self::CallotherBranch(_) => "callother_branch",
            Self::CallCall(_) => "call_call",
        }
    }

    /// Ghidra `Record::printRaw`.
    fn print_raw(self, s: &mut String, addr: Address, spaces: &SpaceManager) {
        let a = addr.raw(spaces);
        let _ = match self {
            Self::Branch => writeln!(s, "override CALL, CALLIND, or RETURN at {a} to a BRANCH"),
            Self::Call => writeln!(s, "override BRANCH, BRANCHIND, or RETURN at {a} to a CALL"),
            Self::CallReturn => writeln!(s, "override BRANCH, BRANCHIND, or RETURN at {a} to a CALL followed by a RETURN"),
            Self::Return => writeln!(s, "override BRANCHIND or CALLIND at {a} to a RETURN"),
            Self::CallotherCall(d) => writeln!(s, "override CALLOTHER at {a} to CALL directly to {}", d.raw(spaces)),
            Self::CallotherBranch(d) => writeln!(s, "override CALLOTHER at {a} to BRANCH directly to {}", d.raw(spaces)),
            Self::CallCall(d) => writeln!(s, "override CALL at {a} to call to a new address {}", d.raw(spaces)),
        };
    }

    fn encode(self, enc: &mut dyn Encoder, addr: Address, spaces: &SpaceManager) -> Result<()> {
        let dest = match self {
            Self::CallotherCall(d) | Self::CallotherBranch(d) | Self::CallCall(d) => Some(d),
            _ => None,
        };
        let el = if dest.is_some() { ELEM_CALLDEST } else { ELEM_FLOW };
        enc.open_element(el);
        enc.write_string(ATTRIB_TYPE, self.name())?;
        addr.encode(enc, spaces)?;
        if let Some(d) = dest {
            d.encode(enc, spaces)?;
        }
        enc.close_element(el);
        Ok(())
    }
}

/// How prototype overrides are written, read and printed (`bk-cspec`'s
/// `FuncProto` codec needs the compiler spec and types; D07 supplies it).
pub trait ProtoCodec {
    /// Writes the prototype (Ghidra `FuncProto::encode`).
    fn encode(&self, proto: &FuncProto, enc: &mut dyn Encoder) -> Result<()>;
    /// Reads a prototype marked as an override (Ghidra `setInternal`,
    /// `decode`, `setOverride`).
    fn decode(&self, dec: &mut dyn Decoder<'_>) -> Result<FuncProto>;
    /// Ghidra `FuncProto::printRaw("func", s)`.
    fn print_raw(&self, proto: &FuncProto) -> String;
}

/// The overrides of one function (Ghidra `Override`).
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    /// Forced gotos: branch address to destination.
    pub force_goto: BTreeMap<Address, Address>,
    /// Dead-code delay per space index, −1 for none.
    pub deadcode_delay: Vec<i32>,
    /// Indirect calls made direct: call address to destination.
    pub deindirect: BTreeMap<Address, Address>,
    /// Prototype overrides at call sites.
    pub proto: BTreeMap<Address, FuncProto>,
    /// Addresses of multistage jump tables (duplicates kept).
    pub multistage_jump: Vec<Address>,
    /// P-code overrides by address.
    pub pcode: BTreeMap<Address, OverrideRecord>,
}

impl Overrides {
    /// Ghidra `clear`.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Whether nothing is overridden (Ghidra `encode`'s test).
    pub fn is_empty(&self) -> bool {
        self.force_goto.is_empty()
            && self.deadcode_delay.is_empty()
            && self.deindirect.is_empty()
            && self.proto.is_empty()
            && self.multistage_jump.is_empty()
            && self.pcode.is_empty()
    }

    /// Ghidra `insertForceGoto`.
    pub fn insert_force_goto(&mut self, target: Address, dest: Address) {
        self.force_goto.insert(target, dest);
    }

    /// Ghidra `insertDeadcodeDelay`.
    pub fn insert_deadcode_delay(&mut self, space: SpaceId, delay: i32) {
        let i = space.index() as usize;
        if self.deadcode_delay.len() <= i {
            self.deadcode_delay.resize(i + 1, -1);
        }
        if let Some(slot) = self.deadcode_delay.get_mut(i) {
            *slot = delay;
        }
    }

    /// Ghidra `hasDeadcodeDelay`: a set delay that differs from the
    /// space's own.
    pub fn has_deadcode_delay(&self, space: SpaceId, spaces: &SpaceManager) -> bool {
        match self.deadcode_delay.get(space.index() as usize) {
            Some(&-1) | None => false,
            Some(&v) => spaces.space(space).is_none_or(|s| v != s.deadcode_delay()),
        }
    }

    /// Ghidra `insertDeindirect`.
    pub fn insert_deindirect(&mut self, call: Address, direct: Address) {
        self.deindirect.insert(call, direct);
    }

    /// Ghidra `insertProtoOverride` (replaces an earlier one).
    pub fn insert_proto_override(&mut self, call: Address, proto: FuncProto) {
        self.proto.insert(call, proto);
    }

    /// Ghidra `insertMultistageJump`.
    pub fn insert_multistage_jump(&mut self, addr: Address) {
        self.multistage_jump.push(addr);
    }

    /// Ghidra `queryMultistageJumptable`.
    pub fn query_multistage_jumptable(&self, addr: Address) -> bool {
        self.multistage_jump.contains(&addr)
    }

    /// Ghidra `insertFlowOverride`.
    pub fn insert_flow_override(&mut self, addr: Address, kind: &str) -> Result<()> {
        self.pcode.insert(addr, OverrideRecord::flow(kind)?);
        Ok(())
    }

    /// Ghidra `insertDestinationOverride`.
    pub fn insert_destination_override(&mut self, addr: Address, dest: Address, kind: &str) -> Result<()> {
        self.pcode.insert(addr, OverrideRecord::call_dest(kind, dest)?);
        Ok(())
    }

    /// Ghidra `getPCodeOverride`.
    pub fn pcode_override(&self, addr: Address) -> Option<OverrideRecord> {
        self.pcode.get(&addr).copied()
    }

    /// Ghidra `printRaw`.
    pub fn print_raw(&self, spaces: &SpaceManager, protos: &dyn ProtoCodec) -> String {
        let mut s = String::new();
        for (a, b) in &self.force_goto {
            let _ = writeln!(s, "force goto at {} jumping to {}", a.raw(spaces), b.raw(spaces));
        }
        for (i, &d) in self.deadcode_delay.iter().enumerate() {
            if d < 0 {
                continue;
            }
            let name = spaces.space_at(i as u32).map_or("", bk_core::Space::name);
            let _ = writeln!(s, "dead code delay on {name} set to {d}");
        }
        for (a, b) in &self.deindirect {
            let _ = writeln!(s, "override indirect at {} to call directly to {}", a.raw(spaces), b.raw(spaces));
        }
        for (a, r) in &self.pcode {
            r.print_raw(&mut s, *a, spaces);
        }
        for (a, p) in &self.proto {
            let _ = writeln!(s, "override prototype at {} to {}", a.raw(spaces), protos.print_raw(p));
        }
        s
    }

    /// Ghidra `generateOverrideMessages`.
    pub fn override_messages(&self, spaces: &SpaceManager) -> Vec<String> {
        self.deadcode_delay
            .iter()
            .enumerate()
            .filter(|(_, d)| **d >= 0)
            .map(|(i, _)| {
                let name = spaces.space_at(i as u32).map_or("", bk_core::Space::name);
                format!("Restarted to delay deadcode elimination for space: {name}")
            })
            .collect()
    }

    /// Ghidra `encode`: nothing when empty, else `<override>`.
    pub fn encode(&self, enc: &mut dyn Encoder, spaces: &SpaceManager, protos: &dyn ProtoCodec) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        enc.open_element(ELEM_OVERRIDE);
        for (a, b) in &self.force_goto {
            enc.open_element(ELEM_FORCEGOTO);
            a.encode(enc, spaces)?;
            b.encode(enc, spaces)?;
            enc.close_element(ELEM_FORCEGOTO);
        }
        for (i, &d) in self.deadcode_delay.iter().enumerate() {
            if d < 0 {
                continue;
            }
            let Some(space) = spaces.space_at(i as u32) else { continue };
            enc.open_element(ELEM_DEADCODEDELAY);
            enc.write_space(ATTRIB_SPACE, &space.marshal_ref());
            enc.write_signed(bk_core::ids::ATTRIB_DELAY, i64::from(d));
            enc.close_element(ELEM_DEADCODEDELAY);
        }
        for (a, p) in &self.proto {
            enc.open_element(ELEM_PROTOOVERRIDE);
            a.encode(enc, spaces)?;
            protos.encode(p, enc)?;
            enc.close_element(ELEM_PROTOOVERRIDE);
        }
        for a in &self.multistage_jump {
            enc.open_element(ELEM_MULTISTAGEJUMP);
            a.encode(enc, spaces)?;
            enc.close_element(ELEM_MULTISTAGEJUMP);
        }
        for (a, r) in &self.pcode {
            r.encode(enc, *a, spaces)?;
        }
        enc.close_element(ELEM_OVERRIDE);
        Ok(())
    }

    /// Ghidra `decode`; unknown children are skipped, as in Ghidra.
    pub fn decode(&mut self, dec: &mut dyn Decoder<'_>, spaces: &SpaceManager, protos: &dyn ProtoCodec) -> Result<()> {
        let el = dec.open_element_expecting(ELEM_OVERRIDE)?;
        while let Some(sub) = dec.open_element()? {
            if sub == ELEM_PROTOOVERRIDE.code() {
                let call = Address::decode(dec, spaces)?;
                let proto = protos.decode(dec)?;
                self.insert_proto_override(call, proto);
            } else if sub == ELEM_FORCEGOTO.code() {
                let target = Address::decode(dec, spaces)?;
                let dest = Address::decode(dec, spaces)?;
                self.insert_force_goto(target, dest);
            } else if sub == ELEM_DEADCODEDELAY.code() {
                let delay = dec.read_signed_attr(bk_core::ids::ATTRIB_DELAY)?;
                let space = dec.read_space_attr(ATTRIB_SPACE)?;
                if delay < 0 {
                    return Err(SymbolError::DeadcodeDelay);
                }
                self.insert_deadcode_delay(space, i32::try_from(delay).unwrap_or(i32::MAX));
            } else if sub == ELEM_MULTISTAGEJUMP.code() {
                let a = Address::decode(dec, spaces)?;
                self.insert_multistage_jump(a);
            } else if sub == ELEM_FLOW.code() {
                let kind = dec.read_string_attr(ATTRIB_TYPE)?.to_owned();
                let addr = Address::decode(dec, spaces)?;
                if addr.is_invalid() {
                    return Err(SymbolError::FlowAddress);
                }
                self.insert_flow_override(addr, &kind)?;
            } else if sub == ELEM_CALLDEST.code() {
                let kind = dec.read_string_attr(ATTRIB_TYPE)?.to_owned();
                let addr = Address::decode(dec, spaces)?;
                let dest = Address::decode(dec, spaces)?;
                if addr.is_invalid() || dest.is_invalid() {
                    return Err(SymbolError::DestinationAddress);
                }
                self.insert_destination_override(addr, dest, &kind)?;
            } else {
                dec.close_element_skipping(sub)?;
                continue;
            }
            dec.close_element(sub)?;
        }
        dec.close_element(el)?;
        Ok(())
    }
}

/// Ghidra `Architecture::decodeFlowOverride`: the `(function address,
/// override address, record)` triples of a `<flowoverridelist>`, for the
/// caller to deliver to the functions found at those addresses.
pub fn decode_flow_override_list(dec: &mut dyn Decoder<'_>, spaces: &SpaceManager) -> Result<Vec<(Address, Address, OverrideRecord)>> {
    let el = dec.open_element_expecting(ELEM_FLOWOVERRIDELIST)?;
    let mut out = Vec::new();
    while dec.peek_element() == Some(ELEM_FLOW.code()) || dec.peek_element() == Some(ELEM_CALLDEST.code()) {
        let sub = dec.open_element()?.ok_or(SymbolError::FlowAddress)?;
        let kind = dec.read_string_attr(ATTRIB_TYPE)?.to_owned();
        let func = Address::decode(dec, spaces)?;
        let over = Address::decode(dec, spaces)?;
        let record = if sub == ELEM_FLOW.code() {
            OverrideRecord::flow(&kind)?
        } else {
            let dest = Address::decode(dec, spaces)?;
            OverrideRecord::call_dest(&kind, dest)?
        };
        out.push((func, over, record));
        dec.close_element(sub)?;
    }
    dec.close_element(el)?;
    Ok(out)
}
