//! The result of decoding one instruction: a tree of constructor nodes with
//! offsets, lengths and resolved handles, and the pending context commits
//! (Ghidra `ParserContext`, `ConstructState`, `FixedHandle`, `ContextSet`).

use bk_core::{Address, SpaceId};
use bk_sla::{ConstructorId, SymbolId};

use super::bytes::Window;

/// "No node" / "no constructor" in the packed node fields.
pub(crate) const NONE: u32 = u32::MAX;

/// A resolved operand or export: a fixed varnode, or a pointer to one
/// (Ghidra `FixedHandle`). Spaces are space indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedHandle {
    /// The space of the varnode.
    pub space: u32,
    /// Its size in bytes.
    pub size: u32,
    /// For a dynamic handle, the space the pointer's value lives in;
    /// [`FixedHandle::NO_SPACE`] for a static one.
    pub offset_space: u32,
    /// The size of the pointer.
    pub offset_size: u32,
    /// The offset of a static varnode, or of the pointer.
    pub offset_offset: u64,
    /// The offset of the temporary that holds a loaded value.
    pub temp_offset: u64,
    /// The space of that temporary.
    pub temp_space: u32,
}

impl FixedHandle {
    /// The `offset_space` of a static handle.
    pub const NO_SPACE: u32 = u32::MAX;

    /// The handle of a node nothing has resolved: the constant 0.
    pub const UNSET: Self = Self {
        space: 0,
        size: 0,
        offset_space: Self::NO_SPACE,
        offset_size: 0,
        offset_offset: 0,
        temp_offset: 0,
        temp_space: 0,
    };

    /// A static varnode.
    pub const fn fixed(space: u32, offset: u64, size: u32) -> Self {
        Self {
            space,
            size,
            offset_space: Self::NO_SPACE,
            offset_size: 0,
            offset_offset: offset,
            temp_offset: 0,
            temp_space: 0,
        }
    }

    /// Whether the handle is a pointer whose target is computed at run time.
    pub const fn is_dynamic(&self) -> bool {
        self.offset_space != Self::NO_SPACE
    }

    /// The space as a [`SpaceId`].
    pub const fn space_id(&self) -> SpaceId {
        SpaceId::new(self.space)
    }
}

/// One constructor (or non-subtable operand) of the parse.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    pub(crate) ctor: u32,
    pub(crate) parent: u32,
    pub(crate) first_child: u32,
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) num_children: u16,
    pub(crate) visited: bool,
    pub(crate) handle: FixedHandle,
}

impl Node {
    pub(crate) const fn new(parent: u32) -> Self {
        Self {
            ctor: NONE,
            parent,
            first_child: NONE,
            offset: 0,
            length: 0,
            num_children: 0,
            visited: false,
            handle: FixedHandle::UNSET,
        }
    }

    /// The constructor chosen here; `None` for a non-subtable operand.
    pub fn constructor(&self) -> Option<ConstructorId> {
        (self.ctor != NONE).then(|| ConstructorId::new(self.ctor))
    }

    /// The node's first byte, from the start of the instruction.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// The node's length in bytes.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// The resolved handle (after [`Decoder::resolve_handles`](crate::Decoder::resolve_handles)).
    pub fn handle(&self) -> &FixedHandle {
        &self.handle
    }

    /// The number of operand children.
    pub fn num_children(&self) -> u32 {
        u32::from(self.num_children)
    }

    /// The index of child `i` in [`Parse::nodes`].
    pub fn child(&self, i: u32) -> Option<u32> {
        (i < u32::from(self.num_children)).then(|| self.first_child.wrapping_add(i))
    }

    /// The index of the parent node; `None` for the root.
    pub fn parent(&self) -> Option<u32> {
        (self.parent != NONE).then_some(self.parent)
    }
}

/// A pending `globalset` (Ghidra `ContextSet`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commit {
    /// The symbol whose handle gives the address.
    pub symbol: SymbolId,
    /// The node of the constructor that issued it.
    pub node: u32,
    /// The context word.
    pub word: u32,
    /// The bits committed.
    pub mask: u32,
    /// Their value, captured when the commit ran.
    pub value: u32,
    /// Whether the change flows forward.
    pub flow: bool,
}

/// How far a parse has been taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParseState {
    /// Nothing decoded.
    Empty,
    /// Constructors and lengths resolved (Ghidra `disassembly`).
    Resolved,
    /// Handles resolved too (Ghidra `pcode`).
    Handles,
}

/// One decoded instruction. Its buffers are reused from one instruction to
/// the next.
#[derive(Clone, Debug)]
pub struct Parse {
    pub(crate) state: ParseState,
    pub(crate) addr: Address,
    pub(crate) naddr: Address,
    pub(crate) next2: Option<Address>,
    /// Why `inst_next2` could not be computed (the next instruction's
    /// decode error, which Ghidra's `getN2addr` throws).
    pub(crate) next2_error: Option<crate::error::DecodeError>,
    pub(crate) delay_slot: u32,
    pub(crate) window: Window,
    pub(crate) context: Vec<u32>,
    pub(crate) nodes: Vec<Node>,
    pub(crate) commits: Vec<Commit>,
    pub(crate) overhang: std::cell::Cell<bool>,
    pub(crate) max_operands: u32,
}

impl Default for Parse {
    fn default() -> Self {
        Self::new()
    }
}

impl Parse {
    /// An empty parse.
    pub fn new() -> Self {
        Self {
            state: ParseState::Empty,
            addr: Address::INVALID,
            naddr: Address::INVALID,
            next2: None,
            next2_error: None,
            delay_slot: 0,
            window: Window::default(),
            context: Vec::new(),
            nodes: Vec::new(),
            commits: Vec::new(),
            overhang: std::cell::Cell::new(false),
            max_operands: 0,
        }
    }

    /// How far the parse has been taken.
    pub fn state(&self) -> ParseState {
        self.state
    }

    /// The instruction's address.
    pub fn address(&self) -> Address {
        self.addr
    }

    /// The address after the instruction (after its delay slots once
    /// [`Decoder::prepare`](crate::Decoder::prepare) has run).
    pub fn next_address(&self) -> Address {
        self.naddr
    }

    /// The instruction's length in bytes.
    pub fn length(&self) -> u32 {
        self.nodes.first().map_or(0, |root| root.length)
    }

    /// The delay-slot byte count (0 when the instruction has none).
    pub fn delay_slot(&self) -> u32 {
        self.delay_slot
    }

    /// The nodes; the root is node 0, and a node's operands are a contiguous
    /// run ([`Node::child`]).
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The root node.
    pub fn root(&self) -> Option<&Node> {
        self.nodes.first()
    }

    /// The pending context commits, in the order they ran.
    pub fn commits(&self) -> &[Commit] {
        &self.commits
    }

    /// The local context words as they stood when decoding finished.
    pub fn context(&self) -> &[u32] {
        &self.context
    }

    /// The 16 instruction bytes fetched.
    pub fn bytes(&self) -> &[u8] {
        self.window.bytes()
    }

    /// The constructors of every node, in node order.
    pub fn constructors(&self) -> impl Iterator<Item = ConstructorId> + '_ {
        self.nodes.iter().filter_map(Node::constructor)
    }

    /// Whether decoding used instruction bytes past index 15, which read as
    /// zero here and as whatever follows the buffer in Ghidra's C++.
    pub fn reads_past_window(&self) -> bool {
        self.overhang.get()
    }

    /// The largest number of operands of a constructor in the parse (Ghidra's
    /// C++ cannot decode more than 20).
    pub fn max_operands(&self) -> u32 {
        self.max_operands
    }

    pub(crate) fn set_next2(&mut self, found: Result<Address, crate::error::DecodeError>) {
        match found {
            Ok(addr) => {
                self.next2 = Some(addr);
                self.next2_error = None;
            }
            Err(e) => {
                self.next2 = None;
                self.next2_error = Some(e);
            }
        }
    }

    /// `inst_next2`, when it was computed.
    pub fn next2(&self) -> Option<Address> {
        self.next2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_structs_are_small() {
        assert!(size_of::<Node>() <= 64, "{}", size_of::<Node>());
        assert!(
            size_of::<FixedHandle>() <= 40,
            "{}",
            size_of::<FixedHandle>()
        );
        let node = Node::new(NONE);
        assert_eq!(node.parent(), None);
        assert_eq!(node.constructor(), None);
        assert_eq!(node.child(0), None);
        assert!(!FixedHandle::UNSET.is_dynamic());
        assert_eq!(Parse::new().length(), 0);
    }
}
