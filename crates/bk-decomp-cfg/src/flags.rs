//! Node flags, edge labels, node kinds and the condition opcode.
//!
//! Ghidra: `FlowBlock::block_flags`, `FlowBlock::edge_flags` and
//! `FlowBlock::block_type` (block.hh:80–124), `FlowBlock::typeToName` and
//! `nameToType` (block.cc:661–712). Every bit keeps Ghidra's value, because
//! dumps print the words in hexadecimal.

/// Boolean properties of a node (`FlowBlock::block_flags`), as a bit word.
pub mod node_flags {
    /// The node ends in a non-structured branch (`f_goto_goto`); also the
    /// goto type of a goto node.
    pub const GOTO_GOTO: u32 = 1;
    /// The node ends with a `break` (`f_break_goto`).
    pub const BREAK_GOTO: u32 = 2;
    /// The node ends with a `continue` (`f_continue_goto`; never assigned by
    /// this Ghidra version).
    pub const CONTINUE_GOTO: u32 = 4;
    /// The node's output is decided by a switch (`f_switch_out`).
    pub const SWITCH_OUT: u32 = 0x10;
    /// The node is the destination of an unstructured goto
    /// (`f_unstructured_targ`).
    pub const UNSTRUCTURED_TARG: u32 = 0x20;
    /// Generic working mark (`f_mark`).
    pub const MARK: u32 = 0x80;
    /// Secondary working mark (`f_mark2`).
    pub const MARK2: u32 = 0x100;
    /// The official entry point of the function (`f_entry_point`).
    pub const ENTRY_POINT: u32 = 0x200;
    /// An unstructured jump leaves the node's interior (`f_interior_gotoout`).
    pub const INTERIOR_GOTOOUT: u32 = 0x400;
    /// An unstructured jump enters the node's interior (`f_interior_gotoin`).
    pub const INTERIOR_GOTOIN: u32 = 0x800;
    /// Labels of the node are printed higher up (`f_label_bumpup`).
    pub const LABEL_BUMPUP: u32 = 0x1000;
    /// The node does nothing in an infinite loop (`f_donothing_loop`).
    pub const DONOTHING_LOOP: u32 = 0x2000;
    /// The node is being deleted (`f_dead`).
    pub const DEAD: u32 = 0x4000;
    /// The condition of a while-do is printed in overflow syntax
    /// (`f_whiledo_overflow`).
    pub const WHILEDO_OVERFLOW: u32 = 0x8000;
    /// The out-edges were swapped since the path was last traced
    /// (`f_flip_path`).
    pub const FLIP_PATH: u32 = 0x1_0000;
    /// The node is a merged form of basic blocks (`f_joined_block`).
    pub const JOINED_BLOCK: u32 = 0x2_0000;
    /// The node is a duplicated basic block (`f_duplicate_block`).
    pub const DUPLICATE_BLOCK: u32 = 0x4_0000;
    /// Removal of a do-nothing node was delayed (`f_delayed_donothing`).
    pub const DELAYED_DONOTHING: u32 = 0x8_0000;
    /// The final transform has run (`f_final_transform`).
    pub const FINAL_TRANSFORM: u32 = 0x10_0000;
}

/// Boolean properties of an edge (`FlowBlock::edge_flags`), as a bit word.
/// Both halves of an edge carry the same label.
pub mod edge_labels {
    /// The edge is unstructured (`f_goto_edge`).
    pub const GOTO: u32 = 1;
    /// The edge completes a loop; removing these gives a DAG (`f_loop_edge`).
    pub const LOOP: u32 = 2;
    /// The default edge of a switch (`f_defaultswitch_edge`).
    pub const DEFAULT_SWITCH: u32 = 4;
    /// An edge that must be removed to make the graph reducible
    /// (`f_irreducible`).
    pub const IRREDUCIBLE: u32 = 8;
    /// An edge of the spanning tree (`f_tree_edge`).
    pub const TREE: u32 = 0x10;
    /// A forward edge of the spanning tree (`f_forward_edge`).
    pub const FORWARD: u32 = 0x20;
    /// A cross edge of the spanning tree (`f_cross_edge`).
    pub const CROSS: u32 = 0x40;
    /// A back edge defining a loop (`f_back_edge`).
    pub const BACK: u32 = 0x80;
    /// The edge exits the body of a loop (`f_loop_exit_edge`).
    pub const LOOP_EXIT: u32 = 0x100;
    /// Copy propagation crossed the edge (`f_immed_copy`).
    pub const IMMED_COPY: u32 = 0x200;

    /// Labels that keep an edge from being a *decision* edge
    /// (`isDecisionOut`, block.hh:348).
    pub const NOT_DECISION: u32 = IRREDUCIBLE | BACK | GOTO;
    /// Labels that keep an edge out of the loop DAG (`isLoopDAGOut`,
    /// block.hh:354).
    pub const NOT_LOOP_DAG: u32 = IRREDUCIBLE | BACK | LOOP_EXIT | GOTO;
    /// Labels that make an edge unstructured (`isGotoOut`, block.hh:359).
    pub const ANY_GOTO: u32 = IRREDUCIBLE | GOTO;
}

/// The kind of a node (`FlowBlock::block_type`, with `t_basic` and
/// `t_plain` folded into [`Kind::Plain`] for nodes of a [`Cfg`](crate::Cfg)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A plain or basic block of the input graph (`t_plain`, `t_basic`).
    Plain,
    /// The working copy of an input node (`BlockCopy`, `t_copy`).
    Copy,
    /// A node ending in an unstructured branch (`BlockGoto`, `t_goto`).
    Goto,
    /// A node with several out-edges of which some are gotos
    /// (`BlockMultiGoto`, `t_multigoto`).
    MultiGoto,
    /// A sequence (`BlockList`, `t_ls`).
    List,
    /// Two conditions joined by `&&` or `||` (`BlockCondition`,
    /// `t_condition`).
    Condition,
    /// An `if` without `else` (`BlockIf`, `t_if`).
    If,
    /// An `if` with `else` (`BlockIfElse`, `t_ifelse`).
    IfElse,
    /// An `if` whose two bodies do not exit (`BlockIfNoExit`, `t_ifnoexit`).
    IfNoExit,
    /// An `if` whose true branch is a goto (`BlockIfGoto`, `t_ifgoto`).
    IfGoto,
    /// A loop tested at the top (`BlockWhileDo`, `t_whiledo`).
    WhileDo,
    /// A loop tested at the bottom (`BlockDoWhile`, `t_dowhile`).
    DoWhile,
    /// A loop without exit (`BlockInfLoop`, `t_infloop`).
    InfLoop,
    /// A switch (`BlockSwitch`, `t_switch`).
    Switch,
}

impl Kind {
    /// Ghidra's name for the kind as `BlockGraph::encodeBody` writes it
    /// (`FlowBlock::typeToName`, block.cc:675): `ifnoexit` is written as
    /// `"ifelse"` and `if` as `"properif"`. A plain node is `"plain"`.
    pub const fn type_name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Copy => "copy",
            Self::Goto => "goto",
            Self::MultiGoto => "multigoto",
            Self::List => "list",
            Self::Condition => "condition",
            Self::If => "properif",
            Self::IfElse | Self::IfNoExit => "ifelse",
            Self::IfGoto => "ifgoto",
            Self::WhileDo => "whiledo",
            Self::DoWhile => "dowhile",
            Self::InfLoop => "infloop",
            Self::Switch => "switch",
        }
    }

    /// The kind's name in the structure dump of the oracle
    /// (`docs/features/decomp-oracle.md` 4.7), which keeps `ifnoexit`
    /// distinct and calls `t_if` `if`.
    pub const fn dump_name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Copy => "copy",
            Self::Goto => "goto",
            Self::MultiGoto => "multigoto",
            Self::List => "list",
            Self::Condition => "condition",
            Self::If => "if",
            Self::IfElse => "ifelse",
            Self::IfNoExit => "ifnoexit",
            Self::IfGoto => "ifgoto",
            Self::WhileDo => "whiledo",
            Self::DoWhile => "dowhile",
            Self::InfLoop => "infloop",
            Self::Switch => "switch",
        }
    }

    /// Whether the kind is a structured node with components
    /// (a `BlockGraph` subclass).
    pub const fn is_structured(self) -> bool {
        !matches!(self, Self::Plain | Self::Copy)
    }
}

/// `FlowBlock::nameToType` (block.cc:661): only `graph` and `copy` are
/// known; every other name is a plain block. Returns `None` for `graph`.
pub(crate) fn name_to_kind(name: &str) -> Option<Kind> {
    match name {
        "graph" => None,
        "copy" => Some(Kind::Copy),
        _ => Some(Kind::Plain),
    }
}

/// The boolean operation stored by a condition node (`BlockCondition::opc`).
///
/// Created as `INT_OR` or `INT_AND`, toggled between `BOOL_AND` and
/// `BOOL_OR` by negation (block.cc:1790, 3091); the value is reproduced as
/// stored (`docs/features/decomp-cfg.md` 4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CondOp {
    /// `CPUI_INT_OR`, given at creation when the second block is the
    /// first's false out.
    IntOr,
    /// `CPUI_INT_AND`, given at creation otherwise.
    IntAnd,
    /// `CPUI_BOOL_AND`.
    BoolAnd,
    /// `CPUI_BOOL_OR`.
    BoolOr,
}

impl CondOp {
    /// Ghidra's opcode name (`get_opname`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::IntOr => "INT_OR",
            Self::IntAnd => "INT_AND",
            Self::BoolAnd => "BOOL_AND",
            Self::BoolOr => "BOOL_OR",
        }
    }

    /// The toggle of `BlockCondition::negateCondition` (block.cc:3091):
    /// `BOOL_AND` becomes `BOOL_OR`, everything else `BOOL_AND`.
    pub(crate) const fn negated(self) -> Self {
        match self {
            Self::BoolAnd => Self::BoolOr,
            _ => Self::BoolAnd,
        }
    }

    /// The operator `printHeader` and the printer show: `&&` only for
    /// `BOOL_AND` (block.cc:3107, printc.cc:3001).
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::BoolAnd => "&&",
            _ => "||",
        }
    }
}
