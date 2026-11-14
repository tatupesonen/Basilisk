//! The canonical form in which an elaboration and a compiled `.sla` file
//! are compared (spec 6.2).
//!
//! Both sides become a list of (path, value) entries. Wherever the file
//! refers to an operand by its position (`opprint`, `const_handle`, `BUILD`,
//! `operand_exp`), the canonical form names the operand's symbol id
//! instead, because the back half reorders operands. What only the back
//! half determines — constructor length, operand offsets, bases, minimum
//! lengths and indices, decision trees — is left out.

mod mine;
mod reference;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bk_sla::{BinaryOp, ConstTpl, HandleSelect, UnaryOp};

pub use mine::canonical as of_elaborated;
pub use reference::canonical as of_sla;

/// One side of a comparison: values keyed by path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Canonical {
    entries: BTreeMap<String, String>,
}

impl Canonical {
    /// Adds an entry.
    pub fn put(&mut self, path: String, value: String) {
        self.entries.insert(path, value);
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The entries whose path starts with `prefix`.
    pub fn with_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.entries
            .range(prefix.to_owned()..)
            .take_while(move |(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// One difference between two canonical forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// The path.
    pub path: String,
    /// basilisk's value, if it has the path.
    pub ours: Option<String>,
    /// The reference's value, if it has the path.
    pub theirs: Option<String>,
}

impl std::fmt::Display for Difference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: basilisk {} / Ghidra {}",
            self.path,
            self.ours.as_deref().unwrap_or("<absent>"),
            self.theirs.as_deref().unwrap_or("<absent>")
        )
    }
}

/// The differences between `ours` and `theirs`, at most `cap` of them, in
/// path order. Also returns the total number of differences.
pub fn diff(ours: &Canonical, theirs: &Canonical, cap: usize) -> (Vec<Difference>, usize) {
    let mut out = Vec::new();
    let mut total = 0;
    let mut a = ours.entries.iter().peekable();
    let mut b = theirs.entries.iter().peekable();
    loop {
        let d = match (a.peek(), b.peek()) {
            (None, None) => break,
            (Some((ka, va)), Some((kb, vb))) => match ka.cmp(kb) {
                std::cmp::Ordering::Equal => {
                    let d = (va != vb).then(|| Difference {
                        path: (*ka).clone(),
                        ours: Some((*va).clone()),
                        theirs: Some((*vb).clone()),
                    });
                    a.next();
                    b.next();
                    d
                }
                std::cmp::Ordering::Less => {
                    let d = Difference {
                        path: (*ka).clone(),
                        ours: Some((*va).clone()),
                        theirs: None,
                    };
                    a.next();
                    Some(d)
                }
                std::cmp::Ordering::Greater => {
                    let d = Difference {
                        path: (*kb).clone(),
                        ours: None,
                        theirs: Some((*vb).clone()),
                    };
                    b.next();
                    Some(d)
                }
            },
            (Some((ka, va)), None) => {
                let d = Difference {
                    path: (*ka).clone(),
                    ours: Some((*va).clone()),
                    theirs: None,
                };
                a.next();
                Some(d)
            }
            (None, Some((kb, vb))) => {
                let d = Difference {
                    path: (*kb).clone(),
                    ours: None,
                    theirs: Some((*vb).clone()),
                };
                b.next();
                Some(d)
            }
        };
        if let Some(d) = d {
            total += 1;
            if out.len() < cap {
                out.push(d);
            }
        }
    }
    (out, total)
}

/// The category of a path, for counting agreement per category.
pub fn category(path: &str) -> &'static str {
    if path.starts_with("header") || path.starts_with("space") || path.starts_with("sourcefile") || path.starts_with("defaultspace") {
        "header"
    } else if path.starts_with("scope") {
        "scopes"
    } else if path.starts_with("symbol") {
        if path.ends_with(".id") {
            "symbol ids"
        } else {
            "symbol contents"
        }
    } else if path.contains(".tpl.") {
        "templates"
    } else if path.contains(".context.") {
        "context changes"
    } else if path.contains(".print") || path.ends_with(".first") {
        "print pieces"
    } else {
        "constructors"
    }
}

pub(crate) fn binary_name(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Plus => "plus",
        BinaryOp::Sub => "sub",
        BinaryOp::Mult => "mult",
        BinaryOp::LeftShift => "lshift",
        BinaryOp::RightShift => "rshift",
        BinaryOp::And => "and",
        BinaryOp::Or => "or",
        BinaryOp::Xor => "xor",
        BinaryOp::Div => "div",
    }
}

pub(crate) fn unary_name(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Minus => "minus",
        UnaryOp::Not => "not",
    }
}

pub(crate) fn field_text(context: bool, f: &bk_sla::Field, out: &mut String) {
    if context {
        let _ = write!(
            out,
            "ctx(sign={},sb={},eb={},sby={},eby={},sh={})",
            u8::from(f.sign_bit),
            f.start_bit,
            f.end_bit,
            f.start_byte,
            f.end_byte,
            f.shift
        );
    } else {
        let _ = write!(
            out,
            "tok(be={},sign={},sb={},eb={},sby={},eby={},sh={})",
            u8::from(f.big_endian),
            u8::from(f.sign_bit),
            f.start_bit,
            f.end_bit,
            f.start_byte,
            f.end_byte,
            f.shift
        );
    }
}

/// Writes a template constant; `operand` maps an operand index to its
/// symbol id and `space` a space index to its name.
pub(crate) fn const_text(c: &ConstTpl, operand: &dyn Fn(u32) -> String, space: &dyn Fn(u32) -> String, out: &mut String) {
    match *c {
        ConstTpl::Real(v) => {
            let _ = write!(out, "#{v:#x}");
        }
        ConstTpl::Handle { index, select, plus } => {
            let sel = match select {
                HandleSelect::Space => "space",
                HandleSelect::Offset => "offset",
                HandleSelect::Size => "size",
                HandleSelect::OffsetPlus => "offset+",
            };
            let _ = write!(out, "h[{}].{sel}", operand(index));
            if select == HandleSelect::OffsetPlus {
                let _ = write!(out, "{plus:#x}");
            }
        }
        ConstTpl::Start => out.push_str("start"),
        ConstTpl::Next => out.push_str("next"),
        ConstTpl::Next2 => out.push_str("next2"),
        ConstTpl::CurSpace => out.push_str("curspace"),
        ConstTpl::CurSpaceSize => out.push_str("curspace_size"),
        ConstTpl::Space(i) => {
            let _ = write!(out, "space({})", space(i));
        }
        ConstTpl::Relative(v) => {
            let _ = write!(out, "rel({v})");
        }
        ConstTpl::FlowRef => out.push_str("flowref"),
        ConstTpl::FlowRefSize => out.push_str("flowref_size"),
        ConstTpl::FlowDest => out.push_str("flowdest"),
        ConstTpl::FlowDestSize => out.push_str("flowdest_size"),
    }
}

/// Writes a varnode template: `(space,offset,size)`.
pub(crate) fn vn_text(vn: &bk_sla::VarnodeTpl, operand: &dyn Fn(u32) -> String, space: &dyn Fn(u32) -> String, out: &mut String) {
    out.push('(');
    const_text(&vn.space, operand, space, out);
    out.push(',');
    const_text(&vn.offset, operand, space, out);
    out.push(',');
    const_text(&vn.size, operand, space, out);
    out.push(')');
}

/// Writes one op: `OPCODE out <- in, in`; a `BUILD` names its operand.
pub(crate) fn op_text(
    opcode: bk_pcode::OpCode,
    output: Option<&bk_sla::VarnodeTpl>,
    inputs: &[bk_sla::VarnodeTpl],
    operand: &dyn Fn(u32) -> String,
    space: &dyn Fn(u32) -> String,
) -> String {
    let mut out = String::new();
    out.push_str(opcode.name());
    if opcode == crate::template::BUILD
        && let [only] = inputs
        && let ConstTpl::Real(index) = only.offset
    {
        let _ = write!(out, " operand {}", operand(index as u32));
        return out;
    }
    out.push(' ');
    match output {
        Some(vn) => vn_text(vn, operand, space, &mut out),
        None => out.push('-'),
    }
    out.push_str(" <-");
    for (i, vn) in inputs.iter().enumerate() {
        out.push_str(if i == 0 { " " } else { ", " });
        vn_text(vn, operand, space, &mut out);
    }
    out
}

/// Writes an export handle.
pub(crate) fn handle_text(hand: &bk_sla::HandleTpl, operand: &dyn Fn(u32) -> String, space: &dyn Fn(u32) -> String) -> String {
    let mut out = String::new();
    for (i, part) in hand.parts().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        const_text(part, operand, space, &mut out);
    }
    out
}

/// Quotes a print piece.
pub(crate) fn quote(text: &str) -> String {
    format!("{text:?}")
}
