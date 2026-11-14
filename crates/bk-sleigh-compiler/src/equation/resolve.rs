//! Where each operand's bytes start (`resolveOperandLeft`,
//! `OperandResolve`, inventory 10 a.7).

use rustc_hash::FxHashMap;

use super::{EquationView, Shape};
use crate::ids::EquationId;
use crate::pattern::Equation;

/// An operand's offset: `reloffset` bytes after the end of operand `base`,
/// or after the constructor's start when `base` is −1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Offsets {
    /// `offsetbase`.
    pub(crate) base: i32,
    /// `reloffset`.
    pub(crate) offset: i32,
}

struct State<'s> {
    offsets: &'s mut [Option<Offsets>],
    irrelevant: &'s [bool],
    shapes: &'s FxHashMap<EquationId, Shape>,
    base: i32,
    offset: i32,
    cur_rightmost: i32,
    size: i32,
}

impl State<'_> {
    fn shape(&self, id: EquationId) -> Shape {
        self.shapes.get(&id).copied().unwrap_or_default()
    }

    fn resolve(&mut self, view: &EquationView<'_>, id: EquationId) -> bool {
        let Some(eq) = view.arena.get_equation(id).copied() else {
            return true;
        };
        match eq {
            Equation::Operand(op) => {
                let Some(index) = view.operand_index(op) else {
                    return true;
                };
                if self.irrelevant.get(index).copied().unwrap_or(false) {
                    if let Some(slot) = self.offsets.get_mut(index) {
                        *slot = Some(Offsets { base: -1, offset: 0 });
                    }
                    return true;
                }
                if self.base == -2 {
                    return false;
                }
                if let Some(slot) = self.offsets.get_mut(index) {
                    *slot = Some(Offsets {
                        base: self.base,
                        offset: self.offset,
                    });
                }
                self.cur_rightmost = index as i32;
                self.size = 0;
                true
            }
            Equation::Unconstrained(_) | Equation::Constraint { .. } => {
                let shape = self.shape(id);
                self.cur_rightmost = -1;
                self.size = if shape.ellipsis { -1 } else { shape.min_length };
                true
            }
            Equation::And(l, r) | Equation::Or(l, r) => {
                let mut saved = (-1, -1);
                if !self.resolve(view, r) {
                    return false;
                }
                if self.cur_rightmost != -1 && self.size != -1 {
                    saved = (self.cur_rightmost, self.size);
                }
                if !self.resolve(view, l) {
                    return false;
                }
                if self.cur_rightmost == -1 || self.size == -1 {
                    (self.cur_rightmost, self.size) = saved;
                }
                true
            }
            Equation::Cat(l, r) => {
                if !self.resolve(view, l) {
                    return false;
                }
                let (cur_base, cur_offset) = (self.base, self.offset);
                let left = self.shape(l);
                if !left.ellipsis {
                    self.offset = self.offset.wrapping_add(left.min_length);
                } else if self.cur_rightmost != -1 {
                    self.base = self.cur_rightmost;
                    self.offset = self.size;
                } else if self.size != -1 {
                    self.offset = self.offset.wrapping_add(self.size);
                } else {
                    self.base = -2;
                }
                let (cur_rightmost, cur_size) = (self.cur_rightmost, self.size);
                if !self.resolve(view, r) {
                    return false;
                }
                self.base = cur_base;
                self.offset = cur_offset;
                if self.cur_rightmost == -1
                    && self.size != -1
                    && cur_rightmost != -1
                    && cur_size != -1
                {
                    self.cur_rightmost = cur_rightmost;
                    self.size = self.size.wrapping_add(cur_size);
                }
                true
            }
            Equation::LeftEllipsis(inner) => {
                let cur_base = self.base;
                self.base = -2;
                if !self.resolve(view, inner) {
                    return false;
                }
                self.base = cur_base;
                true
            }
            Equation::RightEllipsis(inner) => {
                if !self.resolve(view, inner) {
                    return false;
                }
                self.size = -1;
                true
            }
        }
    }
}

/// Resolves the offsets of the operands an equation places. `irrelevant`
/// marks offset-irrelevant operands by index; `offsets` (by index) receives
/// what is resolved and keeps `None` for operands the equation does not
/// place. False when an operand cannot be anchored ("Unable to resolve
/// operand offsets"). The equation's depth was bounded by `generate`.
pub(crate) fn resolve_offsets(
    view: &EquationView<'_>,
    root: EquationId,
    shapes: &FxHashMap<EquationId, Shape>,
    irrelevant: &[bool],
    offsets: &mut [Option<Offsets>],
) -> bool {
    let mut state = State {
        offsets,
        irrelevant,
        shapes,
        base: -1,
        offset: 0,
        cur_rightmost: -1,
        size: 0,
    };
    state.resolve(view, root)
}
