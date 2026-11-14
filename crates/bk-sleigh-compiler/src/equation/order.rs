//! The order in which an equation mentions operands (`operandOrder`,
//! inventory 10 a.8).

use super::EquationView;
use crate::ids::EquationId;
use crate::pattern::Equation;

/// Appends to `order` the index of each operand the equation mentions, left
/// to right, the first time it is seen (`marked` by index).
pub(crate) fn operand_order(
    view: &EquationView<'_>,
    root: EquationId,
    marked: &mut [bool],
    order: &mut Vec<usize>,
) {
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        match view.arena.get_equation(id).copied() {
            Some(Equation::Operand(op)) => {
                if let Some(index) = view.operand_index(op)
                    && let Some(m) = marked.get_mut(index)
                    && !*m
                {
                    *m = true;
                    order.push(index);
                }
            }
            Some(Equation::And(l, r) | Equation::Or(l, r) | Equation::Cat(l, r)) => {
                stack.push(r);
                stack.push(l);
            }
            Some(Equation::LeftEllipsis(inner) | Equation::RightEllipsis(inner)) => {
                stack.push(inner);
            }
            _ => {}
        }
    }
}
