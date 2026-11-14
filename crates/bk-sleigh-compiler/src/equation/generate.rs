//! Pattern equations to patterns (`PatternEquation::genPattern` and the
//! compile-time side of `PatternExpression`, inventory 10 a.5–a.6).

use bk_sla::{BinaryOp, UnaryOp};
use rustc_hash::FxHashMap;

use super::{EqError, EquationView, MAX_DEPTH, MAX_ENUMERATION};
use crate::ids::{EquationId, PExprId};
use crate::pattern::{ConstraintOp, Equation, PExpr, PatValue, Pattern, TokenPattern};

/// The lengths and ellipses of each equation node's result, which operand
/// offsets are resolved from (`resultpattern`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Shape {
    pub(crate) ellipsis: bool,
    pub(crate) min_length: i32,
}

/// The pattern of a value leaf for one of its values (`genPattern(val)`).
fn value_pattern(leaf: &PExpr, value: i64) -> TokenPattern {
    match leaf {
        PExpr::Field(PatValue::Token(f, tok)) => {
            TokenPattern::field(*tok, f.big_endian, f.start_bit, f.end_bit, value)
        }
        PExpr::Field(PatValue::Context(f)) => TokenPattern::context(value, f.start_bit, f.end_bit),
        PExpr::Constant(c) => TokenPattern::constant(*c == value),
        _ => TokenPattern::constant(true),
    }
}

/// The range of a value leaf (`minValue`, `maxValue`).
fn value_range(leaf: &PExpr) -> Result<(i64, i64), EqError> {
    match leaf {
        PExpr::Field(v) => Ok((0, v.max_value())),
        PExpr::Constant(c) => Ok((*c, *c)),
        PExpr::Operand(_) => Err(EqError::new("Operand used in pattern expression")),
        _ => Ok((0, 0)),
    }
}

/// Java's `EqualEquation.isValueInRange`: `min <= value <= max` compared
/// as unsigned 64-bit numbers (spec 4.1), so a constraint on a 64-bit field
/// can match.
pub(crate) const fn is_value_in_range(value: i64, min: i64, max: i64) -> bool {
    (value as u64) >= (min as u64) && (value as u64) <= (max as u64)
}

/// `advance_combo`: the next assignment, the first value varying fastest.
fn advance(cur: &mut [i64], ranges: &[(i64, i64)]) -> bool {
    for (v, &(min, max)) in cur.iter_mut().zip(ranges) {
        *v = v.wrapping_add(1);
        if *v <= max {
            return true;
        }
        *v = min;
    }
    false
}

/// `rhs->getSubValue(cur)`: the expression with its value leaves replaced
/// in order.
fn evaluate(
    view: &EquationView<'_>,
    id: PExprId,
    values: &[i64],
    pos: &mut usize,
    depth: u32,
) -> Result<i64, EqError> {
    if depth > MAX_DEPTH {
        return Err(EqError::new("Pattern expression nested too deeply"));
    }
    Ok(match view.arena.get_expr(id) {
        Some(PExpr::Binary { op, left, right }) => {
            let l = evaluate(view, *left, values, pos, depth + 1)?;
            let r = evaluate(view, *right, values, pos, depth + 1)?;
            match op {
                BinaryOp::Plus => l.wrapping_add(r),
                BinaryOp::Sub => l.wrapping_sub(r),
                BinaryOp::Mult => l.wrapping_mul(r),
                BinaryOp::LeftShift => l.wrapping_shl((r & 63) as u32),
                BinaryOp::RightShift => l.wrapping_shr((r & 63) as u32),
                BinaryOp::And => l & r,
                BinaryOp::Or => l | r,
                BinaryOp::Xor => l ^ r,
                BinaryOp::Div => {
                    if r == 0 {
                        return Err(EqError::new("Division by zero in pattern expression"));
                    }
                    l.wrapping_div(r)
                }
            }
        }
        Some(PExpr::Unary { op, operand }) => {
            let v = evaluate(view, *operand, values, pos, depth + 1)?;
            match op {
                UnaryOp::Minus => v.wrapping_neg(),
                UnaryOp::Not => !v,
            }
        }
        Some(_) => {
            let v = values.get(*pos).copied().unwrap_or(0);
            *pos += 1;
            v
        }
        None => 0,
    })
}

/// `genMinPattern` of an expression.
pub(crate) fn min_pattern(
    view: &EquationView<'_>,
    expr: PExprId,
    ops: &[TokenPattern],
) -> TokenPattern {
    match view.arena.get_expr(expr) {
        Some(PExpr::Field(PatValue::Token(_, tok))) => TokenPattern::token(*tok),
        Some(PExpr::Operand(op)) => view
            .operand_index(*op)
            .and_then(|i| ops.get(i))
            .cloned()
            .unwrap_or_default(),
        _ => TokenPattern::constant(true),
    }
}

/// `resultpattern = resultpattern.doOr(p)`, appending in place when that
/// is what the `or` does (alternatives on the left, no shift), so that a
/// constraint with many values is not quadratic.
fn or_into(acc: &mut TokenPattern, p: TokenPattern) -> Result<(), EqError> {
    let same_shape = acc.tokens == p.tokens
        && !acc.has_ellipsis()
        && !p.has_ellipsis()
        && matches!(acc.pattern, Pattern::Or(_))
        && matches!(p.pattern, Pattern::One(_));
    if same_shape {
        if p.pattern.always_false() {
            return Ok(());
        }
        if p.pattern.always_true() {
            acc.pattern = Pattern::TRUE;
            return Ok(());
        }
        if let (Pattern::Or(list), Pattern::One(d)) = (&mut acc.pattern, p.pattern) {
            list.push(d);
        }
        return Ok(());
    }
    *acc = acc.or(&p).map_err(EqError::combine)?;
    Ok(())
}

struct Generator<'v, 'a> {
    view: &'v EquationView<'a>,
    ops: &'v [TokenPattern],
    shapes: FxHashMap<EquationId, Shape>,
}

impl Generator<'_, '_> {
    fn record(&mut self, id: EquationId, p: &TokenPattern) {
        self.shapes.insert(
            id,
            Shape {
                ellipsis: p.has_ellipsis(),
                min_length: p.minimum_length(),
            },
        );
    }

    fn visit(&mut self, id: EquationId, depth: u32) -> Result<TokenPattern, EqError> {
        if depth > MAX_DEPTH {
            return Err(EqError::new("Pattern equation nested too deeply"));
        }
        let Some(eq) = self.view.arena.get_equation(id).copied() else {
            return Ok(TokenPattern::constant(true));
        };
        let result = match eq {
            Equation::Operand(op) => self
                .view
                .operand_index(op)
                .and_then(|i| self.ops.get(i))
                .cloned()
                .unwrap_or_default(),
            Equation::Unconstrained(expr) => min_pattern(self.view, expr, self.ops),
            Equation::And(l, r) | Equation::Or(l, r) | Equation::Cat(l, r) => {
                let left = self.visit(l, depth + 1)?;
                let right = self.visit(r, depth + 1)?;
                match eq {
                    Equation::And(..) => left.and(&right),
                    Equation::Or(..) => left.or(&right),
                    _ => left.cat(&right),
                }
                .map_err(EqError::combine)?
            }
            Equation::LeftEllipsis(inner) => {
                let mut p = self.visit(inner, depth + 1)?;
                p.left_ellipsis = true;
                p
            }
            Equation::RightEllipsis(inner) => {
                let mut p = self.visit(inner, depth + 1)?;
                p.right_ellipsis = true;
                p
            }
            Equation::Constraint { op, value, expr } => self.constraint(op, value, expr)?,
        };
        self.record(id, &result);
        Ok(result)
    }

    /// The `ValExpressEquation` family.
    fn constraint(
        &self,
        op: ConstraintOp,
        value: PExprId,
        expr: PExprId,
    ) -> Result<TokenPattern, EqError> {
        let lhs = self.view.arena.get_expr(value).copied().unwrap_or(PExpr::Constant(0));
        let (lhs_min, lhs_max) = value_range(&lhs)?;
        let mut leaves = Vec::new();
        self.view.arena.for_each_value(expr, |leaf| leaves.push(*leaf));
        let ranges = leaves
            .iter()
            .map(value_range)
            .collect::<Result<Vec<_>, _>>()?;
        let mut combos: u128 = ranges
            .iter()
            .map(|&(min, max)| (i128::from(max) - i128::from(min) + 1).max(1) as u128)
            .fold(1, u128::saturating_mul);
        if op != ConstraintOp::Equal && lhs_max >= lhs_min {
            combos = combos.saturating_mul((i128::from(lhs_max) - i128::from(lhs_min) + 1) as u128);
        }
        if combos > MAX_ENUMERATION {
            return Err(EqError::new(format!(
                "Constraint enumerates too many values ({combos}; at most {MAX_ENUMERATION})"
            )));
        }
        let build = |lhs_val: i64, cur: &[i64]| -> Result<TokenPattern, EqError> {
            let mut p = value_pattern(&lhs, lhs_val);
            for (leaf, &v) in leaves.iter().zip(cur) {
                p = p.and(&value_pattern(leaf, v)).map_err(EqError::combine)?;
            }
            Ok(p)
        };
        let mut result: Option<TokenPattern> = None;
        let mut add = |p: TokenPattern| -> Result<(), EqError> {
            match &mut result {
                None => result = Some(p),
                Some(acc) => or_into(acc, p)?,
            }
            Ok(())
        };
        let mut cur: Vec<i64> = ranges.iter().map(|r| r.0).collect();
        loop {
            let val = evaluate(self.view, expr, &cur, &mut 0, 0)?;
            if op == ConstraintOp::Equal {
                // Java's unsigned range test (spec 4.1).
                if is_value_in_range(val, lhs_min, lhs_max) {
                    add(build(val, &cur)?)?;
                }
            } else {
                let mut lhs_val = lhs_min;
                while lhs_val <= lhs_max {
                    let skip = match op {
                        ConstraintOp::NotEqual => lhs_val == val,
                        ConstraintOp::Less => lhs_val >= val,
                        ConstraintOp::LessEqual => lhs_val > val,
                        ConstraintOp::Greater => lhs_val <= val,
                        ConstraintOp::GreaterEqual | ConstraintOp::Equal => lhs_val < val,
                    };
                    if !skip {
                        add(build(lhs_val, &cur)?)?;
                    }
                    if lhs_val == i64::MAX {
                        break;
                    }
                    lhs_val += 1;
                }
            }
            if !advance(&mut cur, &ranges) {
                break;
            }
        }
        result.ok_or_else(|| {
            EqError::new(match op {
                ConstraintOp::Equal => "Equal constraint is impossible to match",
                ConstraintOp::NotEqual => "Notequal constraint is impossible to match",
                ConstraintOp::Less => "Less than constraint is impossible to match",
                ConstraintOp::LessEqual => "Less than or equal constraint is impossible to match",
                ConstraintOp::Greater => "Greater than constraint is impossible to match",
                ConstraintOp::GreaterEqual => {
                    "Greater than or equal constraint is impossible to match"
                }
            })
        })
    }
}

/// Generates the pattern of an equation over the operands' patterns
/// `ops` (by operand index), with the shape of every node.
pub(crate) fn generate(
    view: &EquationView<'_>,
    root: EquationId,
    ops: &[TokenPattern],
) -> Result<(TokenPattern, FxHashMap<EquationId, Shape>), EqError> {
    let mut g = Generator {
        view,
        ops,
        shapes: FxHashMap::default(),
    };
    let p = g.visit(root, 0)?;
    Ok((p, g.shapes))
}

/// Ghidra's `EqualEquationTest` (`ghidra.pcodeCPort.slghpatexpress`).
#[cfg(test)]
mod equal_equation_test {
    use super::is_value_in_range;

    #[test]
    fn normal_range() {
        assert!(is_value_in_range(0x1234, 0, 0xffff));
        assert!(!is_value_in_range(-1, 0, 0xffff));
    }

    #[test]
    fn full_width_unsigned_range() {
        assert!(is_value_in_range(0, 0, -1));
        assert!(is_value_in_range(i64::MAX, 0, -1));
        assert!(is_value_in_range(i64::MIN, 0, -1));
        assert!(is_value_in_range(-1, 0, -1));
    }

    #[test]
    fn unsigned_range_crossing_signed_boundary() {
        assert!(!is_value_in_range(4, 5, -2));
        assert!(is_value_in_range(5, 5, -2));
        assert!(is_value_in_range(i64::MAX, 5, -2));
        assert!(is_value_in_range(i64::MIN, 5, -2));
        assert!(is_value_in_range(-2, 5, -2));
        assert!(!is_value_in_range(-1, 5, -2));
    }
}
