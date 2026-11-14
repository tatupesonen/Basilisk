//! The boolean expressions of `@if` and `@elif`.
//!
//! This is Ghidra's `BooleanExpression.g`:
//!
//! ```text
//! expr     := xor ('||' xor)*
//! xor      := and ('^^' and)*
//! and      := not ('&&' not)*
//! not      := '!' '(' expr ')' | '(' expr ')' | term ('==' | '!=') term
//!           | 'defined' '(' NAME ')'
//! term     := NAME | "string"
//! ```
//!
//! A `NAME` in a comparison stands for the value of that definition. An
//! undefined name is reported and compares unequal to everything, so
//! `UNDEFINED != "x"` is true. Both operands of `||`, `^^` and `&&` are
//! always evaluated, as in Ghidra, so every undefined name is reported.

use std::borrow::Cow;

/// Looks up preprocessor definitions for [`evaluate`].
pub trait ExprEnv {
    /// The value of `name`, or `None` if it is not defined.
    fn lookup(&self, name: &str) -> Option<Cow<'_, str>>;
}

impl<F> ExprEnv for F
where
    F: Fn(&str) -> Option<String>,
{
    fn lookup(&self, name: &str) -> Option<Cow<'_, str>> {
        self(name).map(Cow::Owned)
    }
}

/// The result of evaluating an expression.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExprValue {
    /// The truth value.
    pub value: bool,
    /// Names used in comparisons that were not defined, in order of use.
    /// Ghidra reports each as `Macro: NAME is undefined` and fails.
    pub undefined: Vec<String>,
}

/// A malformed expression.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("{message} at column {} of the expression", offset + 1)]
pub struct ExprError {
    /// Byte offset of the problem within the expression.
    pub offset: usize,
    /// What is wrong.
    pub message: String,
}

/// Deepest nesting of parentheses accepted.
const MAX_DEPTH: u32 = 64;

/// Evaluates a preprocessor expression against `env`.
pub fn evaluate(expr: &str, env: &dyn ExprEnv) -> Result<ExprValue, ExprError> {
    let mut eval = Evaluator {
        src: expr,
        pos: 0,
        env,
        undefined: Vec::new(),
        depth: 0,
    };
    let value = eval.expr()?;
    eval.skip_space();
    if eval.pos < expr.len() {
        return Err(eval.error("unexpected text after the expression"));
    }
    Ok(ExprValue {
        value,
        undefined: eval.undefined,
    })
}

struct Evaluator<'a> {
    src: &'a str,
    pos: usize,
    env: &'a dyn ExprEnv,
    undefined: Vec<String>,
    depth: u32,
}

impl<'a> Evaluator<'a> {
    fn error(&self, message: &str) -> ExprError {
        ExprError {
            offset: self.pos,
            message: message.to_owned(),
        }
    }

    fn rest(&self) -> &'a str {
        self.src.get(self.pos..).unwrap_or("")
    }

    fn skip_space(&mut self) {
        let rest = self.rest();
        let trimmed = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        self.pos += rest.len() - trimmed.len();
    }

    /// Consumes `token` if it comes next (after whitespace).
    fn eat(&mut self, token: &str) -> bool {
        self.skip_space();
        if self.rest().starts_with(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, token: &str) -> Result<(), ExprError> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{token}'")))
        }
    }

    fn expr(&mut self) -> Result<bool, ExprError> {
        let mut value = self.xor()?;
        while self.eat("||") {
            let rhs = self.xor()?;
            value = value || rhs;
        }
        Ok(value)
    }

    fn xor(&mut self) -> Result<bool, ExprError> {
        let mut value = self.and()?;
        while self.eat("^^") {
            value ^= self.and()?;
        }
        Ok(value)
    }

    fn and(&mut self) -> Result<bool, ExprError> {
        let mut value = self.not()?;
        while self.eat("&&") {
            let rhs = self.not()?;
            value = value && rhs;
        }
        Ok(value)
    }

    fn not(&mut self) -> Result<bool, ExprError> {
        self.skip_space();
        if self.rest().starts_with("!=") {
            return Err(self.error("expected a name, a string or '('"));
        }
        if self.eat("!") {
            // Only a parenthesised expression may be negated.
            self.skip_space();
            if !self.rest().starts_with('(') {
                return Err(self.error("expected '(' after '!'"));
            }
            return Ok(!self.paren()?);
        }
        if self.rest().starts_with('(') {
            return self.paren();
        }
        if let Some(name) = self.peek_name()
            && name == "defined"
        {
            self.pos += name.len();
            self.expect("(")?;
            self.skip_space();
            let Some(arg) = self.peek_name() else {
                return Err(self.error("expected a name inside 'defined(...)'"));
            };
            self.pos += arg.len();
            self.expect(")")?;
            return Ok(self.env.lookup(arg).is_some());
        }
        let lhs = self.term()?;
        let negate = if self.eat("==") {
            false
        } else if self.eat("!=") {
            true
        } else {
            return Err(self.error("expected '==' or '!='"));
        };
        let rhs = self.term()?;
        let equal = matches!((&lhs, &rhs), (Some(a), Some(b)) if a == b);
        Ok(equal != negate)
    }

    fn paren(&mut self) -> Result<bool, ExprError> {
        self.expect("(")?;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.error("parentheses nested too deeply"));
        }
        let value = self.expr()?;
        self.depth -= 1;
        self.expect(")")?;
        Ok(value)
    }

    /// The name (`[A-Za-z0-9_]+`) at the current position, if any.
    fn peek_name(&self) -> Option<&'a str> {
        let rest = self.rest();
        let len = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if len == 0 { None } else { rest.get(..len) }
    }

    /// A comparison operand: the value of a name (`None` if undefined) or
    /// the raw content of a quoted string.
    fn term(&mut self) -> Result<Option<Cow<'a, str>>, ExprError> {
        self.skip_space();
        if let Some(name) = self.peek_name() {
            if name == "defined" {
                return Err(self.error("'defined' cannot be compared"));
            }
            self.pos += name.len();
            let value = self.env.lookup(name);
            if value.is_none() {
                self.undefined.push(name.to_owned());
            }
            return Ok(value.map(|v| Cow::Owned(v.into_owned())));
        }
        if self.rest().starts_with('"') {
            return self.string().map(|s| Some(Cow::Borrowed(s)));
        }
        Err(self.error("expected a name or a string"))
    }

    /// A quoted string with the escapes of `BooleanExpression.g`; returns the
    /// text between the quotes without interpreting escapes, as Ghidra does.
    fn string(&mut self) -> Result<&'a str, ExprError> {
        let start = self.pos + 1;
        let bytes = self.src.as_bytes();
        let mut i = start;
        loop {
            match bytes.get(i) {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => {
                    let len = escape_len(bytes.get(i + 1..).unwrap_or(&[]));
                    if len == 0 {
                        self.pos = i;
                        return Err(self.error("invalid escape sequence in string"));
                    }
                    i += 1 + len;
                }
                Some(_) => i += 1,
            }
        }
        self.pos = i + 1;
        Ok(self.src.get(start..i).unwrap_or(""))
    }
}

/// Length of a valid escape body (the part after the backslash) at the start
/// of `rest`, or 0 if there is none. The escapes are those of Ghidra's
/// ANTLR lexers: `\b \t \n \f \r \" \' \\`, `\uXXXX`, and octal `\N`, `\NN`,
/// `\NNN` (the three-digit form only with a first digit of 0 to 3).
pub(crate) fn escape_len(rest: &[u8]) -> usize {
    let octal = |i: usize| rest.get(i).is_some_and(|b| (b'0'..=b'7').contains(b));
    match rest.first() {
        Some(b'b' | b't' | b'n' | b'f' | b'r' | b'"' | b'\'' | b'\\') => 1,
        Some(b'u') => {
            let hex = rest
                .get(1..5)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
            if hex { 5 } else { 0 }
        }
        Some(b'0'..=b'3') if octal(1) && octal(2) => 3,
        Some(b'0'..=b'7') => 1 + usize::from(octal(1)),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defs(name: &str) -> Option<String> {
        match name {
            "A" => Some("a".to_owned()),
            "B" => Some("b".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        }
    }

    fn eval(expr: &str) -> Result<bool, ExprError> {
        evaluate(expr, &defs).map(|v| v.value)
    }

    #[test]
    fn comparisons_and_defined() {
        assert_eq!(eval("A == \"a\""), Ok(true));
        assert_eq!(eval("A==\"b\""), Ok(false));
        assert_eq!(eval("A != B"), Ok(true));
        assert_eq!(eval("\"x\" == \"x\""), Ok(true));
        assert_eq!(eval("EMPTY == \"\""), Ok(true));
        assert_eq!(eval("defined(A)"), Ok(true));
        assert_eq!(eval("defined ( NOPE )"), Ok(false));
        assert_eq!(eval(" \t(A == \"a\")\t "), Ok(true));
    }

    #[test]
    fn precedence_is_or_then_xor_then_and() {
        // true || (true ^^ (true && false)), not ((true || true) ^^ true) && false
        assert_eq!(
            eval("defined(A) || defined(A) ^^ defined(A) && defined(X)"),
            Ok(true)
        );
        // (true ^^ true) = false; false || false
        assert_eq!(eval("defined(A) ^^ defined(B) || defined(X)"), Ok(false));
        // xor binds looser than and: true ^^ (true && true) = false
        assert_eq!(eval("defined(A) ^^ defined(A) && defined(B)"), Ok(false));
    }

    #[test]
    fn undefined_names_are_reported_and_compare_unequal() {
        let v = evaluate("NOPE == \"x\" || NADA != \"y\"", &defs).unwrap();
        assert!(v.value, "an undefined name is unequal to everything");
        assert_eq!(v.undefined, ["NOPE", "NADA"]);
        // `defined` does not report.
        assert_eq!(
            evaluate("defined(NOPE)", &defs).unwrap().undefined,
            Vec::<String>::new()
        );
        // Both sides of || are evaluated even when the left is true.
        assert_eq!(
            evaluate("defined(A) || NOPE == \"x\"", &defs)
                .unwrap()
                .undefined,
            ["NOPE"]
        );
    }

    #[test]
    fn negation_needs_parentheses() {
        assert_eq!(eval("!(defined(A))"), Ok(false));
        assert_eq!(eval("!(!(A == \"a\"))"), Ok(true));
        assert!(eval("!defined(A)").is_err());
        assert!(eval("!A == \"a\"").is_err());
    }

    #[test]
    fn strings_keep_escapes_raw() {
        let quote = |name: &str| (name == "Q").then(|| "a\\\"b".to_owned());
        assert_eq!(
            evaluate("Q == \"a\\\"b\"", &quote).map(|v| v.value),
            Ok(true)
        );
        assert!(eval("A == \"a\\q\"").is_err());
        assert!(eval("A == \"a").is_err());
        assert_eq!(eval("\"\\101\" == \"\\101\""), Ok(true));
        assert_eq!(eval("\"\\u00e9\" != \"x\""), Ok(true));
    }

    #[test]
    fn malformed_expressions_are_errors() {
        for bad in [
            "",
            "A",
            "A ==",
            "== A",
            "A = \"a\"",
            "(A == \"a\"",
            "A == \"a\")",
            "A == \"a\" |",
            "A == \"a\" & B == \"b\"",
            "defined A",
            "defined()",
            "defined(A",
            "defined == \"x\"",
            "A == defined",
            "A == \"a\" B == \"b\"",
            "A @ B",
        ] {
            assert!(eval(bad).is_err(), "{bad:?} should be rejected");
        }
        let deep = format!("{}A == \"a\"{}", "(".repeat(200), ")".repeat(200));
        assert!(eval(&deep).is_err());
        let ok = format!("{}A == \"a\"{}", "(".repeat(40), ")".repeat(40));
        assert_eq!(eval(&ok), Ok(true));
    }

    #[test]
    fn escape_lengths() {
        assert_eq!(escape_len(b"n"), 1);
        assert_eq!(escape_len(b"\"x"), 1);
        assert_eq!(escape_len(b"u00e9"), 5);
        assert_eq!(escape_len(b"u00g9"), 0);
        assert_eq!(escape_len(b"377"), 3);
        assert_eq!(escape_len(b"477"), 2);
        assert_eq!(escape_len(b"7x"), 1);
        assert_eq!(escape_len(b"q"), 0);
        assert_eq!(escape_len(b""), 0);
    }
}
