//! `with` blocks (inventory 9.4; `SleighCompile::pushWith`, `popWith`,
//! `WithBlock`).

use bk_sleigh_syntax::ast::WithBlock;

use super::{Compiler, Fatal, WithFrame};

impl<'a> Compiler<'a> {
    /// A `with` block: its header is elaborated once, in the scope that is
    /// current at the block, then the enclosed items.
    pub(crate) fn with_block(&mut self, w: &'a WithBlock) -> Result<(), Fatal> {
        self.lock_context_at(w.span);
        let table = match w.table {
            None => None,
            Some(ident) => match self.table_named(ident) {
                Some(t) => Some(t),
                // Ghidra's parser recovers at the next `}`; the block's
                // items are lost.
                None => return Ok(()),
            },
        };
        let pattern = match w.pattern {
            None => None,
            Some(eq) => match self.equation(eq) {
                Ok(e) => Some(e),
                Err(_) => return Ok(()),
            },
        };
        let context = match &w.context {
            None => Vec::new(),
            Some(block) => match self.context_block(block) {
                Ok(c) => c,
                Err(_) => return Ok(()),
            },
        };
        if self.fatal {
            return Err(Fatal);
        }
        self.with_stack.push(WithFrame { table, pattern, context });
        let result = self.items(&w.items);
        self.with_stack.pop();
        result
    }
}
