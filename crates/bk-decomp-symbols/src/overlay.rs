//! Per-function overlays on a frozen database (spec 5.7, ADR-044).
//!
//! While a function is decompiled the shared [`Database`] is frozen (an
//! `Arc`, `Send + Sync`). Everything the decompilation adds to it goes
//! through an [`Overlay`]: the first change copies the database (later
//! reads see the function's own additions), and every change is logged.
//! [`Overlay::commit`] replays the log on a database in operation order;
//! committing after every function onto the database the overlay was taken
//! from reproduces Ghidra's sequential behaviour exactly, ids included.
//! New objects are matched by creation order, so ids referring to them in
//! later operations are translated on commit.
//!
//! Per-function caches of the other services (strings read, constant-pool
//! records fetched) are plain values the caller keeps per function.

use std::sync::Arc;

use bk_core::{Address, Provenance, Range, SpaceId};
use bk_decomp_types::{TypeFactory, TypeId};

use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::flags::VarnodeFlags;
use crate::ids::{EntryId, ScopeId, SymbolId};

/// One logged change.
#[derive(Clone, Debug)]
enum Op {
    AddSymbol {
        scope: ScopeId,
        name: Box<str>,
        ty: TypeId,
    },
    AddSymbolAt {
        scope: ScopeId,
        name: Box<str>,
        ty: TypeId,
        addr: Address,
        use_point: Address,
    },
    AddFunction {
        scope: ScopeId,
        addr: Address,
        name: Box<str>,
    },
    AddCodeLabel {
        scope: ScopeId,
        addr: Address,
        name: Box<str>,
    },
    AddExternalRef {
        scope: ScopeId,
        addr: Address,
        ref_addr: Address,
        name: Box<str>,
    },
    AddMapPoint {
        sym: SymbolId,
        addr: Address,
        use_point: Address,
    },
    Rename {
        sym: SymbolId,
        name: Box<str>,
        provenance: Provenance,
    },
    Retype {
        sym: SymbolId,
        ty: TypeId,
        provenance: Provenance,
    },
    SetAttribute {
        sym: SymbolId,
        flags: VarnodeFlags,
    },
    ClearAttribute {
        sym: SymbolId,
        flags: VarnodeFlags,
    },
    RemoveSymbol {
        sym: SymbolId,
    },
    SetPropertyRange {
        flags: VarnodeFlags,
        range: Range,
    },
    ClearPropertyRange {
        flags: VarnodeFlags,
        range: Range,
    },
    FindCreateScopeFromName {
        full: Box<str>,
        start: Option<ScopeId>,
    },
    AddRange {
        scope: ScopeId,
        space: SpaceId,
        first: u64,
        last: u64,
    },
}

/// A logged change, whether it failed, and the arena lengths after it.
#[derive(Clone, Debug)]
struct Logged {
    op: Op,
    failed: bool,
    after: [usize; 3],
}

/// The arena lengths of a database: scopes, symbols, entries.
fn lengths(db: &Database) -> [usize; 3] {
    [db.scopes.len(), db.symbols.len(), db.entries.len()]
}

/// A function's additions to a frozen database.
#[derive(Clone, Debug)]
pub struct Overlay {
    base: Arc<Database>,
    work: Option<Database>,
    log: Vec<Logged>,
}

impl Overlay {
    /// An empty overlay on a frozen database.
    pub fn new(base: Arc<Database>) -> Self {
        Self {
            base,
            work: None,
            log: Vec::new(),
        }
    }

    /// The database as this function sees it.
    pub fn db(&self) -> &Database {
        self.work.as_ref().unwrap_or(&self.base)
    }

    /// The number of logged changes.
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Whether nothing was changed.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    fn work(&mut self) -> &mut Database {
        let base = &self.base;
        self.work.get_or_insert_with(|| (**base).clone())
    }

    fn run<T>(&mut self, op: Op, types: &mut TypeFactory) -> Result<T>
    where
        T: FromOutcome,
    {
        let db = self.work();
        let result = apply(db, &op, types);
        let after = lengths(db);
        self.log.push(Logged {
            op,
            failed: result.is_err(),
            after,
        });
        result.and_then(T::from_outcome)
    }

    /// [`Database::add_symbol`] into the overlay.
    pub fn add_symbol(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        self.run(
            Op::AddSymbol {
                scope,
                name: name.into(),
                ty,
            },
            types,
        )
    }

    /// [`Database::add_symbol_at`] into the overlay (what `ActionMapGlobals`
    /// does).
    pub fn add_symbol_at(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        addr: Address,
        use_point: Address,
        types: &mut TypeFactory,
    ) -> Result<EntryId> {
        self.run(
            Op::AddSymbolAt {
                scope,
                name: name.into(),
                ty,
                addr,
                use_point,
            },
            types,
        )
    }

    /// [`Database::add_function`] into the overlay.
    pub fn add_function(
        &mut self,
        scope: ScopeId,
        addr: Address,
        name: &str,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        self.run(
            Op::AddFunction {
                scope,
                addr,
                name: name.into(),
            },
            types,
        )
    }

    /// [`Database::add_code_label`] into the overlay.
    pub fn add_code_label(
        &mut self,
        scope: ScopeId,
        addr: Address,
        name: &str,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        self.run(
            Op::AddCodeLabel {
                scope,
                addr,
                name: name.into(),
            },
            types,
        )
    }

    /// [`Database::add_external_ref`] into the overlay.
    pub fn add_external_ref(
        &mut self,
        scope: ScopeId,
        addr: Address,
        ref_addr: Address,
        name: &str,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        self.run(
            Op::AddExternalRef {
                scope,
                addr,
                ref_addr,
                name: name.into(),
            },
            types,
        )
    }

    /// [`Database::add_map_point`] into the overlay.
    pub fn add_map_point(
        &mut self,
        sym: SymbolId,
        addr: Address,
        use_point: Address,
        types: &mut TypeFactory,
    ) -> Result<EntryId> {
        self.run(
            Op::AddMapPoint {
                sym,
                addr,
                use_point,
            },
            types,
        )
    }

    /// [`Database::rename_symbol_as`] into the overlay.
    pub fn rename_symbol(
        &mut self,
        sym: SymbolId,
        name: &str,
        provenance: Provenance,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(
            Op::Rename {
                sym,
                name: name.into(),
                provenance,
            },
            types,
        )
    }

    /// [`Database::retype_symbol_as`] into the overlay.
    pub fn retype_symbol(
        &mut self,
        sym: SymbolId,
        ty: TypeId,
        provenance: Provenance,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(
            Op::Retype {
                sym,
                ty,
                provenance,
            },
            types,
        )
    }

    /// [`Database::set_attribute`] into the overlay.
    pub fn set_attribute(
        &mut self,
        sym: SymbolId,
        flags: VarnodeFlags,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(Op::SetAttribute { sym, flags }, types)
    }

    /// [`Database::clear_attribute`] into the overlay.
    pub fn clear_attribute(
        &mut self,
        sym: SymbolId,
        flags: VarnodeFlags,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(Op::ClearAttribute { sym, flags }, types)
    }

    /// [`Database::remove_symbol`] into the overlay.
    pub fn remove_symbol(&mut self, sym: SymbolId, types: &mut TypeFactory) -> Result<()> {
        self.run(Op::RemoveSymbol { sym }, types)
    }

    /// [`Database::set_property_range`] into the overlay (a host hole).
    pub fn set_property_range(
        &mut self,
        flags: VarnodeFlags,
        range: Range,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(Op::SetPropertyRange { flags, range }, types)
    }

    /// [`Database::clear_property_range`] into the overlay.
    pub fn clear_property_range(
        &mut self,
        flags: VarnodeFlags,
        range: Range,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(Op::ClearPropertyRange { flags, range }, types)
    }

    /// [`Database::find_create_scope_from_symbol_name`] into the overlay;
    /// returns the scope (the base name is the caller's suffix).
    pub fn find_create_scope_from_symbol_name(
        &mut self,
        full: &str,
        start: Option<ScopeId>,
        types: &mut TypeFactory,
    ) -> Result<ScopeId> {
        self.run(
            Op::FindCreateScopeFromName {
                full: full.into(),
                start,
            },
            types,
        )
    }

    /// [`Database::add_range`] into the overlay.
    pub fn add_range(
        &mut self,
        scope: ScopeId,
        space: SpaceId,
        first: u64,
        last: u64,
        types: &mut TypeFactory,
    ) -> Result<()> {
        self.run(
            Op::AddRange {
                scope,
                space,
                first,
                last,
            },
            types,
        )
    }

    /// Replays the overlay's changes on `into` in operation order. Objects
    /// the overlay created get new ids in `into` (the same ids when `into`
    /// is the database the overlay was taken from); references to them in
    /// later changes are translated. A change that failed in the overlay
    /// must fail again, and one that succeeded must succeed.
    pub fn commit(&self, into: &mut Database, types: &mut TypeFactory) -> Result<()> {
        let base_len = lengths(&self.base);
        let mut work_len = base_len;
        // Per arena: (first new work index, first new target index, count),
        // one span per op that created objects.
        let mut spans: [Vec<(usize, usize, usize)>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for logged in &self.log {
            let op = translate(&logged.op, base_len, &spans)?;
            let before = lengths(into);
            let result = apply(into, &op, types);
            if result.is_err() != logged.failed {
                return Err(SymbolError::Limit(
                    "overlay commit diverged from the overlay",
                ));
            }
            let after = lengths(into);
            let arenas = spans
                .iter_mut()
                .zip(logged.after)
                .zip(work_len)
                .zip(after)
                .zip(before);
            for ((((span, work_after), work_before), into_after), into_before) in arenas {
                let made_work = work_after.saturating_sub(work_before);
                let made_into = into_after.saturating_sub(into_before);
                if made_work != made_into {
                    return Err(SymbolError::Limit(
                        "overlay commit diverged from the overlay",
                    ));
                }
                if made_work > 0 {
                    span.push((work_before, into_before, made_work));
                }
            }
            work_len = logged.after;
        }
        Ok(())
    }
}

/// What an operation returned.
enum Outcome {
    Unit,
    Scope(ScopeId),
    Symbol(SymbolId),
    Entry(EntryId),
}

trait FromOutcome: Sized {
    fn from_outcome(o: Outcome) -> Result<Self>;
}

fn mismatch<T>() -> Result<T> {
    Err(SymbolError::Limit("overlay operation result"))
}

impl FromOutcome for () {
    fn from_outcome(o: Outcome) -> Result<Self> {
        match o {
            Outcome::Unit => Ok(()),
            _ => mismatch(),
        }
    }
}
impl FromOutcome for ScopeId {
    fn from_outcome(o: Outcome) -> Result<Self> {
        match o {
            Outcome::Scope(s) => Ok(s),
            _ => mismatch(),
        }
    }
}
impl FromOutcome for SymbolId {
    fn from_outcome(o: Outcome) -> Result<Self> {
        match o {
            Outcome::Symbol(s) => Ok(s),
            _ => mismatch(),
        }
    }
}
impl FromOutcome for EntryId {
    fn from_outcome(o: Outcome) -> Result<Self> {
        match o {
            Outcome::Entry(e) => Ok(e),
            _ => mismatch(),
        }
    }
}

fn apply(db: &mut Database, op: &Op, types: &mut TypeFactory) -> Result<Outcome> {
    Ok(match op {
        Op::AddSymbol { scope, name, ty } => {
            Outcome::Symbol(db.add_symbol(*scope, name, *ty, types)?)
        }
        Op::AddSymbolAt {
            scope,
            name,
            ty,
            addr,
            use_point,
        } => Outcome::Entry(db.add_symbol_at(*scope, name, *ty, *addr, *use_point, types)?),
        Op::AddFunction { scope, addr, name } => {
            Outcome::Symbol(db.add_function(*scope, *addr, name, types)?)
        }
        Op::AddCodeLabel { scope, addr, name } => {
            Outcome::Symbol(db.add_code_label(*scope, *addr, name, types)?)
        }
        Op::AddExternalRef {
            scope,
            addr,
            ref_addr,
            name,
        } => Outcome::Symbol(db.add_external_ref(*scope, *addr, *ref_addr, name, types)?),
        Op::AddMapPoint {
            sym,
            addr,
            use_point,
        } => Outcome::Entry(db.add_map_point(*sym, *addr, *use_point)?),
        Op::Rename {
            sym,
            name,
            provenance,
        } => {
            db.rename_symbol_as(*sym, name, *provenance)?;
            Outcome::Unit
        }
        Op::Retype {
            sym,
            ty,
            provenance,
        } => {
            db.retype_symbol_as(*sym, *ty, *provenance, types)?;
            Outcome::Unit
        }
        Op::SetAttribute { sym, flags } => {
            db.set_attribute(*sym, *flags)?;
            Outcome::Unit
        }
        Op::ClearAttribute { sym, flags } => {
            db.clear_attribute(*sym, *flags)?;
            Outcome::Unit
        }
        Op::RemoveSymbol { sym } => {
            db.remove_symbol(*sym)?;
            Outcome::Unit
        }
        Op::SetPropertyRange { flags, range } => {
            db.set_property_range(*flags, range);
            Outcome::Unit
        }
        Op::ClearPropertyRange { flags, range } => {
            db.clear_property_range(*flags, range);
            Outcome::Unit
        }
        Op::FindCreateScopeFromName { full, start } => {
            Outcome::Scope(db.find_create_scope_from_symbol_name(full, *start)?.0)
        }
        Op::AddRange {
            scope,
            space,
            first,
            last,
        } => {
            db.add_range(*scope, *space, *first, *last)?;
            Outcome::Unit
        }
    })
}

/// Maps an id of the overlay's database to the target's.
fn map_index(index: u32, base: usize, spans: &[(usize, usize, usize)]) -> Result<u32> {
    let i = index as usize;
    if i < base {
        return Ok(index);
    }
    for &(work, target, count) in spans {
        if i >= work && i < work + count {
            return u32::try_from(target + (i - work))
                .map_err(|_out_of_range| SymbolError::Limit("arena index"));
        }
    }
    Err(SymbolError::StaleId {
        kind: "overlay object",
        index,
    })
}

fn translate(op: &Op, base: [usize; 3], spans: &[Vec<(usize, usize, usize)>; 3]) -> Result<Op> {
    let scope = |s: ScopeId| map_index(s.0, base[0], &spans[0]).map(ScopeId);
    let sym = |s: SymbolId| map_index(s.0, base[1], &spans[1]).map(SymbolId);
    let mut op = op.clone();
    match &mut op {
        Op::AddSymbol { scope: s, .. }
        | Op::AddSymbolAt { scope: s, .. }
        | Op::AddFunction { scope: s, .. }
        | Op::AddCodeLabel { scope: s, .. }
        | Op::AddExternalRef { scope: s, .. }
        | Op::AddRange { scope: s, .. } => *s = scope(*s)?,
        Op::FindCreateScopeFromName { start, .. } => {
            if let Some(s) = start {
                *s = scope(*s)?;
            }
        }
        Op::AddMapPoint { sym: s, .. }
        | Op::Rename { sym: s, .. }
        | Op::Retype { sym: s, .. }
        | Op::SetAttribute { sym: s, .. }
        | Op::ClearAttribute { sym: s, .. }
        | Op::RemoveSymbol { sym: s } => *s = sym(*s)?,
        Op::SetPropertyRange { .. } | Op::ClearPropertyRange { .. } => {}
    }
    Ok(op)
}
