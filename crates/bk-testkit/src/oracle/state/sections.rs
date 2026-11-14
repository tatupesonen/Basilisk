//! The sections of a state dump and the order of records inside each.

use crate::oracle::structure::{self, NodeName, StructNode};
use crate::oracle::text::{
    Lines, ParseError, ParseErrorKind, Record, escape, push_display, shown, unescape,
};

use super::records::{
    ActionRecord, ActiveRecord, BlockRecord, CLineRecord, CallSpecRecord, CommentRecord,
    CounterRecord, DisjointRecord, DynamicRecommendRecord, EdgeRecord, EffectRecord,
    ForeignSymbolRecord, FunctionRecord, GuardRecord, HeritageInfoRecord, HeritageRecord,
    HighRecord, JumpTableRecord, LanedRecord, LoadCopyRecord, LoadTableRecord, MapEntryRecord,
    NameRecommendRecord, OpListRecord, OpRecord, OrderRecord, OverrideRecord, ParamRecord,
    ProtoRecord, RuleRecord, ScopeRecord, SpaceRecord, SymbolRecord, TrashRecord, TrialRecord,
    TypeRecommendRecord, TypeRecord, UnionRecord, VarnodeRecord,
};

/// The sections, in the order a dump has them.
const SECTIONS: [&str; 18] = [
    "function",
    "actions",
    "spaces",
    "varnodes",
    "locorder",
    "deforder",
    "ops",
    "oplists",
    "blocks",
    "structure",
    "proto",
    "callspecs",
    "jumptables",
    "scope",
    "heritage",
    "highs",
    "types",
    "c",
];

/// The most records one section may have.
const MAX_SECTION_RECORDS: usize = 10_000_000;

/// A whole state dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDump {
    /// The Ghidra commit the extension was built from.
    pub ghidra_commit: String,
    /// The architecture id (`x86:LE:64:default:gcc`).
    pub arch_id: String,
    /// `@function`.
    pub function: FunctionSection,
    /// `@actions`: every action and rule of the current root, in position order.
    pub actions: Vec<ActionLineRecord>,
    /// `@spaces`.
    pub spaces: Vec<SpaceRecord>,
    /// `@varnodes`, in create-index order.
    pub varnodes: Vec<VarnodeRecord>,
    /// `@locorder`: the loc bank order with canonical keys.
    pub loc_order: OrderRecord,
    /// `@deforder`: the def bank order with canonical keys.
    pub def_order: OrderRecord,
    /// `@ops`, in sequence-number order.
    pub ops: Vec<OpRecord>,
    /// `@oplists`.
    pub op_lists: Vec<OpListRecord>,
    /// `@blocks`.
    pub blocks: Vec<BlockEntry>,
    /// `@structure`: the structured hierarchy (`S` records, then `P`), when non-empty.
    pub structure: Option<(Vec<StructNode>, Vec<NodeName>)>,
    /// `@proto`: the function's prototype and output trials.
    pub proto: ProtoGroup,
    /// `@callspecs`.
    pub call_specs: Vec<CallSpecEntry>,
    /// `@jumptables`.
    pub jump_tables: Vec<JumpTableEntry>,
    /// `@scope`.
    pub scope: ScopeSection,
    /// `@heritage`.
    pub heritage: HeritageSection,
    /// `@highs`.
    pub highs: Vec<HighRecord>,
    /// `@types`.
    pub types: Vec<TypeRecord>,
    /// `@c`: the decompiled C, when the function is complete.
    pub c: Vec<CLineRecord>,
}

/// `@function`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSection {
    /// `F`.
    pub function: FunctionRecord,
    /// `K`.
    pub counters: CounterRecord,
    /// `W`: the function's comments, warnings included.
    pub comments: Vec<CommentRecord>,
    /// `O`: local overrides, when there are any.
    pub overrides: Option<OverrideRecord>,
    /// `X`: `lanedMap`.
    pub laned: Vec<LanedRecord>,
    /// `U`: `unionMap`.
    pub unions: Vec<UnionRecord>,
}

/// An `@actions` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionLineRecord {
    /// `A`.
    Action(ActionRecord),
    /// `R`.
    Rule(RuleRecord),
}

/// A `B` record and its in-edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    /// `B`.
    pub block: BlockRecord,
    /// `E`, in order.
    pub in_edges: Vec<EdgeRecord>,
}

/// A prototype: `M`, `Q`*, `X`*, `Y`*, then each `ParamActive`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoGroup {
    /// `M`.
    pub proto: ProtoRecord,
    /// `Q`.
    pub params: Vec<ParamRecord>,
    /// `X`.
    pub effects: Vec<EffectRecord>,
    /// `Y`.
    pub likely_trash: Vec<TrashRecord>,
    /// `A` and its `T` records.
    pub active: Vec<ActiveGroup>,
}

/// A `ParamActive` and its trials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGroup {
    /// `A`.
    pub active: ActiveRecord,
    /// `T`, in trial order.
    pub trials: Vec<TrialRecord>,
}

/// A call spec and its prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSpecEntry {
    /// `C`.
    pub call: CallSpecRecord,
    /// Its prototype and trials.
    pub proto: ProtoGroup,
}

/// A jump table and its load tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTableEntry {
    /// `J`.
    pub table: JumpTableRecord,
    /// `D`.
    pub loads: Vec<LoadTableRecord>,
}

/// `@scope`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSection {
    /// `Z`, when the function has a local scope.
    pub scope: Option<ScopeRecord>,
    /// `N`.
    pub name_recommends: Vec<NameRecommendRecord>,
    /// `D`.
    pub dynamic_recommends: Vec<DynamicRecommendRecord>,
    /// `Y`.
    pub type_recommends: Vec<TypeRecommendRecord>,
    /// `S` and their `M` records, in symbol-id order.
    pub symbols: Vec<SymbolEntryGroup>,
    /// `G`.
    pub foreign: Vec<ForeignSymbolRecord>,
}

/// A symbol and its map entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolEntryGroup {
    /// `S`.
    pub symbol: SymbolRecord,
    /// `M`, in `mapentry` order.
    pub entries: Vec<MapEntryRecord>,
}

/// `@heritage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeritageSection {
    /// `Z`.
    pub heritage: HeritageRecord,
    /// `I`.
    pub spaces: Vec<HeritageInfoRecord>,
    /// `M`.
    pub disjoint: Vec<DisjointRecord>,
    /// `L`.
    pub guards: Vec<GuardRecord>,
    /// `C`.
    pub load_copies: LoadCopyRecord,
}

/// The records of one section, read front to back.
struct Section<'a> {
    name: &'static str,
    header_line: usize,
    records: Vec<Record<'a>>,
    next: usize,
}

impl<'a> Section<'a> {
    fn peek(&self) -> Option<&str> {
        self.records.get(self.next).map(Record::tag)
    }

    fn take(&mut self, what: &'static str) -> Result<&Record<'a>, ParseError> {
        let line = self.header_line + self.next + 1;
        let record = self.records.get(self.next).ok_or_else(|| ParseError {
            format: "bkstate",
            line,
            kind: ParseErrorKind::Inconsistent {
                reason: format!("section @{} ends where {what} was expected", self.name),
            },
        })?;
        self.next += 1;
        Ok(record)
    }

    /// Every following record with tag `tag`, parsed.
    fn many<T>(
        &mut self,
        tag: &str,
        parse: fn(&Record<'_>) -> Result<T, ParseError>,
    ) -> Result<Vec<T>, ParseError> {
        let mut out = Vec::new();
        while self.peek() == Some(tag) {
            out.push(parse(self.take("a record")?)?);
        }
        Ok(out)
    }

    fn one<T>(
        &mut self,
        what: &'static str,
        parse: fn(&Record<'_>) -> Result<T, ParseError>,
    ) -> Result<T, ParseError> {
        parse(self.take(what)?)
    }

    fn finish(self) -> Result<(), ParseError> {
        match self.records.get(self.next) {
            None => Ok(()),
            Some(r) => Err(r.error(ParseErrorKind::UnexpectedRecord {
                expected: "the end of the section",
                found: shown(r.text),
            })),
        }
    }
}

fn proto_group(s: &mut Section<'_>) -> Result<ProtoGroup, ParseError> {
    let proto = s.one("an M record", ProtoRecord::parse)?;
    let params = s.many(ParamRecord::TAG, ParamRecord::parse)?;
    let effects = s.many(EffectRecord::TAG, EffectRecord::parse)?;
    let likely_trash = s.many(TrashRecord::TAG, TrashRecord::parse)?;
    let mut active = Vec::new();
    while s.peek() == Some(ActiveRecord::TAG) {
        let a = s.one("an A record", ActiveRecord::parse)?;
        let trials = s.many(TrialRecord::TAG, TrialRecord::parse)?;
        active.push(ActiveGroup { active: a, trials });
    }
    Ok(ProtoGroup {
        proto,
        params,
        effects,
        likely_trash,
        active,
    })
}

fn write_proto_group(out: &mut String, g: &ProtoGroup) {
    g.proto.write(out);
    for r in &g.params {
        r.write(out);
    }
    for r in &g.effects {
        r.write(out);
    }
    for r in &g.likely_trash {
        r.write(out);
    }
    for a in &g.active {
        a.active.write(out);
        for r in &a.trials {
            r.write(out);
        }
    }
}

fn proto_group_len(g: &ProtoGroup) -> usize {
    1 + g.params.len()
        + g.effects.len()
        + g.likely_trash.len()
        + g.active.iter().map(|a| 1 + a.trials.len()).sum::<usize>()
}

impl StateDump {
    /// Read a state dump.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut lines = Lines::new("bkstate", text)?;
        let h = lines.next_line("the BKSTATE header")?;
        h.expect("BKSTATE", 4, "the BKSTATE header")?;
        if h.field(1) != "1" {
            return Err(h.error(ParseErrorKind::UnsupportedVersion {
                version: shown(h.field(1)),
            }));
        }
        let ghidra_commit =
            unescape(h.field(2)).ok_or_else(|| h.bad("ghidra commit", h.field(2)))?;
        let arch_id = unescape(h.field(3)).ok_or_else(|| h.bad("architecture id", h.field(3)))?;
        let mut sections = Vec::with_capacity(SECTIONS.len());
        let mut total = 1_usize;
        for name in SECTIONS {
            let head = lines.next_line("a section header")?;
            let expected = format!("@{name}");
            if head.tag() != expected {
                return Err(head.error(ParseErrorKind::UnexpectedRecord {
                    expected: "the next section header",
                    found: shown(head.text),
                }));
            }
            if head.fields.len() != 2 {
                return Err(head.error(ParseErrorKind::FieldCount {
                    record: "section header",
                    expected: 2,
                    found: head.fields.len(),
                }));
            }
            let count = head.u32_at(1, "record count")? as usize;
            if count > MAX_SECTION_RECORDS {
                return Err(head.error(ParseErrorKind::TooMany {
                    what: "records in one section",
                    limit: MAX_SECTION_RECORDS,
                }));
            }
            let mut records = Vec::with_capacity(count.min(4096));
            for _ in 0..count {
                records.push(lines.next_line("a record of the section")?);
            }
            total += count + 1;
            sections.push(Section {
                name,
                header_line: head.number,
                records,
                next: 0,
            });
        }
        let end = lines.next_line("the END record")?;
        end.expect("END", 2, "the END record")?;
        if end.u32_at(1, "line count")? as usize != total {
            return Err(end.bad("line count (truncated or edited?)", end.field(1)));
        }
        if lines.peek_tag().is_some() {
            return Err(lines.error_at(end.number + 1, ParseErrorKind::TrailingText));
        }
        let mut it = sections.into_iter();
        let mut next = || {
            it.next().ok_or_else(|| ParseError {
                format: "bkstate",
                line: 0,
                kind: ParseErrorKind::Inconsistent {
                    reason: "missing section".into(),
                },
            })
        };

        let mut s = next()?;
        let function = FunctionSection {
            function: s.one("the F record", FunctionRecord::parse)?,
            counters: s.one("the K record", CounterRecord::parse)?,
            comments: s.many(CommentRecord::TAG, CommentRecord::parse)?,
            overrides: s.many(OverrideRecord::TAG, OverrideRecord::parse)?.pop(),
            laned: s.many(LanedRecord::TAG, LanedRecord::parse)?,
            unions: s.many(UnionRecord::TAG, UnionRecord::parse)?,
        };
        s.finish()?;

        let mut s = next()?;
        let mut actions = Vec::new();
        while let Some(tag) = s.peek() {
            actions.push(match tag {
                "A" => ActionLineRecord::Action(s.one("an A record", ActionRecord::parse)?),
                _ => ActionLineRecord::Rule(s.one("an R record", RuleRecord::parse)?),
            });
        }
        s.finish()?;

        let mut s = next()?;
        let spaces = s.many(SpaceRecord::TAG, SpaceRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let varnodes = s.many(VarnodeRecord::TAG, VarnodeRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let loc_order = s.one("the O record", OrderRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let def_order = s.one("the O record", OrderRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let ops = s.many(OpRecord::TAG, OpRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let op_lists = s.many(OpListRecord::TAG, OpListRecord::parse)?;
        s.finish()?;

        let mut s = next()?;
        let mut blocks = Vec::new();
        while s.peek().is_some() {
            let block = s.one("a B record", BlockRecord::parse)?;
            let in_edges = s.many(EdgeRecord::TAG, EdgeRecord::parse)?;
            blocks.push(BlockEntry { block, in_edges });
        }
        s.finish()?;

        let mut s = next()?;
        let structure = if s.peek().is_some() {
            let nodes = s.many("S", structure::parse_node)?;
            let top = s.one("the P record", structure::parse_top)?;
            Some((nodes, top))
        } else {
            None
        };
        s.finish()?;

        let mut s = next()?;
        let proto = proto_group(&mut s)?;
        s.finish()?;

        let mut s = next()?;
        let mut call_specs = Vec::new();
        while s.peek().is_some() {
            let call = s.one("a C record", CallSpecRecord::parse)?;
            let proto = proto_group(&mut s)?;
            call_specs.push(CallSpecEntry { call, proto });
        }
        s.finish()?;

        let mut s = next()?;
        let mut jump_tables = Vec::new();
        while s.peek().is_some() {
            let table = s.one("a J record", JumpTableRecord::parse)?;
            let loads = s.many(LoadTableRecord::TAG, LoadTableRecord::parse)?;
            jump_tables.push(JumpTableEntry { table, loads });
        }
        s.finish()?;

        let mut s = next()?;
        let mut scope = ScopeSection {
            scope: s.many(ScopeRecord::TAG, ScopeRecord::parse)?.pop(),
            name_recommends: s.many(NameRecommendRecord::TAG, NameRecommendRecord::parse)?,
            dynamic_recommends: s
                .many(DynamicRecommendRecord::TAG, DynamicRecommendRecord::parse)?,
            type_recommends: s.many(TypeRecommendRecord::TAG, TypeRecommendRecord::parse)?,
            ..ScopeSection::default()
        };
        while s.peek() == Some(SymbolRecord::TAG) {
            let symbol = s.one("an S record", SymbolRecord::parse)?;
            let entries = s.many(MapEntryRecord::TAG, MapEntryRecord::parse)?;
            scope.symbols.push(SymbolEntryGroup { symbol, entries });
        }
        scope.foreign = s.many(ForeignSymbolRecord::TAG, ForeignSymbolRecord::parse)?;
        s.finish()?;

        let mut s = next()?;
        let heritage = HeritageSection {
            heritage: s.one("the Z record", HeritageRecord::parse)?,
            spaces: s.many(HeritageInfoRecord::TAG, HeritageInfoRecord::parse)?,
            disjoint: s.many(DisjointRecord::TAG, DisjointRecord::parse)?,
            guards: s.many(GuardRecord::TAG, GuardRecord::parse)?,
            load_copies: s.one("the C record", LoadCopyRecord::parse)?,
        };
        s.finish()?;

        let mut s = next()?;
        let highs = s.many(HighRecord::TAG, HighRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let types = s.many(TypeRecord::TAG, TypeRecord::parse)?;
        s.finish()?;
        let mut s = next()?;
        let c = s.many(CLineRecord::TAG, CLineRecord::parse)?;
        s.finish()?;

        Ok(Self {
            ghidra_commit,
            arch_id,
            function,
            actions,
            spaces,
            varnodes,
            loc_order,
            def_order,
            ops,
            op_lists,
            blocks,
            structure,
            proto,
            call_specs,
            jump_tables,
            scope,
            heritage,
            highs,
            types,
            c,
        })
    }

    /// The dump's text; `write(parse(text)) == text` for any parsed text.
    pub fn write(&self) -> String {
        let mut out = String::new();
        let mut total = 1_usize;
        out.push_str("BKSTATE\t1\t");
        out.push_str(&escape(&self.ghidra_commit));
        out.push('\t');
        out.push_str(&escape(&self.arch_id));
        out.push('\n');
        let mut section =
            |out: &mut String, name: &str, count: usize, body: &dyn Fn(&mut String)| {
                out.push('@');
                out.push_str(name);
                out.push('\t');
                push_display(out, &count);
                out.push('\n');
                body(out);
                total += count + 1;
            };
        let f = &self.function;
        let n = 2
            + f.comments.len()
            + usize::from(f.overrides.is_some())
            + f.laned.len()
            + f.unions.len();
        section(&mut out, "function", n, &|o| {
            f.function.write(o);
            f.counters.write(o);
            for r in &f.comments {
                r.write(o);
            }
            if let Some(r) = &f.overrides {
                r.write(o);
            }
            for r in &f.laned {
                r.write(o);
            }
            for r in &f.unions {
                r.write(o);
            }
        });
        section(&mut out, "actions", self.actions.len(), &|o| {
            for a in &self.actions {
                match a {
                    ActionLineRecord::Action(r) => r.write(o),
                    ActionLineRecord::Rule(r) => r.write(o),
                }
            }
        });
        section(&mut out, "spaces", self.spaces.len(), &|o| {
            for r in &self.spaces {
                r.write(o);
            }
        });
        section(&mut out, "varnodes", self.varnodes.len(), &|o| {
            for r in &self.varnodes {
                r.write(o);
            }
        });
        section(&mut out, "locorder", 1, &|o| self.loc_order.write(o));
        section(&mut out, "deforder", 1, &|o| self.def_order.write(o));
        section(&mut out, "ops", self.ops.len(), &|o| {
            for r in &self.ops {
                r.write(o);
            }
        });
        section(&mut out, "oplists", self.op_lists.len(), &|o| {
            for r in &self.op_lists {
                r.write(o);
            }
        });
        let n = self.blocks.iter().map(|b| 1 + b.in_edges.len()).sum();
        section(&mut out, "blocks", n, &|o| {
            for b in &self.blocks {
                b.block.write(o);
                for r in &b.in_edges {
                    r.write(o);
                }
            }
        });
        let n = self
            .structure
            .as_ref()
            .map_or(0, |(nodes, _)| nodes.len() + 1);
        section(&mut out, "structure", n, &|o| {
            if let Some((nodes, top)) = &self.structure {
                for node in nodes {
                    structure::write_node(o, node);
                }
                structure::write_top(o, top);
            }
        });
        section(&mut out, "proto", proto_group_len(&self.proto), &|o| {
            write_proto_group(o, &self.proto);
        });
        let n = self
            .call_specs
            .iter()
            .map(|c| 1 + proto_group_len(&c.proto))
            .sum();
        section(&mut out, "callspecs", n, &|o| {
            for c in &self.call_specs {
                c.call.write(o);
                write_proto_group(o, &c.proto);
            }
        });
        let n = self.jump_tables.iter().map(|j| 1 + j.loads.len()).sum();
        section(&mut out, "jumptables", n, &|o| {
            for j in &self.jump_tables {
                j.table.write(o);
                for r in &j.loads {
                    r.write(o);
                }
            }
        });
        let sc = &self.scope;
        let n = usize::from(sc.scope.is_some())
            + sc.name_recommends.len()
            + sc.dynamic_recommends.len()
            + sc.type_recommends.len()
            + sc.symbols
                .iter()
                .map(|s| 1 + s.entries.len())
                .sum::<usize>()
            + sc.foreign.len();
        section(&mut out, "scope", n, &|o| {
            if let Some(r) = &sc.scope {
                r.write(o);
            }
            for r in &sc.name_recommends {
                r.write(o);
            }
            for r in &sc.dynamic_recommends {
                r.write(o);
            }
            for r in &sc.type_recommends {
                r.write(o);
            }
            for s in &sc.symbols {
                s.symbol.write(o);
                for r in &s.entries {
                    r.write(o);
                }
            }
            for r in &sc.foreign {
                r.write(o);
            }
        });
        let h = &self.heritage;
        let n = 2 + h.spaces.len() + h.disjoint.len() + h.guards.len();
        section(&mut out, "heritage", n, &|o| {
            h.heritage.write(o);
            for r in &h.spaces {
                r.write(o);
            }
            for r in &h.disjoint {
                r.write(o);
            }
            for r in &h.guards {
                r.write(o);
            }
            h.load_copies.write(o);
        });
        section(&mut out, "highs", self.highs.len(), &|o| {
            for r in &self.highs {
                r.write(o);
            }
        });
        section(&mut out, "types", self.types.len(), &|o| {
            for r in &self.types {
                r.write(o);
            }
        });
        section(&mut out, "c", self.c.len(), &|o| {
            for r in &self.c {
                r.write(o);
            }
        });
        out.push_str("END\t");
        push_display(&mut out, &total);
        out.push('\n');
        out
    }

    /// The varnode named `id`.
    pub fn varnode(&self, id: super::ids::VarnodeId) -> Option<&VarnodeRecord> {
        self.varnodes
            .binary_search_by_key(&id.0, |v| v.id.0)
            .ok()
            .and_then(|i| self.varnodes.get(i))
    }

    /// The op with sequence number `seq`.
    pub fn op(&self, seq: &super::ids::SeqNum) -> Option<&OpRecord> {
        self.ops.iter().find(|o| &o.seq == seq)
    }

    /// The type named `t`.
    pub fn data_type(&self, t: super::ids::TypeRef) -> Option<&TypeRecord> {
        self.types.get(t.0 as usize)
    }
}
