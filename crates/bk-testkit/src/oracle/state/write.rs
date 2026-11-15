//! Writing a state dump back: the inverse of `StateDump::parse`, byte for byte.

use crate::oracle::structure;
use crate::oracle::text::{escape, push_display};

use super::scope::ScopeOrders;
use super::sections::{ActionLineRecord, ProtoGroup, StateDump};

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
    /// The dump's text; `write(parse(text)) == text` for any parsed text.
    pub fn write(&self) -> String {
        let mut out = String::new();
        let mut total = 1_usize;
        out.push_str("BKSTATE\t");
        push_display(&mut out, &self.version);
        out.push('\t');
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
            + sc.foreign.len()
            + sc.orders.as_ref().map_or(0, ScopeOrders::len);
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
            if let Some(orders) = &sc.orders {
                orders.write(o);
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
}
