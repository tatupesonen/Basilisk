//! The decode dump of `cspec_oracle.cc`, produced from a `CompilerSpec`
//! in the same record formats.

use bk_core::{RangeList, SpaceManager};
use bk_cspec::list::ParamList;
use bk_cspec::model::{ProtoModel, SharedAction};
use bk_cspec::rules::{AssignAction, DatatypeFilter, ModelRule, QualifierFilter, SizeRestriction};
use bk_cspec::{CompilerSpec, ListKind};

use super::{b, vn};

fn size_desc(s: &SizeRestriction) -> String {
    let sizes: Vec<String> = s.sizes.iter().map(i32::to_string).collect();
    format!("[{},{},{{{}}}]", s.min, s.max, sizes.join(" "))
}

fn filter_desc(f: &DatatypeFilter) -> String {
    match f {
        DatatypeFilter::Homogeneous {
            meta,
            max_primitives,
            size,
        } => format!("homog:{}:{max_primitives}{}", meta.name(), size_desc(size)),
        DatatypeFilter::Array {
            size,
            min_elements,
            max_elements,
        } => format!("array{}el[{min_elements},{max_elements}]", size_desc(size)),
        DatatypeFilter::Meta { meta, size } => format!("meta:{}{}", meta.name(), size_desc(size)),
        DatatypeFilter::Size(size) => format!("any{}", size_desc(size)),
        _ => "?".into(),
    }
}

fn qual_desc(q: &QualifierFilter) -> String {
    match q {
        QualifierFilter::And(list) => {
            let parts: Vec<String> = list.iter().map(qual_desc).collect();
            format!("and({})", parts.join(","))
        }
        QualifierFilter::Varargs { first, last } => format!("varargs({first},{last})"),
        QualifierFilter::Position(p) => format!("pos({p})"),
        QualifierFilter::DatatypeAt { position, filter } => {
            format!("at({position},{})", filter_desc(filter))
        }
        _ => "?".into(),
    }
}

fn idx(e: Option<usize>) -> String {
    e.map_or_else(|| "-1".into(), |i| i.to_string())
}

fn tiles(t: &[usize]) -> String {
    let v: Vec<String> = t.iter().map(usize::to_string).collect();
    format!("{{{}}}", v.join(" "))
}

fn action_desc(a: &AssignAction) -> String {
    match a {
        AssignAction::GotoStack { stack } => format!("goto_stack({stack})"),
        AssignAction::ConvertToPointer { space } => format!(
            "convert_to_ptr({})",
            space.map_or_else(|| "-1".into(), |s| s.index().to_string())
        ),
        AssignAction::MultiSlot(m) => format!(
            "join({},{}{}{}{}{}{},{},{})",
            m.resource as u8,
            b(m.big_endian),
            b(m.consume_from_stack),
            b(m.consume_most_sig),
            b(m.enforce_alignment),
            b(m.justify_right),
            b(m.allow_backfill),
            tiles(&m.tiles),
            idx(m.stack)
        ),
        AssignAction::MultiMember(m) => format!(
            "join_per_primitive({},{}{}{},{})",
            m.resource as u8,
            b(m.recursive),
            b(m.consume_from_stack),
            b(m.consume_most_sig),
            idx(m.stack)
        ),
        AssignAction::DualClass(m) => format!(
            "join_dual_class({},{},{}{}{}{}{},{},{},{},{})",
            m.base as u8,
            m.alt as u8,
            b(m.big_endian),
            b(m.consume_from_stack),
            b(m.consume_most_sig),
            b(m.justify_right),
            b(m.fill_alternate),
            m.tile_size,
            tiles(&m.base_tiles),
            tiles(&m.alt_tiles),
            idx(m.stack)
        ),
        AssignAction::ConsumeAs { class } => format!("consume({})", *class as u8),
        AssignAction::HiddenReturn { code } => format!("hidden_return({})", *code as u8),
        AssignAction::ConsumeExtra {
            class,
            match_size,
            tiles: t,
        } => format!(
            "consume_extra({},{},{})",
            *class as u8,
            b(*match_size),
            tiles(t)
        ),
        AssignAction::ExtraStack {
            after_bytes,
            after_storage,
            stack,
        } => format!(
            "extra_stack({after_bytes},{},{stack})",
            *after_storage as u8
        ),
        AssignAction::ConsumeRemaining { class, tiles: t } => {
            format!("consume_remaining({},{})", *class as u8, tiles(t))
        }
        _ => "?".into(),
    }
}

pub(crate) fn rule_desc(r: &ModelRule) -> String {
    let pre: Vec<String> = r.preconditions.iter().map(action_desc).collect();
    let side: Vec<String> = r.side_effects.iter().map(action_desc).collect();
    format!(
        "{} | {} | {} | {} | {}",
        filter_desc(&r.filter),
        r.qualifier.as_ref().map_or_else(|| "-".into(), qual_desc),
        pre.join(";"),
        action_desc(&r.assign),
        side.join(";")
    )
}

fn list_records(model: &str, io: &str, list: &ParamList, out: &mut Vec<(String, String)>) {
    let merged = list.kind() == ListKind::Merged;
    let fallback = if list.kind().is_output() {
        b(list.uses_fillin_fallback()).to_owned()
    } else {
        "-".to_owned()
    };
    let rs: Vec<String> = list.resource_start().iter().map(i32::to_string).collect();
    let dash = |s: String| if merged { "-".to_owned() } else { s };
    out.push((
        "LIST".into(),
        format!(
            "{model}\t{io}\t{}\t{}\t{}\t{}\t{}\t{}\t{fallback}",
            list.kind().name(),
            dash(list.num_groups().to_string()),
            dash(list.max_delay().to_string()),
            dash(b(list.is_this_before_ret_pointer()).into()),
            dash(b(list.is_auto_killed_by_call()).into()),
            dash(rs.join(",")),
        ),
    ));
    for (i, e) in list.entries().iter().enumerate() {
        let groups: Vec<String> = e.all_groups().iter().map(i32::to_string).collect();
        let join = e.join_pieces().map_or_else(
            || "-".into(),
            |p| p.iter().map(vn).collect::<Vec<_>>().join(","),
        );
        let a = super::addr(e.address(), e.size());
        out.push((
            "ENTRY".into(),
            format!(
                "{model}\t{io}\t{i}\t{a}\t{}\t{}\t{}\t{}\t{}\t{}\t{join}",
                e.min_size(),
                e.align(),
                e.num_slots(),
                e.type_class() as u8,
                groups.join(","),
                e.flags().bits()
            ),
        ));
    }
    for (i, r) in list.rules().iter().enumerate() {
        out.push((
            "RULE".into(),
            format!("{model}\t{io}\t{i}\t{}", rule_desc(r)),
        ));
    }
}

fn ranges(kind: &str, model: &str, r: &RangeList, out: &mut Vec<(String, String)>) {
    for range in r.iter() {
        out.push((
            kind.into(),
            format!(
                "{model}\t{}\t{:x}\t{:x}",
                range.space().index(),
                range.first(),
                range.last()
            ),
        ));
    }
}

/// The MODEL … PRANGE records of one model; `inject_base` is added to
/// payload ids (the payloads the `.pspec` declared first).
pub(crate) fn model_records(
    spec: &CompilerSpec,
    m: &ProtoModel,
    inject_base: i64,
    out: &mut Vec<(String, String)>,
) {
    let name = m.name();
    let alias = m
        .alias_of()
        .and_then(|a| spec.model(a))
        .map_or("-", ProtoModel::name);
    let inj = |v: Option<u32>| v.map_or(-1, |i| i64::from(i) + inject_base);
    out.push((
        "MODEL".into(),
        format!(
            "{name}\t{}\t{}\t{alias}\t{}\t{}\t{}\t{}\t{}\t{}",
            m.extrapop(),
            b(m.is_merged()),
            b(m.has_this_pointer()),
            b(m.is_constructor()),
            b(m.print_in_decl()),
            b(m.is_stack_grows_negative()),
            inj(m.inject_upon_entry()),
            inj(m.inject_upon_return())
        ),
    ));
    list_records(name, "in", m.input(), out);
    list_records(name, "out", m.output(), out);
    for (i, a) in m.shared_actions().iter().enumerate() {
        let d = match a {
            SharedAction::ShareStack {
                input_first,
                extra_align,
                input_stack,
                output_stack,
            } => format!(
                "sharestack({},{extra_align},{},{})",
                b(*input_first),
                idx(*input_stack),
                idx(*output_stack)
            ),
            _ => "hidden_return".into(),
        };
        out.push(("SHARED".into(), format!("{name}\t{i}\t{d}")));
    }
    for e in m.effects() {
        out.push((
            "EFFECT".into(),
            format!("{name}\t{}\t{}", e.kind as u8, vn(&e.range)),
        ));
    }
    for v in m.likely_trash() {
        out.push(("TRASH".into(), format!("{name}\t{}", vn(v))));
    }
    for v in m.internal_storage() {
        out.push(("INTERNAL".into(), format!("{name}\t{}", vn(v))));
    }
    ranges("LRANGE", name, m.local_range(), out);
    ranges("PRANGE", name, m.param_range(), out);
}

/// SPEC, SPLIT, GLOBAL records.
pub(crate) fn spec_records(spec: &CompilerSpec, m: &SpaceManager, out: &mut Vec<(String, String)>) {
    let name = |id: Option<bk_cspec::ModelId>| {
        id.and_then(|i| spec.model(i))
            .map_or_else(|| "-".to_owned(), |x| x.name().to_owned())
    };
    out.push((
        "SPEC".into(),
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            spec.default_model_name(),
            name(spec.eval_current()),
            name(spec.eval_called()),
            spec.funcptr_align(),
            b(spec.aggressive_trim()),
            spec.default_return_address()
                .map_or_else(|| "-".into(), |v| vn(&v))
        ),
    ));
    for s in spec.prefer_split() {
        out.push((
            "SPLIT".into(),
            format!("{}\t{}", vn(&s.storage), s.split_offset),
        ));
    }
    let mut globals = RangeList::new();
    for g in spec.globals() {
        if let Ok(r) = bk_core::Range::from_properties(g, m) {
            globals.insert(r);
        }
    }
    if let Some(other) = m.space_by_name("OTHER") {
        globals.insert_range(other.id(), 0, other.highest());
    }
    for r in globals.iter() {
        out.push((
            "GLOBAL".into(),
            format!("{}\t{:x}\t{:x}", r.space().index(), r.first(), r.last()),
        ));
    }
}
