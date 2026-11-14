//! The kind-specific field of an `S` record.

use super::{KindData, NodeKind, NodeName, SwitchCase};
use crate::oracle::text::{hex, list_items, parse_hex_u64, parse_i32, push_display, write_list};

fn goto_data(field: &str) -> Option<KindData> {
    let (target, kind) = field.split_once(',')?;
    Some(KindData::Goto {
        target: if target == "-" {
            None
        } else {
            Some(NodeName::parse(target)?)
        },
        goto_type: u32::try_from(parse_hex_u64(kind)?).ok()?,
    })
}

pub(super) fn kind_data(kind: NodeKind, field: &str) -> Option<KindData> {
    match kind {
        NodeKind::Goto | NodeKind::IfGoto => goto_data(field),
        NodeKind::MultiGoto => {
            let (targets, default) = field.rsplit_once(',')?;
            let default = match default {
                "default" => true,
                "-" => false,
                _ => return None,
            };
            let targets = list_items(targets)?
                .into_iter()
                .map(NodeName::parse)
                .collect::<Option<Vec<_>>>()?;
            (!targets.is_empty()).then_some(KindData::MultiGoto { targets, default })
        }
        NodeKind::Condition => {
            let ok = !field.is_empty()
                && field != "-"
                && field.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
            ok.then(|| KindData::Condition(field.to_owned()))
        }
        NodeKind::WhileDo => match field {
            "overflow" => Some(KindData::WhileDo { overflow: true }),
            "-" => Some(KindData::WhileDo { overflow: false }),
            _ => None,
        },
        NodeKind::Switch => {
            let cases = list_items(field)?
                .into_iter()
                .map(|item| {
                    let p: Vec<&str> = item.split(':').collect();
                    let [node, out, chain, goto_type, exit, default] = p.as_slice() else {
                        return None;
                    };
                    let flag = |t: &str| match t {
                        "1" => Some(true),
                        "0" => Some(false),
                        _ => None,
                    };
                    Some(SwitchCase {
                        node: NodeName::parse(node)?,
                        out_index: parse_i32(out)?,
                        chain: parse_i32(chain)?,
                        goto_type: u32::try_from(parse_hex_u64(goto_type)?).ok()?,
                        is_exit: flag(exit)?,
                        is_default: flag(default)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some(KindData::Switch(cases))
        }
        _ => (field == "-").then_some(KindData::None),
    }
}

pub(super) fn write_kind_data(out: &mut String, data: &KindData) {
    match data {
        KindData::None => out.push('-'),
        KindData::Goto { target, goto_type } => {
            match target {
                Some(t) => push_display(out, t),
                None => out.push('-'),
            }
            out.push(',');
            out.push_str(&hex(u64::from(*goto_type)));
        }
        KindData::MultiGoto { targets, default } => {
            for t in targets {
                push_display(out, t);
                out.push(',');
            }
            out.push_str(if *default { "default" } else { "-" });
        }
        KindData::Condition(op) => out.push_str(op),
        KindData::WhileDo { overflow } => out.push_str(if *overflow { "overflow" } else { "-" }),
        KindData::Switch(cases) => {
            let items: Vec<String> = cases
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}:{}:{:#x}:{}:{}",
                        c.node,
                        c.out_index,
                        c.chain,
                        c.goto_type,
                        u8::from(c.is_exit),
                        u8::from(c.is_default)
                    )
                })
                .collect();
            write_list(out, &items);
        }
    }
}
