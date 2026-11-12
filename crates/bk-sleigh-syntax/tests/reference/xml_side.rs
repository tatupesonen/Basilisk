//! The model, read from the XML `.sla` that Ghidra's C++ compiler writes
//! with `sleigh -y` (`slghsymbol.cc`, `Constructor::encode` and the symbol
//! `encode` methods; `slghpatexpress.cc` for pattern expressions;
//! `semantics.cc`, `ConstructTpl::encode`).

use std::collections::{BTreeMap, HashMap};

use roxmltree::{Document, Node};

use super::{Attached, Ctor, Model, Piece, binary_shape};

fn attr<'a>(node: Node<'a, '_>, name: &str) -> &'a str {
    node.attribute(name)
        .unwrap_or_else(|| panic!("<{}> without {name}", node.tag_name().name()))
}

fn number(text: &str) -> i64 {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap() as i64
    } else if let Some(hex) = text.strip_prefix("-0x") {
        -(i64::from_str_radix(hex, 16).unwrap())
    } else {
        text.parse().unwrap()
    }
}

fn unsigned(node: Node<'_, '_>, name: &str) -> u64 {
    number(attr(node, name)) as u64
}

fn elements<'a, 'i>(node: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(Node::is_element)
}

/// The shape of a pattern expression element.
fn shape(node: Node<'_, '_>) -> String {
    let op = match node.tag_name().name() {
        "intb" => return number(attr(node, "val")).to_string(),
        "minus_exp" | "not_exp" => {
            let operand = elements(node).next().unwrap();
            let name = if node.tag_name().name() == "minus_exp" {
                "neg"
            } else {
                "inv"
            };
            return format!("({name} {})", shape(operand));
        }
        "plus_exp" => "+",
        "sub_exp" => "-",
        "mult_exp" => "*",
        "div_exp" => "/",
        "lshift_exp" => "<<",
        "rshift_exp" => ">>",
        "and_exp" => "$and",
        "or_exp" => "$or",
        "xor_exp" => "$xor",
        _ => return "leaf".to_owned(),
    };
    let mut children = elements(node);
    let lhs = shape(children.next().unwrap());
    let rhs = shape(children.next().unwrap());
    binary_shape(op, &lhs, &rhs)
}

/// Builds the model from the text of an XML `.sla`.
pub(crate) fn model(xml: &str) -> Model {
    let doc = Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: u32::MAX,
            ..roxmltree::ParsingOptions::default()
        },
    )
    .unwrap();
    let root = doc.root_element();
    let mut model = Model::default();

    let mut source_files = HashMap::new();
    let mut names: HashMap<&str, &str> = HashMap::new();
    let mut symbol_table = None;
    for child in elements(root) {
        match child.tag_name().name() {
            "sourcefiles" => {
                for file in elements(child) {
                    source_files.insert(attr(file, "index"), attr(file, "name").to_owned());
                }
            }
            "spaces" => {
                model.default_space = child.attribute("defaultspace").map(str::to_owned);
                for space in elements(child).filter(|s| s.tag_name().name() == "space") {
                    let wordsize = space.attribute("wordsize").map_or(1, number) as u64;
                    model.spaces.insert(
                        attr(space, "name").to_owned(),
                        (unsigned(space, "size"), wordsize),
                    );
                }
            }
            "symbol_table" => symbol_table = Some(child),
            _ => {}
        }
    }
    let symbol_table = symbol_table.unwrap();
    for head in elements(symbol_table) {
        if head.tag_name().name().ends_with("_head") {
            names.insert(attr(head, "id"), attr(head, "name"));
        }
    }
    let name_of = |id: &str| -> String { names[id].to_owned() };

    // Operand symbols sit beside their constructors in the table; their
    // first child (`operand_exp`) names the table and constructor.
    let mut operand_defs: HashMap<(&str, u64), BTreeMap<String, Vec<String>>> = HashMap::new();
    for sym in elements(symbol_table).filter(|s| s.tag_name().name() == "operand_sym") {
        let mut children = elements(sym);
        let local = children.next().unwrap();
        let Some(def) = children.next() else { continue };
        let shape = shape(def);
        if shape == "leaf" {
            continue;
        }
        operand_defs
            .entry((attr(local, "table"), unsigned(local, "ct")))
            .or_default()
            .insert(name_of(attr(sym, "id")), vec![shape]);
    }

    for sym in elements(symbol_table) {
        let tag = sym.tag_name().name();
        if tag.ends_with("_head") || tag == "scope" {
            continue;
        }
        let name = || name_of(attr(sym, "id"));
        let field = || elements(sym).next().unwrap();
        // A token field's bits, if `field` is one.
        let token_bits = |field: Node<'_, '_>| {
            (field.tag_name().name() == "tokenfield").then(|| {
                (
                    unsigned(field, "startbit"),
                    unsigned(field, "endbit"),
                    attr(field, "signbit") == "true",
                )
            })
        };
        match tag {
            "varnode_sym" => {
                model.varnodes.insert(
                    name(),
                    (
                        attr(sym, "space").to_owned(),
                        unsigned(sym, "off"),
                        unsigned(sym, "size"),
                    ),
                );
            }
            "userop" => {
                model.userops.insert(name());
            }
            "value_sym" => {
                if let Some(bits) = token_bits(field()) {
                    model.token_fields.insert(name(), bits);
                }
            }
            "context_sym" => {
                model.context_fields.insert(
                    name(),
                    (
                        unsigned(sym, "low"),
                        unsigned(sym, "high"),
                        attr(sym, "flow") == "true",
                    ),
                );
            }
            "varlist_sym" | "name_sym" | "valuemap_sym" => {
                if let Some(bits) = token_bits(field()) {
                    model.token_fields.insert(name(), bits);
                }
                let entries = elements(sym).skip(1);
                let attached = match tag {
                    "varlist_sym" => Attached::Variables(
                        entries
                            .map(|e| (e.tag_name().name() == "var").then(|| name_of(attr(e, "id"))))
                            .collect(),
                    ),
                    "name_sym" => Attached::Names(
                        entries
                            .map(|e| e.attribute("name").map(str::to_owned))
                            .collect(),
                    ),
                    _ => Attached::Values(entries.map(|e| Some(number(attr(e, "val")))).collect()),
                };
                model.attached.insert(name(), attached);
            }
            "subtable_sym" => {
                let table = name();
                let id = attr(sym, "id");
                let ctors = elements(sym)
                    .filter(|c| c.tag_name().name() == "constructor")
                    .enumerate()
                    .map(|(index, c)| {
                        let mut ctor = constructor(c, &source_files, &name_of);
                        if let Some(defs) = operand_defs.remove(&(id, index as u64)) {
                            ctor.operand_defs = defs;
                        }
                        ctor
                    })
                    .collect();
                model.tables.insert(table, ctors);
            }
            _ => {}
        }
    }
    // Ghidra stores `attach values` wildcards as a sentinel value.
    for attached in model.attached.values_mut() {
        if let Attached::Values(values) = attached {
            for value in values.iter_mut() {
                if *value == Some(0xBAD_BEEF) {
                    *value = None;
                }
            }
        }
    }
    model
}

fn constructor(
    node: Node<'_, '_>,
    source_files: &HashMap<&str, String>,
    name_of: &dyn Fn(&str) -> String,
) -> Ctor {
    let mut ctor = Ctor {
        file: source_files
            .get(attr(node, "source"))
            .cloned()
            .unwrap_or_default(),
        line: unsigned(node, "line") as u32,
        unimpl: true,
        ..Ctor::default()
    };
    let mut operands = Vec::new();
    for child in elements(node) {
        match child.tag_name().name() {
            "oper" => operands.push(name_of(attr(child, "id"))),
            "print" => ctor
                .display
                .push(Piece::Text(attr(child, "piece").to_owned())),
            "opprint" => {
                let index = number(attr(child, "id")) as usize;
                ctor.display.push(Piece::Operand(operands[index].clone()));
            }
            "context_op" => ctor
                .context_ops
                .push(shape(elements(child).next().unwrap())),
            "commit" => ctor.commits += 1,
            "construct_tpl" => {
                if child.attribute("section").is_some() {
                    ctor.named_sections += 1;
                } else {
                    ctor.unimpl = false;
                    ctor.export = elements(child)
                        .next()
                        .is_some_and(|first| first.tag_name().name() == "handle_tpl");
                    ctor.labels = child.attribute("labels").map_or(0, number) as u32;
                }
            }
            _ => {}
        }
    }
    ctor
}
