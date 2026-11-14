//! Property-test strategies shared by the oracle parsers' tests: valid
//! values of each format, and damaged copies of valid files.

use proptest::prelude::*;

use super::graph::{AddressRange, Facts, GraphFile, OracleAddress};

/// Facts that the extension accepts (never both `s` and `r`).
pub(crate) fn facts() -> impl Strategy<Value = Facts> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(c, s, r, n)| Facts {
        complex: c,
        switch_out: s,
        ends_in_return: r && !s,
        negation_changes_dataflow: n,
    })
}

/// An address with a short space name.
pub(crate) fn address() -> impl Strategy<Value = OracleAddress> {
    ("[a-z][a-z0-9_]{0,6}", any::<u64>())
        .prop_map(|(space, offset)| OracleAddress { space, offset })
}

/// A valid graph file of up to `max` nodes, with arbitrary labels, flags,
/// indices, dominators and ranges.
pub(crate) fn graph_file(max: usize) -> impl Strategy<Value = GraphFile> {
    (0..=max)
        .prop_flat_map(|n| {
            let targets = if n == 0 {
                Just(Vec::new()).boxed()
            } else {
                prop::collection::vec(prop::collection::vec(0..u32::try_from(n).unwrap(), 0..4), n)
                    .boxed()
            };
            (
                targets,
                prop::collection::vec(
                    (
                        facts(),
                        any::<u32>(),
                        0u32..1000,
                        any::<prop::sample::Index>(),
                        any::<bool>(),
                        0u32..100,
                        prop::option::of((address(), address())),
                    ),
                    n,
                ),
                prop::collection::vec(any::<u32>(), 0..32),
            )
        })
        .prop_map(|(outs, extras, labels)| {
            let facts: Vec<Facts> = extras.iter().map(|e| e.0).collect();
            let mut graph = GraphFile::from_out_edges(&outs, &facts).unwrap();
            let n = graph.nodes.len();
            let mut label_iter = labels.into_iter().cycle();
            for (node, (_, flags, index, dom, has_dom, numdesc, range)) in
                graph.nodes.iter_mut().zip(extras)
            {
                node.flags = flags;
                node.index = index;
                node.idom = has_dom.then(|| u32::try_from(dom.index(n)).unwrap());
                node.numdesc = numdesc;
                node.range = range.map(|(start, stop)| AddressRange { start, stop });
                for edge in &mut node.in_edges {
                    edge.label = label_iter.next().unwrap_or(0);
                }
            }
            graph
        })
}

/// Damaged copies of the texts `valid` produces: a cut, an insertion, a
/// deleted or duplicated line, a changed character.
pub(crate) fn mutated(valid: impl Strategy<Value = String>) -> impl Strategy<Value = String> {
    (
        valid,
        0usize..5,
        any::<prop::sample::Index>(),
        any::<prop::sample::Index>(),
        "[\\t\\n:,0-9a-zA-Z\\-x]{0,4}",
    )
        .prop_map(|(text, kind, a, b, insert)| {
            let chars: Vec<char> = text.chars().collect();
            if chars.is_empty() {
                return insert;
            }
            let i = a.index(chars.len());
            let j = b.index(chars.len());
            let (lo, hi) = (i.min(j), i.max(j));
            match kind {
                0 => chars[..i].iter().collect(),
                1 => {
                    let mut s: String = chars[..i].iter().collect();
                    s.push_str(&insert);
                    s.extend(&chars[i..]);
                    s
                }
                2 => {
                    let mut s: String = chars[..lo].iter().collect();
                    s.extend(&chars[hi..]);
                    s
                }
                3 => {
                    let lines: Vec<&str> = text.split_inclusive('\n').collect();
                    let k = a.index(lines.len());
                    let mut s = String::new();
                    for (n, line) in lines.iter().enumerate() {
                        s.push_str(line);
                        if n == k {
                            s.push_str(line);
                        }
                    }
                    s
                }
                _ => {
                    let mut s: String = chars[..i].iter().collect();
                    s.push_str(&insert);
                    s.extend(chars.iter().skip(i + 1));
                    s
                }
            }
        })
}
