//! The command palette: every action, function, label and address, found
//! by typing part of its name. It opens in two modes: everything
//! (Tools → Command Palette, Ctrl+Shift+P) and Go To (`G`, Ghidra's Go To
//! Address/Label dialog), which lists only locations.

use fuzzy_matcher::FuzzyMatcher as _;
use fuzzy_matcher::skim::SkimMatcherV2;

use crate::actions::{ACTIONS, ActionContext, ActionId, Keymap};
use crate::model::{Address, SourceResult, Symbol, SymbolKind};
use crate::task::{DataClient, Pending};

/// Entries listed at once.
pub const MAX_SHOWN: usize = 14;

/// Which entries the palette offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Actions and locations.
    All,
    /// Locations only (Go To).
    GoTo,
}

/// What choosing an entry does.
#[derive(Debug, Clone, PartialEq)]
pub enum Choice {
    /// Run an action.
    Action(ActionId),
    /// Go to an address.
    Go(Address),
}

/// One line of results.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// Main text.
    pub label: String,
    /// Secondary text (menu path, kind and address).
    pub detail: String,
    /// Key binding, for actions.
    pub shortcut: Option<String>,
    /// Indices of `label` characters that matched, for emphasis.
    pub matched: Vec<usize>,
    /// What it does.
    pub choice: Choice,
    /// Whether it can run now.
    pub enabled: bool,
    /// Symbol kind, for the icon.
    pub kind: Option<SymbolKind>,
}

/// The palette's state while open.
#[derive(Debug)]
pub struct Palette {
    /// Mode.
    pub mode: Mode,
    /// What has been typed.
    pub query: String,
    /// Highlighted entry.
    pub selected: usize,
    lookup: Option<(String, Pending<SourceResult<Vec<Symbol>>>)>,
    symbols: Vec<Symbol>,
    /// Focus the input on the next frame.
    pub focus: bool,
}

impl Palette {
    /// A palette in `mode`.
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            query: String::new(),
            selected: 0,
            lookup: None,
            symbols: Vec::new(),
            focus: true,
        }
    }

    /// The title shown above the input.
    pub fn title(&self) -> &'static str {
        match self.mode {
            Mode::All => "Command Palette",
            Mode::GoTo => "Go To Address/Label",
        }
    }

    /// The hint inside the empty input.
    pub fn hint(&self) -> &'static str {
        match self.mode {
            Mode::All => "Type an action, function, label or address",
            Mode::GoTo => "Address, label or function name",
        }
    }

    /// Requests symbols matching the query (once per query).
    pub fn refresh(&mut self, client: &DataClient) {
        let q = self.query.trim().to_owned();
        if self.lookup.as_ref().map(|l| &l.0) != Some(&q) {
            if q.is_empty() {
                self.symbols.clear();
                self.lookup = None;
            } else {
                let q2 = q.clone();
                self.lookup = Some((q, client.request(move |s| s.lookup(&q2, 40))));
            }
        }
        if let Some((_, p)) = &mut self.lookup {
            if let Some(Ok(v)) = p.poll() {
                self.symbols.clone_from(v);
            }
        }
    }

    /// Whether the symbol lookup for the current query is still running.
    pub fn searching(&mut self) -> bool {
        self.lookup.as_mut().is_some_and(|(_, p)| p.poll().is_none())
    }

    /// The entries for the current query, best first.
    pub fn entries(&self, keymap: &Keymap, cx: &ActionContext, mac: bool) -> Vec<Entry> {
        let q = self.query.trim();
        let matcher = SkimMatcherV2::default().ignore_case();
        let mut out: Vec<(i64, Entry)> = Vec::new();
        if let Some(a) = Address::parse(q) {
            out.push((
                i64::MAX,
                Entry {
                    label: format!("Go to {a}"),
                    detail: "Address".into(),
                    shortcut: None,
                    matched: Vec::new(),
                    choice: Choice::Go(a),
                    enabled: true,
                    kind: None,
                },
            ));
        }
        for (rank, s) in self.symbols.iter().enumerate() {
            let matched = matcher
                .fuzzy_indices(&s.name, q)
                .map(|(_, m)| m)
                .unwrap_or_default();
            let kind = match s.kind {
                SymbolKind::Function => "Function",
                SymbolKind::Import => "External function",
                SymbolKind::Data => "Data",
                SymbolKind::String => "String",
                _ => "Label",
            };
            out.push((
                // The source ranks symbols; keep its order, after exact names.
                if &*s.name == q { i64::MAX - 1 } else { 1_000_000 - rank as i64 },
                Entry {
                    label: s.name.to_string(),
                    detail: format!("{kind} · {}", s.address),
                    shortcut: None,
                    matched,
                    choice: Choice::Go(s.address),
                    enabled: true,
                    kind: Some(s.kind),
                },
            ));
        }
        if self.mode == Mode::All {
            for a in ACTIONS {
                let path = a.menu.map_or("", |m| m.title());
                let hay = if path.is_empty() {
                    a.name.to_owned()
                } else {
                    format!("{} {path}", a.name)
                };
                let score = if q.is_empty() {
                    Some(0)
                } else {
                    matcher.fuzzy_match(&hay, q)
                };
                if let Some(score) = score {
                    let matched = matcher
                        .fuzzy_indices(a.name, q)
                        .map(|(_, m)| m)
                        .unwrap_or_default();
                    let detail = match (a.menu, a.unavailable_reason()) {
                        (_, Some(r)) => r.to_owned(),
                        (Some(m), None) => format!("{} → {}", m.title(), a.name.trim_end_matches("...")),
                        (None, None) => a.description.to_owned(),
                    };
                    out.push((
                        // Actions rank with symbols by match quality; an
                        // empty query lists actions in menu order.
                        if q.is_empty() { -(out.len() as i64) } else { score * 1000 },
                        Entry {
                            label: a.name.to_owned(),
                            detail,
                            shortcut: keymap.primary(a.id).map(|k| k.label(mac)),
                            matched,
                            choice: Choice::Action(a.id),
                            enabled: a.enabled(cx),
                            kind: None,
                        },
                    ));
                }
            }
        }
        out.sort_by(|a, b| b.0.cmp(&a.0));
        out.into_iter().map(|(_, e)| e).take(MAX_SHOWN * 4).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> ActionContext {
        ActionContext {
            program: true,
            code_view: true,
            ..ActionContext::default()
        }
    }

    #[test]
    fn actions_match_fuzzily_with_their_shortcuts() {
        let mut p = Palette::new(Mode::All);
        p.query = "shw refs".into();
        let e = p.entries(&Keymap::default(), &cx(), false);
        assert_eq!(e[0].choice, Choice::Action(ActionId::ShowReferences));
        assert_eq!(e[0].shortcut.as_deref(), Some("Ctrl+Shift+F"));
        p.query = "goto".into();
        let e = p.entries(&Keymap::default(), &cx(), false);
        assert_eq!(e[0].choice, Choice::Action(ActionId::GoTo));
    }

    #[test]
    fn addresses_come_first_and_go_to_mode_has_no_actions() {
        let mut p = Palette::new(Mode::GoTo);
        p.query = "0x100000650".into();
        let e = p.entries(&Keymap::default(), &cx(), false);
        assert_eq!(e[0].choice, Choice::Go(Address(0x1_0000_0650)));
        assert!(e.iter().all(|x| !matches!(x.choice, Choice::Action(_))));
    }

    #[test]
    fn unavailable_actions_are_listed_disabled_with_the_reason() {
        let mut p = Palette::new(Mode::All);
        p.query = "auto analyze".into();
        let e = p.entries(&Keymap::default(), &cx(), false);
        let a = e.iter().find(|x| x.choice == Choice::Action(ActionId::AutoAnalyze)).unwrap();
        assert!(!a.enabled);
        assert!(a.detail.contains("M5"));
    }
}
