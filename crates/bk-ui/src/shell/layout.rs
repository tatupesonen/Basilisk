//! The window layout: the main window's docking tree and the detached
//! native windows, each with its own docking tree.
//!
//! The default is Ghidra's CodeBrowser arrangement: Program Trees above
//! the Symbol Tree on the left, the Listing in the centre, the Decompiler
//! on the right, the Console at the bottom (with the Functions, Defined
//! Strings and References windows as tabs beside it). Everything here is
//! plain data, saved between runs and tested without a window.

use egui::{Pos2, Rect, Vec2};
use egui_dock::{DockState, NodeIndex, Surface, SurfaceIndex};

use crate::model::Location;
use crate::views::ViewKind;

/// One pane: a view of some kind, identified for the life of the layout.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Tab {
    /// Unique id (the view's state is keyed by it).
    pub id: u64,
    /// What it shows.
    pub kind: ViewKind,
    /// Set for snapshots: the location the view stays at.
    pub snapshot: Option<Location>,
}

/// A pane group detached into its own operating-system window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Detached {
    /// Unique id (seeds the viewport id).
    pub id: u64,
    /// Its panes.
    pub dock: DockState<Tab>,
    /// Outer position on screen, once known.
    pub position: Option<[f32; 2]>,
    /// Inner size, once known.
    pub size: Option<[f32; 2]>,
}

impl Detached {
    /// The panes in this window.
    pub fn tabs(&self) -> impl Iterator<Item = &Tab> {
        self.dock.iter_all_tabs().map(|(_, t)| t)
    }

    /// The window title: its panes' kinds.
    pub fn title(&self) -> String {
        let names: Vec<&str> = self.tabs().map(|t| t.kind.title()).collect();
        format!("basilisk — {}", names.join(", "))
    }
}

/// The whole layout.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Layout {
    /// The main window's panes.
    pub main: DockState<Tab>,
    /// Detached windows.
    pub windows: Vec<Detached>,
    next_id: u64,
}

/// Where a kind of pane goes when it is opened and not already showing.
fn home(kind: ViewKind) -> &'static [ViewKind] {
    match kind {
        ViewKind::SymbolTree | ViewKind::ProgramTrees => &[ViewKind::SymbolTree, ViewKind::ProgramTrees],
        ViewKind::Listing => &[ViewKind::Listing],
        ViewKind::Decompiler => &[ViewKind::Decompiler],
        _ => &[
            ViewKind::Console,
            ViewKind::Functions,
            ViewKind::Strings,
            ViewKind::References,
            ViewKind::SearchResults,
        ],
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::ghidra()
    }
}

impl Layout {
    /// Ghidra's CodeBrowser arrangement.
    pub fn ghidra() -> Self {
        let mut next_id = 0;
        let mut tab = |kind| {
            next_id += 1;
            Tab {
                id: next_id,
                kind,
                snapshot: None,
            }
        };
        let listing = tab(ViewKind::Listing);
        let decompiler = tab(ViewKind::Decompiler);
        let trees = tab(ViewKind::ProgramTrees);
        let symbols = tab(ViewKind::SymbolTree);
        let bottom = vec![
            tab(ViewKind::Console),
            tab(ViewKind::Functions),
            tab(ViewKind::Strings),
            tab(ViewKind::References),
        ];
        let mut main = DockState::new(vec![listing]);
        let surface = main.main_surface_mut();
        let [rest, left] = surface.split_left(NodeIndex::root(), 0.19, vec![trees]);
        surface.split_below(left, 0.32, vec![symbols]);
        let [top, _bottom] = surface.split_below(rest, 0.74, bottom);
        surface.split_right(top, 0.52, vec![decompiler]);
        Self {
            main,
            windows: Vec::new(),
            next_id,
        }
    }

    /// A fresh tab id.
    pub fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Every tab in every window.
    pub fn tabs(&self) -> Vec<&Tab> {
        self.main
            .iter_all_tabs()
            .map(|(_, t)| t)
            .chain(self.windows.iter().flat_map(Detached::tabs))
            .collect()
    }

    /// The first tab of `kind` that follows navigation, wherever it is.
    pub fn find_kind(&self, kind: ViewKind) -> Option<u64> {
        self.tabs()
            .into_iter()
            .find(|t| t.kind == kind && t.snapshot.is_none())
            .map(|t| t.id)
    }

    /// Which window holds tab `id`: `None` for main, `Some(window id)`.
    pub fn window_of(&self, id: u64) -> Option<Option<u64>> {
        if self.main.find_tab_from(|t| t.id == id).is_some() {
            return Some(None);
        }
        self.windows
            .iter()
            .find(|w| w.dock.find_tab_from(|t| t.id == id).is_some())
            .map(|w| Some(w.id))
    }

    /// Makes tab `id` the visible tab of its group.
    pub fn focus(&mut self, id: u64) {
        if let Some(path) = self.main.find_tab_from(|t| t.id == id) {
            let _ = self.main.set_active_tab(path);
            self.main.set_focused_node_and_surface(path.node_path());
            return;
        }
        for w in &mut self.windows {
            if let Some(path) = w.dock.find_tab_from(|t| t.id == id) {
                let _ = w.dock.set_active_tab(path);
                w.dock.set_focused_node_and_surface(path.node_path());
            }
        }
    }

    /// Adds a tab where its kind belongs in the main window: beside a
    /// pane of the same family, or in the focused group.
    pub fn add(&mut self, tab: Tab) -> u64 {
        let id = tab.id;
        let family = home(tab.kind);
        let target = self
            .main
            .iter_all_tabs()
            .find(|(_, t)| family.contains(&t.kind))
            .map(|(p, _)| p.node_path());
        match target {
            Some(node) => {
                if let Ok(leaf) = self.main.leaf_mut(node) {
                    leaf.tabs.push(tab);
                    leaf.active = egui_dock::TabIndex(leaf.tabs.len() - 1);
                }
            }
            None if self.main.main_surface().is_empty() => {
                self.main = DockState::new(vec![tab]);
            }
            None => self.main.push_to_focused_leaf(tab),
        }
        self.focus(id);
        id
    }

    /// Shows the pane of `kind` (focusing it if open, adding it if not)
    /// and returns its id. This is the Window menu.
    pub fn show(&mut self, kind: ViewKind) -> u64 {
        if let Some(id) = self.find_kind(kind) {
            self.focus(id);
            return id;
        }
        let id = self.new_id();
        self.add(Tab {
            id,
            kind,
            snapshot: None,
        })
    }

    /// Removes tab `id` from wherever it is; empty windows close.
    pub fn remove(&mut self, id: u64) -> Option<Tab> {
        if let Some(path) = self.main.find_tab_from(|t| t.id == id) {
            return self.main.remove_tab(path);
        }
        let mut found = None;
        for w in &mut self.windows {
            if let Some(path) = w.dock.find_tab_from(|t| t.id == id) {
                found = w.dock.remove_tab(path);
            }
        }
        self.windows.retain(|w| w.tabs().next().is_some());
        found
    }

    /// Detaches tab `id` into a new native window; returns the window id.
    pub fn detach(&mut self, id: u64) -> Option<u64> {
        // Already alone in its own window: nothing to do.
        if let Some(Some(w)) = self.window_of(id) {
            if self.windows.iter().any(|d| d.id == w && d.tabs().count() == 1) {
                return Some(w);
            }
        }
        let tab = self.remove(id)?;
        let wid = self.new_id();
        self.windows.push(Detached {
            id: wid,
            dock: DockState::new(vec![tab]),
            position: None,
            size: None,
        });
        Some(wid)
    }

    /// Moves every pane of window `wid` back into the main window.
    pub fn dock(&mut self, wid: u64) {
        let Some(i) = self.windows.iter().position(|w| w.id == wid) else {
            return;
        };
        let w = self.windows.remove(i);
        for (_, t) in w.dock.iter_all_tabs() {
            self.add(t.clone());
        }
    }

    /// Closes window `wid` and its panes; returns the closed tab ids.
    pub fn close_window(&mut self, wid: u64) -> Vec<u64> {
        let mut closed = Vec::new();
        self.windows.retain(|w| {
            if w.id == wid {
                closed.extend(w.tabs().map(|t| t.id));
                false
            } else {
                true
            }
        });
        closed
    }

    /// Turns egui_dock's floating windows (a tab dragged out of the dock
    /// area) into native windows at the same place. `origin` is the main
    /// window's inner position on screen.
    pub fn adopt_floating(&mut self, origin: Option<Pos2>) -> Vec<u64> {
        let floating: Vec<SurfaceIndex> = self
            .main
            .iter_surfaces_indexed()
            .filter(|(_, s)| matches!(s, Surface::Window(..)))
            .map(|(i, _)| i)
            .collect();
        let mut made = Vec::new();
        for i in floating.into_iter().rev() {
            let rect = self
                .main
                .get_window_state(i)
                .map(egui_dock::WindowState::rect);
            if let Some(Surface::Window(tree, _)) = self.main.remove_surface(i) {
                let tabs: Vec<Tab> = tree.tabs().cloned().collect();
                if tabs.is_empty() {
                    continue;
                }
                let wid = self.new_id();
                let place = |r: Rect| {
                    let o = origin.unwrap_or(Pos2::ZERO);
                    ([o.x + r.min.x, o.y + r.min.y], [r.width().max(360.0), r.height().max(240.0)])
                };
                let (position, size) = match rect.filter(|r| r.is_positive()) {
                    Some(r) => {
                        let (p, s) = place(r);
                        (Some(p), Some(s))
                    }
                    None => (None, None),
                };
                self.windows.push(Detached {
                    id: wid,
                    dock: DockState::new(tabs),
                    position,
                    size,
                });
                made.push(wid);
            }
        }
        made
    }

    /// Records where a detached window is on screen.
    pub fn set_window_rect(&mut self, wid: u64, position: Option<Pos2>, size: Option<Vec2>) {
        if let Some(w) = self.windows.iter_mut().find(|w| w.id == wid) {
            if let Some(p) = position {
                w.position = Some([p.x, p.y]);
            }
            if let Some(s) = size {
                w.size = Some([s.x, s.y]);
            }
        }
    }

    /// Repairs a layout read from disk: drops empty windows, keeps ids
    /// unique, and starts over if the main window lost every pane.
    pub fn repair(mut self) -> Self {
        self.windows.retain(|w| w.tabs().next().is_some());
        let max = self.tabs().iter().map(|t| t.id).chain(self.windows.iter().map(|w| w.id)).max().unwrap_or(0);
        self.next_id = self.next_id.max(max);
        if self.main.iter_all_tabs().next().is_none() && self.windows.is_empty() {
            return Self::ghidra();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(dock: &DockState<Tab>) -> Vec<ViewKind> {
        dock.iter_all_tabs().map(|(_, t)| t.kind).collect()
    }

    #[test]
    fn default_is_ghidras_code_browser() {
        let l = Layout::ghidra();
        let k = kinds(&l.main);
        for kind in [
            ViewKind::Listing,
            ViewKind::Decompiler,
            ViewKind::SymbolTree,
            ViewKind::ProgramTrees,
            ViewKind::Console,
        ] {
            assert!(k.contains(&kind), "{kind:?} missing");
        }
        assert!(l.windows.is_empty());
        // Program Trees and the Symbol Tree share the left column, the
        // Console group sits below the Listing.
        let leaf_of = |kind| {
            l.main
                .iter_all_tabs()
                .find(|(_, t)| t.kind == kind)
                .map(|(p, _)| p.node_path())
                .unwrap()
        };
        assert_ne!(leaf_of(ViewKind::Listing), leaf_of(ViewKind::Decompiler));
        assert_eq!(leaf_of(ViewKind::Console), leaf_of(ViewKind::Functions));
    }

    #[test]
    fn show_focuses_or_adds_beside_its_family() {
        let mut l = Layout::ghidra();
        let id = l.find_kind(ViewKind::Functions).unwrap();
        assert_eq!(l.show(ViewKind::Functions), id);
        let id = l.remove(id).unwrap().id;
        assert!(l.find_kind(ViewKind::Functions).is_none());
        let again = l.show(ViewKind::Functions);
        assert_ne!(again, id);
        let console = l.find_kind(ViewKind::Console).unwrap();
        let path = |id: u64| l.main.find_tab_from(|t| t.id == id).unwrap().node_path();
        assert_eq!(path(again), path(console));
    }

    #[test]
    fn detach_and_dock_back() {
        let mut l = Layout::ghidra();
        let dec = l.find_kind(ViewKind::Decompiler).unwrap();
        let w = l.detach(dec).unwrap();
        assert_eq!(l.window_of(dec), Some(Some(w)));
        assert!(!kinds(&l.main).contains(&ViewKind::Decompiler));
        assert_eq!(l.windows[0].title(), "basilisk — Decompile");
        // Another pane can join the detached window.
        let console = l.find_kind(ViewKind::Console).unwrap();
        let tab = l.remove(console).unwrap();
        l.windows[0].dock.push_to_first_leaf(tab);
        assert_eq!(l.windows[0].tabs().count(), 2);
        l.dock(w);
        assert!(l.windows.is_empty());
        assert_eq!(l.window_of(dec), Some(None));
        assert_eq!(l.window_of(console), Some(None));
    }

    #[test]
    fn closing_a_window_closes_its_panes() {
        let mut l = Layout::ghidra();
        let dec = l.find_kind(ViewKind::Decompiler).unwrap();
        let w = l.detach(dec).unwrap();
        assert_eq!(l.close_window(w), vec![dec]);
        assert!(l.find_kind(ViewKind::Decompiler).is_none());
        // And the Window menu brings it back.
        l.show(ViewKind::Decompiler);
        assert!(l.find_kind(ViewKind::Decompiler).is_some());
    }

    #[test]
    fn floating_tabs_become_native_windows() {
        let mut l = Layout::ghidra();
        let strings = l.find_kind(ViewKind::Strings).unwrap();
        let path = l.main.find_tab_from(|t| t.id == strings).unwrap();
        l.main.detach_tab(path, Rect::from_min_size(Pos2::new(100.0, 50.0), Vec2::new(500.0, 300.0)));
        let made = l.adopt_floating(Some(Pos2::new(1000.0, 200.0)));
        assert_eq!(made.len(), 1);
        assert_eq!(l.window_of(strings), Some(Some(made[0])));
        assert_eq!(l.main.iter_surfaces().filter(|s| matches!(s, Surface::Window(..))).count(), 0);
        assert_eq!(l.windows[0].size, Some([500.0, 300.0]));
    }

    #[test]
    fn layout_with_a_detached_window_round_trips() {
        let mut l = Layout::ghidra();
        let dec = l.find_kind(ViewKind::Decompiler).unwrap();
        let w = l.detach(dec).unwrap();
        l.set_window_rect(w, Some(Pos2::new(1500.0, 80.0)), Some(Vec2::new(700.0, 900.0)));
        let json = serde_json::to_string(&l).unwrap();
        let back: Layout = serde_json::from_str::<Layout>(&json).unwrap().repair();
        assert_eq!(back.windows.len(), 1);
        assert_eq!(back.windows[0].position, Some([1500.0, 80.0]));
        assert_eq!(back.window_of(dec), Some(Some(w)));
        let mut back = back;
        assert!(back.new_id() > w);
    }
}
