//! Edit → Tool Options: appearance (theme, density) and key bindings.
//! Bindings are changed by pressing the new keys, as in Ghidra's Key
//! Bindings page; a binding taken from another action is moved, and the
//! page says which action lost it.

use egui::RichText;

use super::tool::Prefs;
use crate::actions::{ACTIONS, ActionId, KeyChord, Keymap};
use crate::design::{Density, ThemeKind, Tokens, tokens::space, widgets};

/// Pages of the options window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Page {
    /// Theme and density.
    #[default]
    Appearance,
    /// Key bindings.
    KeyBindings,
}

/// The options window's state.
#[derive(Debug, Clone, Default)]
pub struct OptionsState {
    /// The page shown.
    pub page: Page,
    filter: String,
    /// The action waiting for a key press.
    pub capture: Option<ActionId>,
    message: Option<String>,
}

impl OptionsState {
    /// Opened on the key bindings page.
    pub fn key_bindings() -> Self {
        Self {
            page: Page::KeyBindings,
            ..Self::default()
        }
    }

    /// Whether the next key press is being recorded.
    pub fn capturing(&self) -> bool {
        self.capture.is_some()
    }

    /// Records `chord` for the action being captured.
    pub fn assign(&mut self, keymap: &mut Keymap, chord: KeyChord) {
        let Some(id) = self.capture.take() else {
            return;
        };
        let lost = keymap.conflict(id, chord);
        keymap.bind(id, chord);
        self.message = lost
            .and_then(crate::actions::action)
            .map(|a| format!("{chord} was removed from {}", a.name));
    }
}

/// Draws the options window. Returns false when it was closed.
pub fn ui(
    ctx: &egui::Context,
    st: &mut OptionsState,
    prefs: &mut Prefs,
    t: &Tokens,
    mac: bool,
) -> bool {
    let p = t.palette;
    let mut open = true;
    // Capture before anything else sees the keys.
    if st.capture.is_some() {
        let pressed = ctx.input_mut(|i| {
            let mut found = None;
            for e in &i.events {
                if let egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } = e
                {
                    found = Some((*key, *modifiers));
                }
            }
            if let Some((k, m)) = found {
                i.consume_key(m, k);
            }
            found
        });
        if let Some((key, m)) = pressed {
            if key == egui::Key::Escape {
                st.capture = None;
            } else {
                st.assign(
                    &mut prefs.keymap,
                    crate::actions::keymap::chord(key, m.command, m.shift, m.alt),
                );
            }
        }
    }
    egui::Window::new("Tool Options")
        .id(egui::Id::new("bk-options"))
        .open(&mut open)
        .collapsible(false)
        .default_size([720.0, 480.0])
        .show(ctx, |ui| {
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(150.0);
                    for (page, name) in [
                        (Page::Appearance, "Appearance"),
                        (Page::KeyBindings, "Key Bindings"),
                    ] {
                        if ui.selectable_label(st.page == page, name).clicked() {
                            st.page = page;
                        }
                    }
                });
                ui.separator();
                ui.vertical(|ui| match st.page {
                    Page::Appearance => appearance(ui, prefs, t),
                    Page::KeyBindings => key_bindings(ui, st, &mut prefs.keymap, t, mac),
                });
            });
        });
    let _ = p;
    open
}

fn appearance(ui: &mut egui::Ui, prefs: &mut Prefs, t: &Tokens) {
    widgets::section_label(ui, t, "THEME");
    ui.horizontal(|ui| {
        ui.radio_value(&mut prefs.theme, ThemeKind::Dark, "Dark");
        ui.radio_value(&mut prefs.theme, ThemeKind::Light, "Light");
    });
    ui.add_space(space::LG);
    widgets::section_label(ui, t, "ROW DENSITY");
    ui.horizontal(|ui| {
        ui.radio_value(&mut prefs.density, Density::Comfortable, "Comfortable");
        ui.radio_value(&mut prefs.density, Density::Compact, "Compact");
    });
    ui.add_space(space::SM);
    ui.label(
        RichText::new("Compact fits about 18% more rows in the Listing and Decompiler.")
            .size(t.metrics.small_size)
            .color(t.palette.text_muted),
    );
}

fn key_bindings(
    ui: &mut egui::Ui,
    st: &mut OptionsState,
    keymap: &mut Keymap,
    t: &Tokens,
    mac: bool,
) {
    let p = t.palette;
    ui.horizontal(|ui| {
        ui.set_width(520.0);
        widgets::filter_field(
            ui,
            t,
            &mut st.filter,
            "Filter actions",
            egui::Id::new("bk-keys-filter"),
        );
    });
    ui.add_space(space::XS);
    if let Some(m) = &st.message {
        ui.label(RichText::new(m).color(p.warning).size(t.metrics.small_size));
    }
    if let Some(id) = st.capture {
        let name = crate::actions::action(id).map_or("", |a| a.name);
        ui.label(
            RichText::new(format!("Press the new keys for {name} (Esc cancels)"))
                .color(p.accent_text),
        );
    }
    let f = st.filter.to_lowercase();
    egui::ScrollArea::vertical()
        .max_height(360.0)
        .auto_shrink(false)
        .show(ui, |ui| {
            egui::Grid::new("bk-keys")
                .num_columns(4)
                .spacing([space::LG, space::XS])
                .show(ui, |ui| {
                    for a in ACTIONS
                        .iter()
                        .filter(|a| f.is_empty() || a.name.to_lowercase().contains(&f))
                    {
                        let menu = a.menu.map_or("", |m| m.title());
                        ui.label(RichText::new(a.name).color(p.text));
                        ui.label(
                            RichText::new(menu)
                                .color(p.text_muted)
                                .size(t.metrics.small_size),
                        );
                        ui.horizontal(|ui| {
                            let keys = keymap.bindings(a.id);
                            if keys.is_empty() {
                                ui.label(RichText::new("—").color(p.text_disabled));
                            }
                            for k in keys {
                                widgets::key_chip(ui, t, &k.label(mac));
                            }
                            if keymap.is_changed(a.id) {
                                ui.label(
                                    RichText::new("changed")
                                        .color(p.accent_text)
                                        .size(t.metrics.small_size),
                                );
                            }
                        });
                        ui.horizontal(|ui| {
                            if ui
                                .small_button("Set…")
                                .on_hover_text("Press the new keys")
                                .clicked()
                            {
                                st.capture = Some(a.id);
                                st.message = None;
                            }
                            if ui.small_button("Clear").clicked() {
                                keymap.unbind(a.id);
                            }
                            if keymap.is_changed(a.id) && ui.small_button("Default").clicked() {
                                keymap.reset(a.id);
                            }
                        });
                        ui.end_row();
                    }
                });
        });
    ui.add_space(space::SM);
    if widgets::button(ui, t, "Restore Ghidra Defaults").clicked() {
        keymap.reset_all();
        st.message = None;
    }
}
