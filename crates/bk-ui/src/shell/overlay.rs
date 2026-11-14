//! What floats above the panes: the command palette and the small dialogs
//! Ghidra users know (Rename / Edit Label, Set Comment, Search Program Text,
//! Search Memory, About). None blocks the rest of the tool: the panes keep
//! updating behind them, and Escape or a click elsewhere closes them.

use std::collections::BTreeMap;

use egui::{Align2, Key, RichText, Sense, vec2};

use super::palette::{Choice, Mode, Palette};
use super::workspace::{Edit, Workspace};
use crate::actions::{ActionContext, ActionId, Keymap};
use crate::design::{Tokens, icons, tokens::radius, tokens::space, typography, widgets};
use crate::model::{Address, Command, CommentKind, Referent, SearchQuery, SourceResult};
use crate::task::{DataClient, Pending};
use crate::views::Target;

/// What an overlay needs from the shell.
#[derive(Debug)]
pub struct Env<'a> {
    /// Design tokens.
    pub tokens: &'a Tokens,
    /// Key bindings.
    pub keymap: &'a Keymap,
    /// What is enabled.
    pub actions: ActionContext,
    /// macOS key labels.
    pub mac: bool,
    /// The data interface.
    pub client: &'a DataClient,
}

/// What the overlay decided this frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Stay open.
    Keep,
    /// Close without doing anything.
    Close,
    /// Run an action.
    Run(ActionId),
    /// Go to an address.
    Go(Address),
    /// Apply edits.
    Apply(Vec<Edit>),
    /// Run a search.
    Search(SearchQuery, String),
}

/// The rename dialog's state.
#[derive(Debug)]
pub struct Rename {
    title: &'static str,
    old: String,
    name: String,
    error: Option<String>,
    make: RenameKind,
    focus: bool,
}

#[derive(Debug, Clone, Copy)]
enum RenameKind {
    Symbol { address: Address, existing: bool },
    Variable { function: Address, index: u32 },
}

/// The existing comments, loading.
type CommentsLoad = Pending<SourceResult<Vec<(CommentKind, String)>>>;

/// The Set Comment dialog's state.
#[derive(Debug)]
pub struct CommentEdit {
    address: Address,
    kind: CommentKind,
    texts: BTreeMap<u8, String>,
    originals: BTreeMap<u8, String>,
    load: Option<CommentsLoad>,
    focus: bool,
}

fn kind_key(k: CommentKind) -> u8 {
    match k {
        CommentKind::Eol => 0,
        CommentKind::Pre => 1,
        CommentKind::Post => 2,
        CommentKind::Plate => 3,
    }
}

/// The search dialog's state.
#[derive(Debug)]
pub struct SearchBox {
    memory: bool,
    text: String,
    error: Option<String>,
    focus: bool,
}

/// An open overlay.
#[derive(Debug)]
pub enum Overlay {
    /// The command palette (or Go To).
    Palette(Palette),
    /// Rename / Edit Label / Add Label.
    Rename(Rename),
    /// Set Comment.
    Comment(CommentEdit),
    /// Search Program Text / Search Memory.
    Search(SearchBox),
    /// About Basilisk.
    About,
}

/// Parses "48 89 e5" or "4889e5" into bytes.
pub fn parse_bytes(text: &str) -> Result<Vec<u8>, String> {
    let hex: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let hex = hex.trim_start_matches("0x");
    if hex.is_empty() {
        return Err("Type the bytes to find, in hex (48 89 e5)".into());
    }
    if !hex.len().is_multiple_of(2) {
        return Err("Hex bytes come in pairs of digits".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(|| format!("{:?} is not a hex byte", hex.get(i..i + 2).unwrap_or("")))
        })
        .collect()
}

fn valid_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        Err("A name cannot be empty".into())
    } else if name.chars().any(char::is_whitespace) {
        Err("A name cannot contain spaces".into())
    } else {
        Ok(())
    }
}

impl Overlay {
    /// The palette in `mode`.
    pub fn palette(mode: Mode) -> Self {
        Self::Palette(Palette::new(mode))
    }

    /// The rename dialog for what is under the cursor.
    pub fn rename(target: &Target, current_label: Option<String>) -> Self {
        let token = target.token.as_ref();
        let (title, old, make) = match token.map(|t| (&t.referent, t)) {
            Some((Some(Referent::Variable { function, index }), t)) => (
                "Rename Variable",
                t.text.to_string(),
                RenameKind::Variable {
                    function: *function,
                    index: *index,
                },
            ),
            Some((Some(Referent::Address(a)), t)) => (
                crate::views::rename_title(Some(target)),
                t.text.trim_start_matches("->").to_string(),
                RenameKind::Symbol {
                    address: *a,
                    existing: true,
                },
            ),
            _ => match current_label {
                Some(l) => (
                    "Edit Label",
                    l,
                    RenameKind::Symbol {
                        address: target.address,
                        existing: true,
                    },
                ),
                None => (
                    "Add Label",
                    String::new(),
                    RenameKind::Symbol {
                        address: target.address,
                        existing: false,
                    },
                ),
            },
        };
        Self::Rename(Rename {
            title,
            name: old.clone(),
            old,
            error: None,
            make,
            focus: true,
        })
    }

    /// The Set Comment dialog at `address`, on `kind` (EOL by default).
    pub fn comment(ws: &Workspace, address: Address, kind: Option<CommentKind>) -> Self {
        Self::Comment(CommentEdit {
            address,
            kind: kind.unwrap_or(CommentKind::Eol),
            texts: BTreeMap::new(),
            originals: BTreeMap::new(),
            load: Some(ws.client.request(move |s| s.comments(address))),
            focus: true,
        })
    }

    /// The search dialog: program text, or memory bytes.
    pub fn search(memory: bool) -> Self {
        Self::Search(SearchBox {
            memory,
            text: String::new(),
            error: None,
            focus: true,
        })
    }

    /// Draws the overlay in the current viewport.
    pub fn ui(&mut self, ctx: &egui::Context, env: &Env<'_>) -> Outcome {
        let escape = ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Escape));
        if escape {
            return Outcome::Close;
        }
        match self {
            Self::Palette(p) => palette_ui(ctx, env, p),
            Self::Rename(r) => rename_ui(ctx, env, r),
            Self::Comment(c) => comment_ui(ctx, env, c),
            Self::Search(s) => search_ui(ctx, env, s),
            Self::About => about_ui(ctx, env),
        }
    }
}

fn dialog<R>(
    ctx: &egui::Context,
    t: &Tokens,
    title: &str,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> Option<R> {
    egui::Window::new(
        RichText::new(title)
            .family(typography::strong_family())
            .size(t.metrics.body_size + 1.0),
    )
    .id(egui::Id::new("bk-dialog").with(title))
    .collapsible(false)
    .resizable(false)
    .anchor(Align2::CENTER_TOP, vec2(0.0, 120.0))
    .frame(
        egui::Frame::window(&ctx.global_style())
            .fill(t.palette.raised)
            .inner_margin(egui::Margin::same(space::XL as i8)),
    )
    .show(ctx, |ui| {
        ui.set_width(440.0);
        add(ui)
    })
    .and_then(|r| r.inner)
}

fn buttons(ui: &mut egui::Ui, t: &Tokens, ok: &str) -> (bool, bool) {
    ui.add_space(space::LG);
    let size = vec2(ui.available_width(), t.metrics.table_row + 4.0);
    ui.allocate_ui_with_layout(
        size,
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            let ok = widgets::primary_button(ui, t, ok).clicked();
            let cancel = widgets::button(ui, t, "Cancel").clicked();
            (ok, cancel)
        },
    )
    .inner
}

fn rename_ui(ctx: &egui::Context, env: &Env<'_>, r: &mut Rename) -> Outcome {
    let t = env.tokens;
    let title = r.title;
    let out = dialog(ctx, t, title, |ui| {
        let label = if r.old.is_empty() {
            "Name for the new label".to_owned()
        } else {
            format!("New name for {}", r.old)
        };
        ui.label(RichText::new(label).color(t.palette.text_secondary));
        ui.add_space(space::SM);
        let edit = egui::TextEdit::singleline(&mut r.name)
            .font(egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .id(egui::Id::new("bk-rename-input"));
        let mut resp = edit.show(ui);
        if r.focus {
            r.focus = false;
            resp.response.request_focus();
            let all = egui::text::CCursorRange::two(
                egui::text::CCursor::new(0),
                egui::text::CCursor::new(r.name.chars().count()),
            );
            resp.state.cursor.set_char_range(Some(all));
            resp.state.store(ui.ctx(), resp.response.id);
        }
        if let Some(e) = &r.error {
            ui.add_space(space::XS);
            ui.label(
                RichText::new(e)
                    .color(t.palette.error)
                    .size(t.metrics.small_size),
            );
        }
        let enter = resp.response.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        let (ok, cancel) = buttons(ui, t, "OK");
        (ok || enter, cancel)
    });
    let Some((ok, cancel)) = out else {
        return Outcome::Keep;
    };
    if cancel {
        return Outcome::Close;
    }
    if !ok {
        return Outcome::Keep;
    }
    if let Err(e) = valid_name(&r.name) {
        r.error = Some(e);
        r.focus = true;
        return Outcome::Keep;
    }
    if r.name == r.old {
        return Outcome::Close;
    }
    let name = r.name.trim().to_owned();
    let edit = match r.make {
        RenameKind::Variable { function, index } => Edit {
            command: Command::RenameVariable {
                function,
                index,
                name,
            },
            undo: Command::RenameVariable {
                function,
                index,
                name: r.old.clone(),
            },
        },
        RenameKind::Symbol { address, existing } => Edit {
            command: Command::RenameSymbol { address, name },
            undo: if existing {
                Command::RenameSymbol {
                    address,
                    name: r.old.clone(),
                }
            } else {
                Command::RemoveLabel { address }
            },
        },
    };
    Outcome::Apply(vec![edit])
}

fn comment_ui(ctx: &egui::Context, env: &Env<'_>, c: &mut CommentEdit) -> Outcome {
    let t = env.tokens;
    if let Some(p) = &mut c.load
        && let Some(r) = p.take()
    {
        c.load = None;
        for (k, text) in r.unwrap_or_default() {
            c.originals.insert(kind_key(k), text.clone());
            c.texts.entry(kind_key(k)).or_insert(text);
        }
    }
    let title = format!("Set Comment at {}", c.address);
    let out = dialog(ctx, t, &title, |ui| {
        ui.horizontal(|ui| {
            for k in CommentKind::ALL {
                let on = c.kind == k;
                let has = c.texts.get(&kind_key(k)).is_some_and(|s| !s.is_empty());
                let text = if has {
                    format!("{} •", k.title())
                } else {
                    k.title().to_owned()
                };
                if ui.selectable_label(on, text).clicked() {
                    c.kind = k;
                    c.focus = true;
                }
            }
        });
        ui.add_space(space::SM);
        let text = c.texts.entry(kind_key(c.kind)).or_default();
        let resp = ui.add(
            egui::TextEdit::multiline(text)
                .font(egui::TextStyle::Monospace)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .id(egui::Id::new("bk-comment-input")),
        );
        if c.focus {
            c.focus = false;
            resp.request_focus();
        }
        ui.add_space(space::XS);
        ui.label(
            RichText::new(
                "Enter saves · Shift+Enter starts a new line · an empty comment is removed",
            )
            .color(t.palette.text_muted)
            .size(t.metrics.small_size),
        );
        // Enter saves; Shift+Enter is a new line (the text edit inserts it).
        let enter =
            resp.has_focus() && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Enter));
        let (ok, cancel) = buttons(ui, t, "OK");
        (ok || enter, cancel)
    });
    let Some((ok, cancel)) = out else {
        return Outcome::Keep;
    };
    if cancel {
        return Outcome::Close;
    }
    if !ok {
        return Outcome::Keep;
    }
    let mut edits = Vec::new();
    for k in CommentKind::ALL {
        let new = c.texts.get(&kind_key(k)).cloned().unwrap_or_default();
        let new = new.trim_end().to_owned();
        let old = c.originals.get(&kind_key(k)).cloned().unwrap_or_default();
        if new != old {
            edits.push(Edit {
                command: Command::SetComment {
                    address: c.address,
                    kind: k,
                    text: new,
                },
                undo: Command::SetComment {
                    address: c.address,
                    kind: k,
                    text: old,
                },
            });
        }
    }
    Outcome::Apply(edits)
}

fn search_ui(ctx: &egui::Context, env: &Env<'_>, s: &mut SearchBox) -> Outcome {
    let t = env.tokens;
    let title = if s.memory {
        "Search Memory"
    } else {
        "Search Program Text"
    };
    let out = dialog(ctx, t, title, |ui| {
        let hint = if s.memory {
            "Hex bytes, for example 55 48 89 e5"
        } else {
            "Text in mnemonics, operands, labels and comments"
        };
        let resp = ui.add(
            egui::TextEdit::singleline(&mut s.text)
                .font(egui::TextStyle::Monospace)
                .hint_text(hint)
                .desired_width(f32::INFINITY)
                .id(egui::Id::new("bk-search-input")),
        );
        if s.focus {
            s.focus = false;
            resp.request_focus();
        }
        if let Some(e) = &s.error {
            ui.label(
                RichText::new(e)
                    .color(t.palette.error)
                    .size(t.metrics.small_size),
            );
        }
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        let (ok, cancel) = buttons(ui, t, "Search");
        (ok || enter, cancel)
    });
    let Some((ok, cancel)) = out else {
        return Outcome::Keep;
    };
    if cancel {
        return Outcome::Close;
    }
    if !ok {
        return Outcome::Keep;
    }
    if s.memory {
        match parse_bytes(&s.text) {
            Ok(b) => Outcome::Search(SearchQuery::Bytes(b), s.text.trim().to_owned()),
            Err(e) => {
                s.error = Some(e);
                Outcome::Keep
            }
        }
    } else if s.text.trim().is_empty() {
        s.error = Some("Type the text to find".into());
        Outcome::Keep
    } else {
        Outcome::Search(
            SearchQuery::Text(s.text.trim().to_owned()),
            format!("\"{}\"", s.text.trim()),
        )
    }
}

fn about_ui(ctx: &egui::Context, env: &Env<'_>) -> Outcome {
    let t = env.tokens;
    let out = dialog(ctx, t, "About Basilisk", |ui| {
        ui.horizontal(|ui| {
            if let Some(tex) = super::brand::mark(ui.ctx(), t.kind) {
                ui.add(egui::Image::new(&tex).fit_to_exact_size(vec2(56.0, 56.0)));
            }
            ui.add_space(space::LG);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Basilisk")
                        .text_style(typography::style::display())
                        .color(t.palette.text),
                );
                ui.label(
                    RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                        .color(t.palette.text_secondary),
                );
            });
        });
        ui.add_space(space::LG);
        for line in [
            "A reimplementation of Ghidra in Rust. GPL-3.0-or-later.",
            "Ghidra is developed by the NSA and licensed under Apache-2.0.",
            "Inter and JetBrains Mono: SIL Open Font License 1.1.",
            "Phosphor icons: MIT.",
        ] {
            ui.label(RichText::new(line).color(t.palette.text_secondary));
        }
        ui.add_space(space::LG);
        let size = vec2(ui.available_width(), t.metrics.table_row + 4.0);
        ui.allocate_ui_with_layout(
            size,
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| widgets::primary_button(ui, t, "Close").clicked(),
        )
        .inner
    });
    if out == Some(true) {
        Outcome::Close
    } else {
        Outcome::Keep
    }
}

fn palette_ui(ctx: &egui::Context, env: &Env<'_>, p: &mut Palette) -> Outcome {
    let t = env.tokens;
    let pal = t.palette;
    p.refresh(env.client);
    let entries = p.entries(env.keymap, env.actions, env.mac);
    let (down, up, enter) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::NONE, Key::ArrowDown),
            i.consume_key(egui::Modifiers::NONE, Key::ArrowUp),
            i.consume_key(egui::Modifiers::NONE, Key::Enter),
        )
    });
    let shown = entries.len().min(super::palette::MAX_SHOWN);
    if down && shown > 0 {
        p.selected = (p.selected + 1) % shown;
    }
    if up && shown > 0 {
        p.selected = (p.selected + shown - 1) % shown;
    }
    p.selected = p.selected.min(shown.saturating_sub(1));
    let mut chosen = None;
    let width = 640.0_f32.min(ctx.content_rect().width() - 32.0);
    let area = egui::Area::new(egui::Id::new("bk-palette"))
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_TOP, vec2(0.0, 72.0))
        .show(ctx, |ui| {
            egui::Frame::popup(ui.style())
                .fill(pal.raised)
                .corner_radius(egui::CornerRadius::same(radius::LG))
                .inner_margin(egui::Margin::same(space::MD as i8))
                .show(ui, |ui| {
                    ui.set_width(width);
                    ui.horizontal(|ui| {
                        ui.label(icons::rich(icons::PALETTE).color(pal.text_muted));
                        ui.label(
                            RichText::new(p.title())
                                .size(t.metrics.small_size)
                                .color(pal.text_secondary),
                        );
                    });
                    ui.add_space(space::XS);
                    let hint = p.hint();
                    let input = ui.add(
                        egui::TextEdit::singleline(&mut p.query)
                            .hint_text(hint)
                            .font(egui::FontId::proportional(t.metrics.body_size + 2.0))
                            .desired_width(f32::INFINITY)
                            .margin(egui::Margin::symmetric(space::SM as i8, space::SM as i8))
                            .id(egui::Id::new("bk-palette-input")),
                    );
                    widgets::name_field(ui, &input, hint);
                    if p.focus {
                        p.focus = false;
                        input.request_focus();
                    }
                    if input.changed() {
                        p.selected = 0;
                    }
                    ui.add_space(space::XS);
                    if entries.is_empty() {
                        let msg = if p.query.trim().is_empty() {
                            "Type to search"
                        } else if p.searching() {
                            "Searching…"
                        } else {
                            "No matches"
                        };
                        ui.add_space(space::SM);
                        ui.label(RichText::new(msg).color(pal.text_muted));
                        ui.add_space(space::SM);
                    }
                    for (i, e) in entries.iter().take(super::palette::MAX_SHOWN).enumerate() {
                        let (rect, resp) = ui.allocate_exact_size(
                            vec2(ui.available_width(), t.metrics.table_row + 6.0),
                            Sense::click(),
                        );
                        let sel = i == p.selected;
                        if sel {
                            ui.painter().rect_filled(
                                rect,
                                egui::CornerRadius::same(radius::SM),
                                pal.selection,
                            );
                        } else if resp.hovered() {
                            ui.painter().rect_filled(
                                rect,
                                egui::CornerRadius::same(radius::SM),
                                pal.hover,
                            );
                        }
                        let icon = match (&e.choice, e.kind) {
                            (Choice::Action(_), _) => icons::KEYBOARD,
                            (_, Some(crate::model::SymbolKind::Function)) => icons::FUNCTION,
                            (_, Some(crate::model::SymbolKind::Import)) => icons::IMPORT,
                            (_, Some(crate::model::SymbolKind::Data)) => icons::DATA,
                            (_, Some(crate::model::SymbolKind::String)) => icons::STRING,
                            (_, Some(_)) => icons::LABEL,
                            (_, None) => icons::GOTO,
                        };
                        let y = rect.center().y;
                        let fg = if e.enabled {
                            pal.text
                        } else {
                            pal.text_disabled
                        };
                        ui.painter().text(
                            egui::pos2(rect.left() + 14.0, y),
                            Align2::CENTER_CENTER,
                            icon,
                            icons::font(t.metrics.icon_size),
                            pal.text_muted,
                        );
                        // Label with matched characters in the accent colour.
                        let mut job = egui::text::LayoutJob::default();
                        for (ci, ch) in e.label.chars().enumerate() {
                            let hit = e.matched.contains(&ci);
                            let color = if hit && e.enabled {
                                pal.accent_text
                            } else {
                                fg
                            };
                            let family = if hit {
                                typography::strong_family()
                            } else {
                                egui::FontFamily::Proportional
                            };
                            job.append(
                                &ch.to_string(),
                                0.0,
                                egui::TextFormat::simple(
                                    egui::FontId::new(t.metrics.body_size, family),
                                    color,
                                ),
                            );
                        }
                        let g = ui.painter().layout_job(job);
                        let label_w = g.size().x;
                        ui.painter().galley(
                            egui::pos2(rect.left() + 30.0, y - g.size().y / 2.0),
                            g,
                            fg,
                        );
                        ui.painter().text(
                            egui::pos2(rect.left() + 30.0 + label_w + 10.0, y),
                            Align2::LEFT_CENTER,
                            &e.detail,
                            egui::FontId::proportional(t.metrics.small_size),
                            pal.text_muted,
                        );
                        if let Some(s) = &e.shortcut {
                            let font = egui::FontId::monospace(t.metrics.small_size - 1.0);
                            let g =
                                ui.painter()
                                    .layout_no_wrap(s.clone(), font, pal.text_secondary);
                            let chip = egui::Rect::from_min_size(
                                egui::pos2(
                                    rect.right() - g.size().x - 18.0,
                                    y - g.size().y / 2.0 - 3.0,
                                ),
                                g.size() + vec2(12.0, 6.0),
                            );
                            ui.painter().rect(
                                chip,
                                egui::CornerRadius::same(radius::SM),
                                pal.chrome,
                                egui::Stroke::new(1.0, pal.hairline),
                                egui::StrokeKind::Inside,
                            );
                            ui.painter()
                                .galley(chip.min + vec2(6.0, 3.0), g, pal.text_secondary);
                        }
                        if resp.clicked() {
                            chosen = Some(e.clone());
                        }
                    }
                    let n = entries.len();
                    if n > super::palette::MAX_SHOWN {
                        ui.label(
                            RichText::new(format!(
                                "{} more — keep typing to narrow",
                                n - super::palette::MAX_SHOWN
                            ))
                            .size(t.metrics.small_size)
                            .color(pal.text_muted),
                        );
                    }
                    ui.add_space(space::XS);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = space::XS;
                        for (k, what) in [("↑↓", "select"), ("Enter", "run"), ("Esc", "close")]
                        {
                            widgets::key_chip(ui, t, k);
                            ui.label(
                                RichText::new(what)
                                    .size(t.metrics.small_size)
                                    .color(pal.text_muted),
                            );
                            ui.add_space(space::SM);
                        }
                    });
                });
        });
    if enter {
        chosen = entries.get(p.selected).cloned();
    }
    let clicked_outside = ctx.input(|i| i.pointer.any_pressed())
        && ctx
            .pointer_interact_pos()
            .is_some_and(|pos| !area.response.rect.contains(pos));
    match chosen {
        Some(e) if e.enabled => match e.choice {
            Choice::Action(a) => Outcome::Run(a),
            Choice::Go(a) => Outcome::Go(a),
        },
        None if clicked_outside => Outcome::Close,
        Some(_) | None => Outcome::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_bytes_parse_with_or_without_spaces() {
        assert_eq!(parse_bytes("55 48 89 e5"), Ok(vec![0x55, 0x48, 0x89, 0xe5]));
        assert_eq!(parse_bytes("4889E5"), Ok(vec![0x48, 0x89, 0xe5]));
        assert!(parse_bytes("488").is_err());
        assert!(parse_bytes("zz").is_err());
        assert!(parse_bytes(" ").is_err());
    }

    #[test]
    fn names_are_checked() {
        assert!(valid_name("parse_config").is_ok());
        assert!(valid_name("two words").is_err());
        assert!(valid_name("").is_err());
    }
}
