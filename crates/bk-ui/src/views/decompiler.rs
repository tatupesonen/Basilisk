//! The Decompiler window: token-coloured C for the function at the current
//! location, cross-highlighted with the Listing.
//!
//! Listing → Decompiler: the lines produced from the instruction at the
//! current location are marked. Decompiler → Listing: putting the cursor on
//! a line moves the location to its first instruction (the Listing follows)
//! and marks all of that line's instructions there. Clicking a token marks
//! its other uses; middle-click sets Ghidra's persistent highlight, shared
//! with the Listing.

use std::sync::Arc;

use egui::text::{LayoutJob, TextFormat};
use egui::{Align2, Color32, CornerRadius, FontFamily, FontId, Galley, Rect, Stroke, pos2, vec2};

use super::listing::layout::Span;
use super::scroller::Scroller;
use super::{Related, Target, View, ViewCx, ViewKind};
use crate::actions::ActionId;
use crate::design::{Tokens, icons, syntax, widgets};
use crate::model::{
    Address, DecompiledFunction, FunctionInfo, Location, Referent, SourceError, SourceResult,
    TokenKind,
};
use crate::task::Pending;

type Fetch = Pending<SourceResult<(Option<FunctionInfo>, Option<DecompiledFunction>)>>;

#[derive(Debug, Clone)]
struct LineLayout {
    galley: Arc<Galley>,
    spans: Vec<Span>,
}

/// The Decompiler view.
#[derive(Debug)]
pub struct DecompilerView {
    snapshot: Option<Location>,
    fetch: Option<Fetch>,
    function: Option<Arc<DecompiledFunction>>,
    info: Option<FunctionInfo>,
    error: Option<String>,
    revision: u64,
    seen_generation: Option<u64>,
    layouts: Vec<LineLayout>,
    layout_key: Option<(u64, usize)>,
    scroller: Scroller,
    cursor: Option<(usize, Option<usize>)>,
    /// Lines produced from the current location (listing → decompiler).
    marked: Vec<usize>,
    reveal_marked: bool,
    gutter: f32,
    cw: f32,
    preview: super::preview::Preview,
}

impl DecompilerView {
    /// A decompiler that follows the current location, or a snapshot of
    /// the function at `snapshot`.
    pub fn new(snapshot: Option<Location>) -> Self {
        Self {
            snapshot,
            fetch: None,
            function: None,
            info: None,
            error: None,
            revision: u64::MAX,
            seen_generation: None,
            layouts: Vec::new(),
            layout_key: None,
            scroller: Scroller::default(),
            cursor: None,
            marked: Vec::new(),
            reveal_marked: false,
            gutter: 40.0,
            cw: 8.0,
            preview: super::preview::Preview::default(),
        }
    }

    fn request(&mut self, cx: &ViewCx<'_>, a: Address, force: bool) {
        let shown = if force {
            None
        } else {
            self.function.as_ref().map(|f| f.entry)
        };
        self.fetch = Some(cx.client.request(move |s| {
            let info = s.function_containing(a)?;
            match &info {
                Some(f) if Some(f.entry) == shown => Ok((info, None)),
                Some(_) => {
                    let d = s.decompile(a)?;
                    Ok((info, Some(d)))
                }
                None => Err(SourceError::NoFunction(a)),
            }
        }));
    }

    fn location(&self, cx: &ViewCx<'_>) -> Address {
        self.snapshot
            .map_or_else(|| cx.shared.nav.current().address, |l| l.address)
    }

    fn sync(&mut self, cx: &mut ViewCx<'_>) {
        let rev = cx.client.revision();
        let generation = cx.shared.nav.generation();
        if rev != self.revision {
            self.revision = rev;
            let a = self.location(cx);
            self.request(cx, a, true);
        } else if self.seen_generation != Some(generation) && self.snapshot.is_none() {
            let a = self.location(cx);
            self.request(cx, a, false);
        }
        self.seen_generation = Some(generation);
        if let Some(f) = &mut self.fetch {
            if let Some(r) = f.take() {
                self.fetch = None;
                match r {
                    Ok((info, decompiled)) => {
                        self.error = None;
                        if let Some(d) = decompiled {
                            let same = self.function.as_ref().is_some_and(|f| f.entry == d.entry);
                            self.function = Some(Arc::new(d));
                            self.layout_key = None;
                            if !same {
                                self.cursor = None;
                                self.scroller = Scroller::default();
                            }
                        }
                        self.info = info;
                        self.reveal_marked = true;
                    }
                    Err(SourceError::NoFunction(a)) => {
                        self.function = None;
                        self.info = None;
                        self.error = Some(format!("No function at {a}"));
                    }
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        }
        // Mark the lines of the current location.
        let here = cx.shared.nav.current().address;
        self.marked = match &self.function {
            Some(f) if self.snapshot.is_none() => f
                .lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.covers(here))
                .map(|(i, _)| i)
                .collect(),
            _ => Vec::new(),
        };
    }

    fn layout(&mut self, ui: &egui::Ui, t: &Tokens) {
        let Some(f) = &self.function else {
            self.layouts.clear();
            return;
        };
        let key = (u64::from(t.kind == crate::design::ThemeKind::Dark) + (t.metrics.code_size as u64) * 2, f.lines.len());
        if self.layout_key == Some(key) && self.layouts.len() == f.lines.len() {
            return;
        }
        self.layout_key = Some(key);
        let font = FontId::monospace(t.metrics.code_size);
        self.cw = ui.fonts_mut(|fo| fo.glyph_width(&font, '0'));
        let digits = f.lines.len().to_string().len().max(2);
        self.gutter = (digits as f32 + 2.0) * self.cw + 8.0;
        let painter = ui.painter();
        self.layouts = f
            .lines
            .iter()
            .map(|line| {
                let mut job = LayoutJob::default();
                job.wrap.max_width = f32::INFINITY;
                let mut col = usize::from(line.indent) * 2;
                job.append(
                    "",
                    col as f32 * self.cw,
                    TextFormat::simple(font.clone(), Color32::TRANSPARENT),
                );
                let mut spans = Vec::new();
                // The signature line (unindented, no keywords) names the function.
                let defining_line = line.indent == 0 && !line.tokens.iter().any(|t| t.kind == TokenKind::Keyword);
                for tok in &line.tokens {
                    let x0 = col as f32 * self.cw;
                    let fam = if defining_line && tok.kind == TokenKind::Function {
                        syntax::family(tok.kind, true)
                    } else {
                        FontFamily::Monospace
                    };
                    job.append(
                        &tok.text,
                        0.0,
                        TextFormat::simple(
                            FontId::new(t.metrics.code_size, fam),
                            syntax::color(&t.syntax, tok.kind),
                        ),
                    );
                    col += tok.text.chars().count();
                    if !matches!(tok.kind, TokenKind::Plain | TokenKind::Punctuation) || tok.referent.is_some() {
                        spans.push(Span {
                            x0,
                            x1: col as f32 * self.cw,
                            token: tok.clone(),
                        });
                    }
                }
                LineLayout {
                    galley: painter.layout_job(job),
                    spans,
                }
            })
            .collect();
    }

    fn token_at(&self, line: usize, x: f32) -> Option<usize> {
        self.layouts
            .get(line)?
            .spans
            .iter()
            .position(|s| x >= s.x0 && x < s.x1)
    }

    fn cursor_token(&self) -> Option<&Span> {
        let (l, t) = self.cursor?;
        self.layouts.get(l)?.spans.get(t?)
    }

    /// Puts the cursor on a line (and token), moving the tool's location
    /// to the line's first instruction so the Listing follows.
    fn set_cursor(&mut self, cx: &mut ViewCx<'_>, line: usize, token: Option<usize>) {
        self.cursor = Some((line, token));
        let Some(f) = &self.function else { return };
        let Some(l) = f.lines.get(line) else { return };
        cx.shared.related = Related {
            ranges: l.ranges.clone(),
        };
        if let Some(r) = l.ranges.first() {
            if self.snapshot.is_none() && !l.covers(cx.shared.nav.current().address) {
                cx.shared.nav.move_to(Location::at(r.start));
                self.seen_generation = Some(cx.shared.nav.generation());
            }
        }
    }

    fn follow(&mut self, cx: &mut ViewCx<'_>) -> bool {
        let target = self
            .cursor_token()
            .and_then(|s| s.token.referent.as_ref().and_then(Referent::address));
        match target {
            Some(a) => {
                cx.shared.nav.go(Location::at(a));
                true
            }
            None => false,
        }
    }

    fn step_highlight(&mut self, cx: &mut ViewCx<'_>, forward: bool) -> bool {
        let Some(h) = cx.shared.highlight.clone().or_else(|| self.cursor_token().map(|s| s.token.clone())) else {
            return false;
        };
        let all: Vec<(usize, usize)> = self
            .layouts
            .iter()
            .enumerate()
            .flat_map(|(l, ll)| {
                ll.spans
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.token.matches(&h))
                    .map(move |(i, _)| (l, i))
            })
            .collect();
        let here = self.cursor.map_or((0, 0), |(l, t)| (l, t.unwrap_or(0)));
        let next = if forward {
            all.iter().find(|p| **p > here).or_else(|| all.first())
        } else {
            all.iter().rev().find(|p| **p < here).or_else(|| all.last())
        };
        if let Some(&(l, i)) = next {
            self.set_cursor(cx, l, Some(i));
            self.scroller.keep_visible(l as u64, self.layouts.len() as u64);
        }
        true
    }

    fn keyboard(&mut self, ui: &egui::Ui, cx: &mut ViewCx<'_>) {
        if !cx.focused || ui.ctx().egui_wants_keyboard_input() || self.layouts.is_empty() {
            return;
        }
        let n = self.layouts.len();
        let (mut line, mut tok) = self.cursor.unwrap_or((0, None));
        let page = self.scroller.visible.saturating_sub(1).max(1) as usize;
        let mut moved = false;
        ui.input(|i| {
            for e in &i.events {
                if let egui::Event::Key { key, pressed: true, modifiers, .. } = e {
                    if modifiers.command || modifiers.alt {
                        continue;
                    }
                    moved = true;
                    match key {
                        egui::Key::ArrowDown => (line, tok) = ((line + 1).min(n - 1), None),
                        egui::Key::ArrowUp => (line, tok) = (line.saturating_sub(1), None),
                        egui::Key::PageDown => (line, tok) = ((line + page).min(n - 1), None),
                        egui::Key::PageUp => (line, tok) = (line.saturating_sub(page), None),
                        egui::Key::ArrowRight => tok = Some(tok.map_or(0, |t| t + 1)),
                        egui::Key::ArrowLeft => tok = tok.and_then(|t| t.checked_sub(1)),
                        _ => moved = false,
                    }
                }
            }
        });
        if moved {
            let spans = self.layouts.get(line).map_or(0, |l| l.spans.len());
            tok = tok.filter(|_| spans > 0).map(|t| t.min(spans - 1));
            self.set_cursor(cx, line, tok);
            self.scroller.keep_visible(line as u64, n as u64);
        }
    }

    fn paint_line(&self, ui: &egui::Ui, cx: &ViewCx<'_>, i: usize, rect: Rect) {
        let t = cx.tokens;
        let p = t.palette;
        let painter = ui.painter();
        let Some(l) = self.layouts.get(i) else { return };
        let cursor_line = self.cursor.map(|c| c.0) == Some(i);
        let marked = self.marked.contains(&i);
        if cursor_line {
            painter.rect_filled(rect, CornerRadius::ZERO, p.cursor_line);
        } else if marked {
            painter.rect_filled(rect, CornerRadius::ZERO, p.related_line);
        }
        // Line numbers, as Ghidra's decompiler shows them.
        painter.text(
            pos2(rect.left() + self.gutter - 12.0, rect.center().y),
            Align2::RIGHT_CENTER,
            (i + 1).to_string(),
            FontId::monospace(t.metrics.code_size - 1.0),
            if cursor_line { p.text_secondary } else { p.text_disabled },
        );
        let origin = pos2(rect.left() + self.gutter, rect.center().y - l.galley.size().y / 2.0);
        let cursor_tok = self.cursor_token().map(|s| &s.token);
        for (k, s) in l.spans.iter().enumerate() {
            let r = Rect::from_min_max(
                pos2(origin.x + s.x0 - 1.0, rect.top() + 2.0),
                pos2(origin.x + s.x1 + 1.0, rect.bottom() - 2.0),
            );
            let persistent = cx.shared.highlight.as_ref().is_some_and(|h| h.matches(&s.token));
            let same_as_cursor = cursor_tok.is_some_and(|c| c.matches(&s.token));
            if s.token.referent.is_some() {
                super::token_node(ui, ui.id().with(("decomp-token", i, k)), r, &s.token);
            }
            if persistent {
                painter.rect_filled(r, CornerRadius::same(2), p.token_highlight);
            } else if same_as_cursor {
                painter.rect_filled(r, CornerRadius::same(2), widgets::fade(p.token_highlight, 0.55));
            }
            if cursor_line && self.cursor.and_then(|c| c.1) == Some(k) {
                painter.rect_stroke(
                    r,
                    CornerRadius::same(2),
                    Stroke::new(1.0, if cx.focused { p.accent } else { p.text_muted }),
                    egui::StrokeKind::Inside,
                );
            }
        }
        painter.galley(origin, l.galley.clone(), p.text);
        if cursor_line {
            let c = if cx.focused { p.accent } else { p.text_muted };
            painter.rect_filled(
                Rect::from_min_size(pos2(rect.left() + 4.0, rect.top() + 2.0), vec2(3.0, rect.height() - 4.0)),
                CornerRadius::same(1),
                c,
            );
        } else if marked {
            painter.rect_filled(
                Rect::from_min_size(pos2(rect.left() + 5.0, rect.top() + 3.0), vec2(1.5, rect.height() - 6.0)),
                CornerRadius::ZERO,
                p.text_muted,
            );
        }
    }
}

impl View for DecompilerView {
    fn kind(&self) -> ViewKind {
        ViewKind::Decompiler
    }

    fn title(&self, shared: &super::Shared) -> String {
        match &self.function {
            Some(f) => format!("Decompile: {} - ({})", f.name, shared.program.name),
            None => "Decompile".to_owned(),
        }
    }

    fn is_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    fn target(&self) -> Option<Target> {
        let f = self.function.as_ref()?;
        let (line, _) = self.cursor?;
        let l = f.lines.get(line)?;
        let token = self.cursor_token().map(|s| s.token.clone());
        // A function name refers to its entry; elsewhere the line's first
        // instruction is where comments go.
        let address = token
            .as_ref()
            .and_then(|t| match t.kind {
                TokenKind::Function if line == 0 || l.ranges.is_empty() => t.referent.as_ref().and_then(Referent::address),
                _ => None,
            })
            .or_else(|| l.ranges.first().map(|r| r.start))
            .unwrap_or(f.entry);
        Some(Target {
            address,
            token,
            function: Some(f.entry),
        })
    }

    fn handle(&mut self, action: ActionId, cx: &mut ViewCx<'_>) -> bool {
        match action {
            ActionId::FollowReference => self.follow(cx),
            ActionId::NextHighlight => self.step_highlight(cx, true),
            ActionId::PreviousHighlight => self.step_highlight(cx, false),
            ActionId::Copy => {
                if let (Some(f), Some((l, _))) = (&self.function, self.cursor) {
                    let text = f.lines.get(l).map(|l| l.tokens.iter().map(|t| &*t.text).collect::<String>());
                    cx.ctx.copy_text(text.unwrap_or_default());
                }
                true
            }
            _ => false,
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut ViewCx<'_>) {
        let t = *cx.tokens;
        self.sync(cx);
        ui.painter().rect_filled(ui.available_rect_before_wrap(), CornerRadius::ZERO, t.palette.surface);
        if self.function.is_none() {
            match (&self.error, &self.fetch) {
                (Some(e), _) => widgets::empty_state(ui, &t, icons::DECOMPILER, e, "Put the cursor in a function to decompile it."),
                (None, _) => widgets::empty_state(ui, &t, icons::DECOMPILER, "Decompiling…", ""),
            }
            return;
        }
        self.layout(ui, &t);
        self.keyboard(ui, cx);
        let n = self.layouts.len() as u64;
        if self.reveal_marked {
            self.reveal_marked = false;
            if let Some(&first) = self.marked.first() {
                self.scroller.reveal(first as u64, n);
            }
        }
        let row_h = t.metrics.code_row;
        let mut lines = Vec::new();
        let top_pad = 6.0;
        ui.add_space(top_pad);
        let shown = self.scroller.show(ui, &t, n, row_h, |_, i, r| lines.push((i, r)));
        for (i, r) in lines {
            self.paint_line(ui, cx, i as usize, r);
        }
        let resp = shown.response;
        let rect = shown.rect;
        let hit = |s: &Self, pos: egui::Pos2| {
            let k = ((pos.y - rect.top() + s.scroller.offset) / row_h).floor().max(0.0) as u64;
            let line = (s.scroller.top + k) as usize;
            let tok = s.token_at(line, pos.x - rect.left() - s.gutter);
            (line, tok)
        };
        let mut hovered = None;
        if let Some(pos) = resp.hover_pos() {
            let (line, tok) = hit(self, pos);
            if let Some(s) = tok.and_then(|k| self.layouts.get(line)?.spans.get(k)) {
                hovered = s.token.referent.as_ref().and_then(Referent::address);
                if hovered.is_some() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
            }
        }
        self.preview.want(cx, hovered);
        if self.preview.active() {
            let digits = crate::views::listing::layout::address_digits(cx.shared.program.image_base.offset(0xffff_ffff));
            resp.clone().on_hover_ui_at_pointer(|ui| self.preview.ui(ui, &t, digits));
        }
        if let Some(pos) = resp.interact_pointer_pos() {
            let (line, tok) = hit(self, pos);
            if (line as u64) < n && (resp.clicked() || resp.secondary_clicked() || resp.double_clicked()) {
                self.set_cursor(cx, line, tok);
            }
            if resp.double_clicked() {
                self.follow(cx);
            }
            if resp.middle_clicked() {
                let token = tok.and_then(|k| self.layouts.get(line)?.spans.get(k)).map(|s| s.token.clone());
                cx.shared.highlight = match (token, &cx.shared.highlight) {
                    (Some(t), Some(h)) if t.matches(h) => None,
                    (t, _) => t,
                };
            }
        }
        let target = self.target();
        resp.context_menu(|ui| super::popup_menu(ui, cx, target.as_ref()));
        if self.fetch.is_some() {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(30));
        }
    }
}
