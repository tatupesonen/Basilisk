//! The interface's own components, built on egui and styled by the tokens:
//! toolbar buttons, key chips, filter fields, pane toolbars, empty states
//! and loading placeholders. Views use these rather than styling egui
//! widgets themselves, so every pane looks and behaves alike.

use egui::{
    Align2, Color32, CornerRadius, FontId, Rect, Response, RichText, Sense, Stroke, Ui, Vec2,
};

use super::icons;
use super::tokens::{Tokens, radius, space};
use super::typography;

/// A square icon button for toolbars and pane headers. Quiet until hovered.
pub fn icon_button(ui: &mut Ui, t: &Tokens, icon: &str, tooltip: &str, enabled: bool) -> Response {
    let side = t.metrics.toolbar_height - 8.0;
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), sense);
    let response = response.on_hover_text(tooltip);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, tooltip));
    let p = t.palette;
    let painter = ui.painter_at(rect);
    if enabled && (response.hovered() || response.has_focus()) {
        painter.rect_filled(rect, CornerRadius::same(radius::SM), p.hover);
    }
    if response.has_focus() {
        painter.rect_stroke(
            rect,
            CornerRadius::same(radius::SM),
            Stroke::new(1.0, p.accent),
            egui::StrokeKind::Inside,
        );
    }
    let color = if !enabled {
        p.text_disabled
    } else if response.hovered() {
        p.text
    } else {
        p.text_secondary
    };
    painter.text(
        rect.center(),
        Align2::CENTER_CENTER,
        icon,
        icons::font(t.metrics.icon_size + 1.0),
        color,
    );
    response
}

/// A thin vertical divider between toolbar groups.
pub fn toolbar_divider(ui: &mut Ui, t: &Tokens) {
    let h = t.metrics.toolbar_height - 14.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(space::SM * 2.0 + 1.0, h), Sense::hover());
    ui.painter().vline(
        rect.center().x,
        rect.y_range(),
        Stroke::new(1.0, t.palette.hairline),
    );
}

/// A key binding drawn as a small key cap (`Ctrl+Shift+F`).
pub fn key_chip(ui: &mut Ui, t: &Tokens, text: &str) -> Response {
    let font = FontId::monospace(t.metrics.small_size - 1.0);
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, t.palette.text_secondary);
    let size = galley.size() + egui::vec2(space::SM * 2.0, space::XXS * 2.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect(
        rect,
        CornerRadius::same(radius::SM),
        t.palette.chrome,
        Stroke::new(1.0, t.palette.hairline),
        egui::StrokeKind::Inside,
    );
    ui.painter().galley(
        rect.center() - galley.size() / 2.0,
        galley,
        t.palette.text_secondary,
    );
    response
}

/// A filter field with a search icon and a clear button. Returns the text
/// edit's response (changed when the text changed).
pub fn filter_field(ui: &mut Ui, t: &Tokens, text: &mut String, hint: &str, id: egui::Id) -> Response {
    let p = t.palette;
    let height = t.metrics.table_row;
    let width = ui.available_width();
    let frame = egui::Frame::NONE
        .fill(p.input)
        .stroke(Stroke::new(1.0, p.hairline))
        .corner_radius(CornerRadius::same(radius::SM))
        .inner_margin(egui::Margin::symmetric(space::SM as i8, 0));
    frame
        .show(ui, |ui| {
            ui.set_width(width - space::SM * 2.0 - 2.0);
            ui.set_height(height - 2.0);
            ui.horizontal_centered(|ui| {
                ui.label(icons::rich(icons::SEARCH).color(p.text_muted));
                let clear_w = if text.is_empty() { 0.0 } else { 18.0 };
                let edit = egui::TextEdit::singleline(text)
                    .id(id)
                    .hint_text(RichText::new(hint).color(p.text_muted))
                    .frame(egui::Frame::NONE)
                    .desired_width(ui.available_width() - clear_w);
                let r = ui.add(edit);
                name_field(ui, &r, hint);
                if !text.is_empty() {
                    let clear = ui
                        .add(egui::Label::new(icons::rich(icons::CLOSE).color(p.text_muted)).sense(Sense::click()))
                        .on_hover_text("Clear filter");
                    if clear.clicked() {
                        text.clear();
                        let mut r = r.clone();
                        r.mark_changed();
                        return r;
                    }
                }
                r
            })
            .inner
        })
        .inner
}

/// Gives a text field an accessible name (its hint), which egui leaves
/// empty for fields without a visible label.
pub fn name_field(ui: &Ui, response: &Response, name: &str) {
    ui.ctx()
        .accesskit_node_builder(response.id, |node| node.set_label(name.to_owned()));
}

/// The strip at the top of a pane holding its filter and buttons.
pub fn pane_toolbar<R>(ui: &mut Ui, t: &Tokens, add: impl FnOnce(&mut Ui) -> R) -> R {
    let r = egui::Frame::NONE
        .fill(t.palette.surface)
        .inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(add).inner
        })
        .inner;
    let rect = ui.min_rect();
    ui.painter().hline(
        rect.x_range(),
        ui.cursor().top(),
        Stroke::new(1.0, t.palette.hairline),
    );
    r
}

/// A centred message for an empty pane: an icon, a title and what to do.
pub fn empty_state(ui: &mut Ui, t: &Tokens, icon: &str, title: &str, detail: &str) {
    let p = t.palette;
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.3).max(space::XL));
        ui.label(icons::rich(icon).size(28.0).color(p.text_disabled));
        ui.add_space(space::SM);
        ui.label(
            RichText::new(title)
                .family(typography::strong_family())
                .color(p.text_secondary),
        );
        ui.add_space(space::XXS);
        ui.label(RichText::new(detail).color(p.text_muted).size(t.metrics.small_size));
    });
}

/// A loading placeholder: a soft bar where text will appear.
pub fn placeholder_bar(ui: &Ui, t: &Tokens, rect: Rect, fraction: f32) {
    let h = (rect.height() * 0.4).max(4.0);
    let bar = Rect::from_min_size(
        egui::pos2(rect.left(), rect.center().y - h / 2.0),
        egui::vec2(rect.width() * fraction.clamp(0.05, 1.0), h),
    );
    ui.painter()
        .rect_filled(bar, CornerRadius::same(radius::SM), t.palette.hover);
}

/// A small muted section heading inside a pane or dialog.
pub fn section_label(ui: &mut Ui, t: &Tokens, text: &str) {
    ui.label(
        RichText::new(text)
            .family(typography::strong_family())
            .size(t.metrics.small_size)
            .color(t.palette.text_secondary),
    );
}

/// A primary (accent) button, used once per dialog for the main choice.
pub fn primary_button(ui: &mut Ui, t: &Tokens, text: &str) -> Response {
    let p = t.palette;
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .family(typography::strong_family())
                .color(p.on_accent),
        )
        .fill(p.accent)
        .corner_radius(CornerRadius::same(radius::SM))
        .min_size(egui::vec2(72.0, t.metrics.table_row)),
    )
}

/// A secondary button.
pub fn button(ui: &mut Ui, t: &Tokens, text: &str) -> Response {
    let p = t.palette;
    ui.add(
        egui::Button::new(RichText::new(text).color(p.text))
            .fill(p.raised)
            .stroke(Stroke::new(1.0, p.hairline))
            .corner_radius(CornerRadius::same(radius::SM))
            .min_size(egui::vec2(72.0, t.metrics.table_row)),
    )
}

/// Paints a focus ring around `rect` (keyboard focus indication).
pub fn focus_ring(ui: &Ui, t: &Tokens, rect: Rect) {
    ui.painter().rect_stroke(
        rect.shrink(0.5),
        CornerRadius::same(radius::SM),
        Stroke::new(1.0, t.palette.accent),
        egui::StrokeKind::Inside,
    );
}

/// A colour with reduced opacity (for overlays).
pub fn fade(c: Color32, alpha: f32) -> Color32 {
    c.gamma_multiply(alpha)
}
