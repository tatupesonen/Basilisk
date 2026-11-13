//! Applies the tokens to egui's style, so stock widgets (buttons, inputs,
//! menus, scroll bars) look like the rest of the interface.

use egui::style::{Selection, WidgetVisuals, Widgets};
use egui::{Color32, CornerRadius, Shadow, Stroke, Style, Visuals};

use super::tokens::{Density, ThemeKind, Tokens, radius, space};
use super::typography;

fn tokens_id() -> egui::Id {
    egui::Id::new("bk-ui-tokens")
}

/// Installs the fonts. Call once per context.
pub fn install_fonts(ctx: &egui::Context) {
    ctx.set_fonts(typography::fonts());
}

/// The tokens currently applied to `ctx` (dark and comfortable before the
/// first [`apply`]).
pub fn tokens(ctx: &egui::Context) -> Tokens {
    ctx.data(|d| d.get_temp::<Tokens>(tokens_id()))
        .unwrap_or_else(|| Tokens::new(ThemeKind::Dark, Density::Comfortable))
}

fn widget(bg: Color32, fg: Color32, stroke: Stroke) -> WidgetVisuals {
    WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: stroke,
        corner_radius: CornerRadius::same(radius::SM),
        fg_stroke: Stroke::new(1.0, fg),
        expansion: 0.0,
    }
}

/// Visuals built from the tokens.
pub fn visuals(t: &Tokens) -> Visuals {
    let p = t.palette;
    let mut v = match t.kind {
        ThemeKind::Dark => Visuals::dark(),
        ThemeKind::Light => Visuals::light(),
    };
    let none = Stroke::NONE;
    v.widgets = Widgets {
        noninteractive: widget(p.surface, p.text_secondary, Stroke::new(1.0, p.hairline)),
        inactive: widget(p.raised, p.text, none),
        hovered: widget(p.hover, p.text, Stroke::new(1.0, p.hairline)),
        active: widget(p.selection, p.text, Stroke::new(1.0, p.accent)),
        open: widget(p.hover, p.text, none),
    };
    // Unframed widgets (menu items, toolbar buttons) use `weak_bg_fill`.
    v.widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    v.selection = Selection {
        bg_fill: p.selection,
        stroke: Stroke::new(1.0, p.text),
    };
    v.hyperlink_color = p.accent_text;
    v.faint_bg_color = p.hover;
    v.extreme_bg_color = p.input;
    v.code_bg_color = p.surface;
    v.warn_fg_color = p.warning;
    v.error_fg_color = p.error;
    v.window_fill = p.raised;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(radius::LG);
    v.menu_corner_radius = CornerRadius::same(radius::MD);
    v.panel_fill = p.chrome;
    let shadow_alpha = if t.kind == ThemeKind::Dark { 120 } else { 40 };
    v.window_shadow = Shadow {
        offset: [0, 6],
        blur: 18,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };
    v.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 12,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };
    v.text_cursor.stroke = Stroke::new(2.0, p.accent);
    v.striped = false;
    v.indent_has_left_vline = false;
    v.collapsing_header_frame = false;
    v.button_frame = true;
    v.override_text_color = None;
    v
}

/// The whole style for the tokens.
pub fn style(t: &Tokens, base: &Style) -> Style {
    let mut s = base.clone();
    s.visuals = visuals(t);
    s.text_styles = typography::text_styles(&t.metrics);
    let sp = &mut s.spacing;
    sp.item_spacing = egui::vec2(space::MD, space::XS);
    sp.button_padding = egui::vec2(space::MD, space::XXS + 1.0);
    sp.menu_margin = egui::Margin::same(space::XS as i8);
    sp.window_margin = egui::Margin::same(space::LG as i8);
    sp.indent = space::LG + space::XS;
    sp.interact_size = egui::vec2(24.0, t.metrics.table_row - 4.0);
    sp.icon_width = 12.0;
    sp.icon_spacing = space::SM;
    sp.combo_height = 300.0;
    sp.scroll = egui::style::ScrollStyle {
        bar_width: 8.0,
        floating: true,
        floating_allocated_width: 0.0,
        ..egui::style::ScrollStyle::floating()
    };
    s.interaction.tooltip_delay = 0.35;
    s.interaction.show_tooltips_only_when_still = true;
    s.animation_time = 0.08;
    s
}

/// Applies `kind` and `density` to `ctx`: fonts sizes, colours, spacing,
/// and stores the tokens for the views.
pub fn apply(ctx: &egui::Context, kind: ThemeKind, density: Density) {
    let t = Tokens::new(kind, density);
    let theme = match kind {
        ThemeKind::Dark => egui::Theme::Dark,
        ThemeKind::Light => egui::Theme::Light,
    };
    let base = ctx.style_of(theme);
    ctx.set_style_of(theme, style(&t, &base));
    ctx.set_theme(theme);
    ctx.data_mut(|d| d.insert_temp(tokens_id(), t));
}
