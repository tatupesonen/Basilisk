//! Typefaces and the type scale.
//!
//! Inter for the chrome and JetBrains Mono (no-ligature build) for code,
//! both under the SIL Open Font License 1.1 (licence texts beside the font
//! files in `assets/fonts/`), which permits bundling in a GPL-3.0 program.
//! Inter is drawn for screens at small sizes; JetBrains Mono has a tall
//! x-height and distinct `0O 1lI` shapes. Icons are Phosphor (MIT) through
//! `egui-phosphor`.

use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily, FontId, TextStyle};

use super::tokens::Metrics;

const INTER: &[u8] = include_bytes!("../../assets/fonts/Inter-Regular.ttf");
const INTER_SEMIBOLD: &[u8] = include_bytes!("../../assets/fonts/Inter-SemiBold.ttf");
const MONO: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMonoNL-Regular.ttf");
const MONO_SEMIBOLD: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMonoNL-SemiBold.ttf");

/// The icon face (Phosphor only).
pub fn icon_family() -> FontFamily {
    FontFamily::Name("bk-icons".into())
}

/// The semibold chrome face (pane titles, headings).
pub fn strong_family() -> FontFamily {
    FontFamily::Name("bk-strong".into())
}

/// The semibold code face (function names in headers).
pub fn code_strong_family() -> FontFamily {
    FontFamily::Name("bk-code-strong".into())
}

/// The font set: Inter and JetBrains Mono, with Phosphor icons as a
/// fallback in every family so an icon can sit inside any label.
pub fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::empty();
    for (name, bytes) in [
        ("inter", INTER),
        ("inter-semibold", INTER_SEMIBOLD),
        ("mono", MONO),
        ("mono-semibold", MONO_SEMIBOLD),
    ] {
        fonts
            .font_data
            .insert(name.into(), Arc::new(FontData::from_static(bytes)));
    }
    fonts
        .families
        .insert(FontFamily::Proportional, vec!["inter".into(), "mono".into()]);
    fonts
        .families
        .insert(FontFamily::Monospace, vec!["mono".into(), "inter".into()]);
    fonts.families.insert(
        strong_family(),
        vec!["inter-semibold".into(), "inter".into()],
    );
    fonts.families.insert(
        code_strong_family(),
        vec!["mono-semibold".into(), "mono".into()],
    );
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    // Icons are drawn in their own family: Inter has private-use glyphs of
    // its own that would shadow Phosphor's codepoints in a fallback chain.
    fonts.families.insert(icon_family(), vec!["phosphor".into()]);
    // Icons inside every family, after the text faces.
    for fam in [FontFamily::Monospace, strong_family(), code_strong_family()] {
        if let Some(list) = fonts.families.get_mut(&fam) {
            list.push("phosphor".into());
        }
    }
    fonts
}

/// Named text styles beyond egui's defaults.
pub mod style {
    use egui::TextStyle;

    /// Pane titles and section headings.
    pub fn heading() -> TextStyle {
        TextStyle::Name("bk-heading".into())
    }

    /// Display text (welcome screen).
    pub fn display() -> TextStyle {
        TextStyle::Name("bk-display".into())
    }

    /// Code (listing, decompiler).
    pub fn code() -> TextStyle {
        TextStyle::Monospace
    }
}

/// The text styles for a density.
pub fn text_styles(m: &Metrics) -> std::collections::BTreeMap<TextStyle, FontId> {
    [
        (TextStyle::Small, FontId::proportional(m.small_size)),
        (TextStyle::Body, FontId::proportional(m.body_size)),
        (TextStyle::Button, FontId::proportional(m.body_size)),
        (TextStyle::Monospace, FontId::monospace(m.code_size)),
        (TextStyle::Heading, FontId::new(m.title_size, strong_family())),
        (style::heading(), FontId::new(m.body_size, strong_family())),
        (style::display(), FontId::new(m.display_size, strong_family())),
    ]
    .into_iter()
    .collect()
}
