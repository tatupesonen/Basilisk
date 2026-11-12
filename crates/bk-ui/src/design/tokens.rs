//! Design tokens: every colour and size the interface uses, in one place.
//!
//! Views never write a colour or a size literally; they ask the [`Tokens`]
//! of the current theme and density. The reasoning behind each value, and
//! the measured contrast figures, are in `docs/features/ui-design.md`; the
//! tests at the bottom of `contrast.rs` assert those figures.

use egui::Color32;

/// Light or dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ThemeKind {
    /// Soot backgrounds, bone text. The default.
    Dark,
    /// Bone backgrounds, soot text.
    Light,
}

/// Row height and type size: comfortable (default) or compact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Density {
    /// 20 px code rows, 13 px type.
    Comfortable,
    /// 17 px code rows, 12 px type.
    Compact,
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// A colour written as `#RRGGBB` (as in the brand guide and the design
/// document). A malformed string gives magenta, which a test rejects.
pub const fn hex(s: &str) -> Color32 {
    match s.as_bytes() {
        [b'#', r1, r2, g1, g2, b1, b2] => Color32::from_rgb(
            nibble(*r1) * 16 + nibble(*r2),
            nibble(*g1) * 16 + nibble(*g2),
            nibble(*b1) * 16 + nibble(*b2),
        ),
        _ => Color32::MAGENTA,
    }
}

/// The brand colours (`assets/brand/README.md`).
pub mod brand {
    use super::{Color32, hex};
    /// Ember: the mark on dark backgrounds, and the accent.
    pub const EMBER: Color32 = hex("#FF6A2B");
    /// Ember deep: the mark on light backgrounds.
    pub const EMBER_DEEP: Color32 = hex("#E8551A");
    /// Soot: dark backgrounds.
    pub const SOOT: Color32 = hex("#150F0D");
    /// Bone: text on dark.
    pub const BONE: Color32 = hex("#F1ECE6");
}

/// Surface and text colours of a theme.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    /// Menu bar, toolbar, tab strips, status bar: the frame around content.
    pub chrome: Color32,
    /// Pane content: tables, trees, the listing and the decompiler.
    pub surface: Color32,
    /// Menus, popups, the palette: things floating above.
    pub raised: Color32,
    /// Input fields.
    pub input: Color32,
    /// Separators between panes and table rows.
    pub border: Color32,
    /// Quiet lines inside a pane (table grid, gutters).
    pub hairline: Color32,
    /// Hovered rows and buttons.
    pub hover: Color32,
    /// Selected rows (Ghidra's selection), a faint ember tint.
    pub selection: Color32,
    /// The cursor's row in a code view.
    pub cursor_line: Color32,
    /// Rows of the other view linked to the cursor (cross-highlight).
    pub related_line: Color32,
    /// Background of tokens matching the highlighted one (Ghidra's
    /// middle-click highlight, yellow in Ghidra).
    pub token_highlight: Color32,
    /// Body text.
    pub text: Color32,
    /// Secondary text: column headers, labels, inactive tabs.
    pub text_secondary: Color32,
    /// Least important readable text: addresses, bytes, hints.
    pub text_muted: Color32,
    /// Disabled controls (exempt from the 4.5:1 rule, as WCAG allows).
    pub text_disabled: Color32,
    /// The accent: focus, the active pane's tab, the cursor marker.
    pub accent: Color32,
    /// Text drawn on an accent fill.
    pub on_accent: Color32,
    /// Accent used as text on `surface` (ember is too light for text on bone).
    pub accent_text: Color32,
    /// Errors.
    pub error: Color32,
    /// Warnings.
    pub warning: Color32,
    /// Success.
    pub success: Color32,
}

/// Colours of the syntax roles, shared by the listing and the decompiler.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SyntaxPalette {
    /// Instruction mnemonics.
    pub mnemonic: Color32,
    /// Registers.
    pub register: Color32,
    /// Immediates and constants (one role: a literal number).
    pub number: Color32,
    /// Labels and unnamed addresses.
    pub label: Color32,
    /// Functions, including imports.
    pub function: Color32,
    /// Global variables and data.
    pub global: Color32,
    /// Local variables and structure fields.
    pub variable: Color32,
    /// Parameters.
    pub parameter: Color32,
    /// C keywords.
    pub keyword: Color32,
    /// Data types.
    pub datatype: Color32,
    /// String literals.
    pub string: Color32,
    /// Comments.
    pub comment: Color32,
    /// Punctuation and plain text in code.
    pub punctuation: Color32,
    /// The address column.
    pub address: Color32,
    /// The bytes column.
    pub bytes: Color32,
}

/// Sizes that depend on density.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Metrics {
    /// Height of a listing or decompiler row.
    pub code_row: f32,
    /// Monospaced text size.
    pub code_size: f32,
    /// Height of a table or tree row.
    pub table_row: f32,
    /// Body text size of the chrome.
    pub body_size: f32,
    /// Small text (status bar, table headers, hints).
    pub small_size: f32,
    /// Titles (welcome screen headings, dialog titles).
    pub title_size: f32,
    /// Large display text (the welcome screen's name).
    pub display_size: f32,
    /// Height of the tab strip of a pane.
    pub tab_height: f32,
    /// Height of the toolbar.
    pub toolbar_height: f32,
    /// Height of the status bar.
    pub status_height: f32,
    /// Icon size in toolbars and tabs.
    pub icon_size: f32,
}

/// The spacing scale (px). Every gap and padding is one of these.
pub mod space {
    /// Hairline gaps.
    pub const XXS: f32 = 2.0;
    /// Inside compact controls.
    pub const XS: f32 = 4.0;
    /// Between related items.
    pub const SM: f32 = 6.0;
    /// Default padding.
    pub const MD: f32 = 8.0;
    /// Between groups.
    pub const LG: f32 = 12.0;
    /// Around sections.
    pub const XL: f32 = 16.0;
    /// Large layout gaps.
    pub const XXL: f32 = 24.0;
    /// Page margins (welcome screen).
    pub const XXXL: f32 = 40.0;
}

/// Corner radii (px).
pub mod radius {
    /// Buttons, inputs, chips.
    pub const SM: u8 = 4;
    /// Menus, popups.
    pub const MD: u8 = 6;
    /// The palette and dialogs.
    pub const LG: u8 = 8;
}

/// Every token of one theme at one density.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tokens {
    /// Which theme these are.
    pub kind: ThemeKind,
    /// Which density.
    pub density: Density,
    /// Surfaces and text.
    pub palette: Palette,
    /// Code colours.
    pub syntax: SyntaxPalette,
    /// Sizes.
    pub metrics: Metrics,
}

const DARK: Palette = Palette {
    chrome: hex("#15100E"),
    surface: hex("#1D1815"),
    raised: hex("#27211D"),
    input: hex("#15100E"),
    border: hex("#0E0A08"),
    hairline: hex("#2A2420"),
    hover: hex("#2B2420"),
    selection: hex("#45291C"),
    cursor_line: hex("#2C241F"),
    related_line: hex("#262421"),
    token_highlight: hex("#4A3D17"),
    text: hex("#ECE5DD"),
    text_secondary: hex("#B3A89E"),
    text_muted: hex("#968C82"),
    text_disabled: hex("#645B54"),
    accent: brand::EMBER,
    on_accent: brand::SOOT,
    accent_text: hex("#FF8A57"),
    error: hex("#F2806F"),
    warning: hex("#E8B85A"),
    success: hex("#8CCB8A"),
};

const LIGHT: Palette = Palette {
    chrome: hex("#EFEAE4"),
    surface: hex("#FBF8F4"),
    raised: hex("#FFFFFF"),
    input: hex("#FFFFFF"),
    border: hex("#D6CCC2"),
    hairline: hex("#EDE7E0"),
    hover: hex("#F0E9E1"),
    selection: hex("#F8D9C6"),
    cursor_line: hex("#F3ECE4"),
    related_line: hex("#F5F0E6"),
    token_highlight: hex("#F7E39A"),
    text: hex("#1E1814"),
    text_secondary: hex("#5E554E"),
    text_muted: hex("#6E645C"),
    text_disabled: hex("#A79D94"),
    accent: brand::EMBER_DEEP,
    on_accent: hex("#FFFFFF"),
    accent_text: hex("#B93D0A"),
    error: hex("#B4271C"),
    warning: hex("#8A5A00"),
    success: hex("#2E7A2E"),
};

const DARK_SYNTAX: SyntaxPalette = SyntaxPalette {
    mnemonic: hex("#E4DCD3"),
    register: hex("#8DB8E8"),
    number: hex("#A8DCA0"),
    label: hex("#E3AC7E"),
    function: hex("#EAC86E"),
    global: hex("#EE98B0"),
    variable: hex("#C0D2EA"),
    parameter: hex("#B5A6F5"),
    keyword: hex("#DA94D0"),
    datatype: hex("#4EC5C1"),
    string: hex("#D3D98A"),
    comment: hex("#968C82"),
    punctuation: hex("#B3A89E"),
    address: hex("#968C82"),
    bytes: hex("#7F766E"),
};

const LIGHT_SYNTAX: SyntaxPalette = SyntaxPalette {
    mnemonic: hex("#2A221D"),
    register: hex("#1D5FA8"),
    number: hex("#276B1A"),
    label: hex("#9A4E12"),
    function: hex("#7A5A00"),
    global: hex("#B02A5E"),
    variable: hex("#3F5163"),
    parameter: hex("#5B45C7"),
    keyword: hex("#9A2F96"),
    datatype: hex("#006A75"),
    string: hex("#5F5E00"),
    comment: hex("#6E655D"),
    punctuation: hex("#5E554E"),
    address: hex("#6E645C"),
    bytes: hex("#7A7068"),
};

const COMFORTABLE: Metrics = Metrics {
    code_row: 20.0,
    code_size: 13.0,
    table_row: 24.0,
    body_size: 13.0,
    small_size: 12.0,
    title_size: 16.0,
    display_size: 28.0,
    tab_height: 30.0,
    toolbar_height: 36.0,
    status_height: 26.0,
    icon_size: 15.0,
};

const COMPACT: Metrics = Metrics {
    code_row: 17.0,
    code_size: 12.0,
    table_row: 20.0,
    body_size: 12.0,
    small_size: 11.0,
    title_size: 15.0,
    display_size: 26.0,
    tab_height: 26.0,
    toolbar_height: 30.0,
    status_height: 22.0,
    icon_size: 14.0,
};

impl Tokens {
    /// The tokens of `kind` at `density`.
    pub fn new(kind: ThemeKind, density: Density) -> Self {
        let (palette, syntax) = match kind {
            ThemeKind::Dark => (DARK, DARK_SYNTAX),
            ThemeKind::Light => (LIGHT, LIGHT_SYNTAX),
        };
        let metrics = match density {
            Density::Comfortable => COMFORTABLE,
            Density::Compact => COMPACT,
        };
        Self {
            kind,
            density,
            palette,
            syntax,
            metrics,
        }
    }
}
