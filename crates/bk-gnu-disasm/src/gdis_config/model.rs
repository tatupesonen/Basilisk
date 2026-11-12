//! The content of a `.gdis` file, and choosing options with it.

use std::collections::BTreeMap;

use super::ConfigError;

/// A parsed `.gdis` file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GdisConfig {
    /// Options sent with every request (`<global optstring=…>`).
    pub global: Option<String>,
    /// Options chosen by a context register's value.
    pub context: Option<ContextOptions>,
}

/// Options chosen by the value of a context register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextOptions {
    /// The context register's name, as in the SLEIGH language.
    pub register: String,
    /// Per register value. Values are Java `long`s, as `Long.decode` reads
    /// them; a register's value is compared after conversion to `i64`.
    pub options: BTreeMap<i64, ContextOption>,
}

/// What one context-register value selects.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContextOption {
    /// Options added to the global ones.
    pub optstring: Option<String>,
    /// Text Ghidra shows before the GNU disassembly (`"T: "` for Thumb).
    pub display_prefix: Option<String>,
}

impl GdisConfig {
    /// The option string for an instruction, as Ghidra builds it: the
    /// global options, followed after a comma by those the context
    /// register's value selects. `register_value` gives the value of the
    /// named register at the instruction. `None` means no options.
    ///
    /// A value with no entry selects nothing beyond the global options
    /// (Ghidra logs a warning then).
    pub fn options_for(
        &self,
        register_value: impl FnOnce(&str) -> Option<i64>,
    ) -> Result<Option<String>, ConfigError> {
        let selected = match &self.context {
            None => None,
            Some(context) => context
                .select(register_value)?
                .and_then(|o| o.optstring.as_deref()),
        };
        Ok(match (self.global.as_deref(), selected) {
            (Some(global), Some(selected)) => Some(format!("{global},{selected}")),
            (Some(only), None) | (None, Some(only)) => Some(only.to_owned()),
            (None, None) => None,
        })
    }

    /// The display prefix for an instruction (Ghidra's
    /// `getDisassemblyDisplayPrefix`), if the file names a context register
    /// and its value has one.
    pub fn display_prefix_for(
        &self,
        register_value: impl FnOnce(&str) -> Option<i64>,
    ) -> Result<Option<&str>, ConfigError> {
        match &self.context {
            None => Ok(None),
            Some(context) => Ok(context
                .select(register_value)?
                .and_then(|o| o.display_prefix.as_deref())),
        }
    }
}

impl ContextOptions {
    fn select(
        &self,
        register_value: impl FnOnce(&str) -> Option<i64>,
    ) -> Result<Option<&ContextOption>, ConfigError> {
        let value =
            register_value(&self.register).ok_or_else(|| ConfigError::UnknownContextRegister {
                register: self.register.clone(),
            })?;
        Ok(self.options.get(&value))
    }
}
