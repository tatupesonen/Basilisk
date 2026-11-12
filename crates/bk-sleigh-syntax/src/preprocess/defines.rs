//! The table of preprocessor definitions.

use std::borrow::Cow;
use std::collections::BTreeMap;

use super::expr::ExprEnv;

/// Preprocessor definitions: `@define NAME value`, `-DNAME=value`.
///
/// Callers pass an initial set to the preprocessor. Ghidra's compiler
/// launcher fills it from `-DNAME=VALUE` options and, for `-dMODULE`, with
/// the module's name mapped to its directory so that a specification can
/// `@include "$(MODULE)/data/languages/x.sinc"` across modules.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Defines {
    map: BTreeMap<String, String>,
}

impl Defines {
    /// No definitions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Defines `name` as `value`, replacing any earlier definition.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.map.insert(name.into(), value.into());
        self
    }

    /// Builder form of [`Self::set`].
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.set(name, value);
        self
    }

    /// Removes the definition of `name`, if any.
    pub fn undefine(&mut self, name: &str) {
        self.map.remove(name);
    }

    /// The value of `name`, if defined.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.map.get(name).map(String::as_str)
    }

    /// Whether `name` is defined.
    pub fn is_defined(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// All definitions, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.map.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of definitions.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether there are no definitions.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Defines {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self {
            map: iter
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }
}

impl ExprEnv for Defines {
    fn lookup(&self, name: &str) -> Option<Cow<'_, str>> {
        self.get(name).map(Cow::Borrowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_undefine() {
        let mut d = Defines::new().with("A", "1");
        d.set("B", "");
        assert_eq!(d.get("A"), Some("1"));
        assert_eq!(d.get("B"), Some(""));
        assert!(d.is_defined("B"));
        assert_eq!(d.get("C"), None);
        d.set("A", "2");
        assert_eq!(d.get("A"), Some("2"));
        d.undefine("A");
        d.undefine("never");
        assert!(!d.is_defined("A"));
        assert_eq!(d.len(), 1);
        let e: Defines = [("X", "x"), ("Y", "y")].into_iter().collect();
        assert_eq!(e.iter().collect::<Vec<_>>(), [("X", "x"), ("Y", "y")]);
        assert!(!e.is_empty());
    }
}
