//! Key chords and the user's key map (defaults plus remappings, stored
//! between runs).

use std::collections::BTreeMap;
use std::fmt;

use egui::{Key, Modifiers};

use super::registry::{ACTIONS, ActionId, action};

/// A key with modifiers. `ctrl` is the platform command key: Control on
/// Linux and Windows, Command on macOS, as Ghidra maps it
/// (`DockingUtils.CONTROL_KEY_MODIFIER_MASK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KeyChord {
    /// The key.
    pub key: Key,
    /// Control (Command on macOS).
    pub ctrl: bool,
    /// Shift.
    pub shift: bool,
    /// Alt (Option on macOS).
    pub alt: bool,
}

/// A chord (for the action table).
pub const fn chord(key: Key, ctrl: bool, shift: bool, alt: bool) -> KeyChord {
    KeyChord {
        key,
        ctrl,
        shift,
        alt,
    }
}

impl KeyChord {
    /// Whether the chord has no modifier (fires only when no text field
    /// has focus, so typing is never taken for a command).
    pub fn is_bare(&self) -> bool {
        !self.ctrl && !self.alt && !self.shift
    }

    /// Whether `modifiers` match the chord exactly.
    pub fn matches(&self, key: Key, modifiers: Modifiers) -> bool {
        self.key == key
            && self.ctrl == modifiers.command
            && self.shift == modifiers.shift
            && self.alt == modifiers.alt
    }

    /// The chord as shown on this platform (`Ctrl+Shift+F`, `Cmd+E`).
    pub fn label(&self, mac: bool) -> String {
        let mut s = String::new();
        if self.ctrl {
            s.push_str(if mac { "Cmd+" } else { "Ctrl+" });
        }
        if self.alt {
            s.push_str(if mac { "Opt+" } else { "Alt+" });
        }
        if self.shift {
            s.push_str("Shift+");
        }
        s.push_str(key_name(self.key));
        s
    }
}

fn key_name(k: Key) -> &'static str {
    match k {
        Key::ArrowLeft => "Left",
        Key::ArrowRight => "Right",
        Key::ArrowUp => "Up",
        Key::ArrowDown => "Down",
        Key::Semicolon => ";",
        Key::Period => ".",
        Key::Comma => ",",
        Key::Delete => "Delete",
        Key::Enter => "Enter",
        Key::Escape => "Esc",
        other => other.name(),
    }
}

impl fmt::Display for KeyChord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label(false))
    }
}

/// The key bindings in force: Ghidra's defaults with the user's changes.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Keymap {
    /// Actions whose bindings the user changed (an empty list unbinds).
    overrides: BTreeMap<ActionId, Vec<KeyChord>>,
}

impl Keymap {
    /// The chords bound to `id`.
    pub fn bindings(&self, id: ActionId) -> &[KeyChord] {
        match self.overrides.get(&id) {
            Some(v) => v,
            None => action(id).map_or(&[], |a| a.keys),
        }
    }

    /// The first chord of `id`, for menus and the palette.
    pub fn primary(&self, id: ActionId) -> Option<KeyChord> {
        self.bindings(id).first().copied()
    }

    /// Binds `chord` to `id` alone, removing it from any other action.
    pub fn bind(&mut self, id: ActionId, chord: KeyChord) {
        for a in ACTIONS {
            if a.id != id && self.bindings(a.id).contains(&chord) {
                let rest: Vec<KeyChord> = self
                    .bindings(a.id)
                    .iter()
                    .copied()
                    .filter(|c| *c != chord)
                    .collect();
                self.overrides.insert(a.id, rest);
            }
        }
        self.overrides.insert(id, vec![chord]);
    }

    /// Removes every binding of `id`.
    pub fn unbind(&mut self, id: ActionId) {
        self.overrides.insert(id, Vec::new());
    }

    /// Restores Ghidra's default for `id`.
    pub fn reset(&mut self, id: ActionId) {
        self.overrides.remove(&id);
    }

    /// Restores every default.
    pub fn reset_all(&mut self) {
        self.overrides.clear();
    }

    /// Whether `id` has been changed from its default.
    pub fn is_changed(&self, id: ActionId) -> bool {
        self.overrides.contains_key(&id)
    }

    /// The action bound to a key press, if any.
    pub fn lookup(&self, key: Key, modifiers: Modifiers) -> Option<ActionId> {
        ACTIONS
            .iter()
            .map(|a| a.id)
            .find(|id| self.bindings(*id).iter().any(|c| c.matches(key, modifiers)))
    }

    /// The other action already using `chord`, if any.
    pub fn conflict(&self, id: ActionId, chord: KeyChord) -> Option<ActionId> {
        ACTIONS
            .iter()
            .map(|a| a.id)
            .find(|other| *other != id && self.bindings(*other).contains(&chord))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_come_from_the_table() {
        let k = Keymap::default();
        assert_eq!(k.primary(ActionId::GoTo).unwrap().to_string(), "G");
        assert_eq!(k.lookup(Key::G, Modifiers::NONE), Some(ActionId::GoTo));
        assert_eq!(
            k.lookup(Key::F, Modifiers::COMMAND | Modifiers::SHIFT),
            Some(ActionId::ShowReferences)
        );
        assert_eq!(k.lookup(Key::G, Modifiers::SHIFT), None);
    }

    #[test]
    fn remapping_moves_the_chord_and_survives_serialisation() {
        let mut k = Keymap::default();
        let n = chord(Key::N, false, false, false);
        k.bind(ActionId::Rename, n);
        assert_eq!(k.lookup(Key::N, Modifiers::NONE), Some(ActionId::Rename));
        assert_eq!(k.lookup(Key::L, Modifiers::NONE), None);
        assert!(k.is_changed(ActionId::Rename));
        // Taking G from Go To unbinds it there.
        k.bind(ActionId::Rename, chord(Key::G, false, false, false));
        assert!(k.bindings(ActionId::GoTo).is_empty());
        assert_eq!(k.conflict(ActionId::SetComment, chord(Key::G, false, false, false)), Some(ActionId::Rename));
        let json = serde_json::to_string(&k).unwrap();
        let back: Keymap = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
        k.reset_all();
        assert_eq!(k, Keymap::default());
    }

    #[test]
    fn chords_print_for_each_platform() {
        let c = chord(Key::F, true, true, false);
        assert_eq!(c.label(false), "Ctrl+Shift+F");
        assert_eq!(c.label(true), "Cmd+Shift+F");
        assert!(chord(Key::L, false, false, false).is_bare());
    }
}
