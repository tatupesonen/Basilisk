//! Serialisation of [`bk_core::Provenance`], which `bk-core` does not make
//! serialisable itself: as its lower-case kind name.

use bk_core::Provenance;
use serde::{Deserialize, Deserializer, Serializer};

/// The name written for a provenance.
pub(crate) fn name(p: Provenance) -> Option<&'static str> {
    Some(match p {
        Provenance::Default => "default",
        Provenance::Analysis => "analysis",
        Provenance::Model => "model",
        Provenance::Imported => "imported",
        Provenance::LibrarySignature => "library_signature",
        Provenance::DebugInfo => "debug_info",
        Provenance::User => "user",
        _ => return None,
    })
}

/// The provenance with the given name.
pub(crate) fn from_name(s: &str) -> Option<Provenance> {
    Some(match s {
        "default" => Provenance::Default,
        "analysis" => Provenance::Analysis,
        "model" => Provenance::Model,
        "imported" => Provenance::Imported,
        "library_signature" => Provenance::LibrarySignature,
        "debug_info" => Provenance::DebugInfo,
        "user" => Provenance::User,
        _ => return None,
    })
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's `with` calls this with a reference"
)]
pub(crate) fn serialize<S: Serializer>(p: &Provenance, s: S) -> Result<S::Ok, S::Error> {
    match name(*p) {
        Some(n) => s.serialize_str(n),
        None => Err(serde::ser::Error::custom("provenance kind without a name")),
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Provenance, D::Error> {
    let text = String::deserialize(d)?;
    from_name(&text).ok_or_else(|| serde::de::Error::custom(format!("unknown provenance {text}")))
}
