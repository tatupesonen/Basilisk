//! Arbitrary text decoded as a `<typegrp>` by `bk-decomp-types`, then the
//! factory encoded again.
//! The process must not panic, overflow the stack or hang.

#![no_main]

use std::sync::OnceLock;

use bk_decomp_types::{DataOrganization, TypeEnv, TypeFactory};
use libfuzzer_sys::fuzz_target;

/// A factory with the default core types, cloned for every input.
fn template() -> &'static TypeFactory {
    static F: OnceLock<TypeFactory> = OnceLock::new();
    F.get_or_init(|| {
        TypeFactory::with_core_types(TypeEnv::simple(8, false), DataOrganization::default())
            .unwrap_or_else(|_| TypeFactory::new(TypeEnv::simple(8, false), DataOrganization::default()))
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut f = template().clone();
    if f.decode_text(text).is_ok() {
        let mut enc = bk_marshal::XmlEncoder::new(false);
        let _ = f.encode(&mut enc);
    }
});
