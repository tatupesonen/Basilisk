//! Bodies of the `bk_sleigh_*` fuzz targets, shared with the regression
//! replay test in `crates/bk-sleigh/tests/fuzz_regressions.rs`.

#![allow(
    dead_code,
    reason = "shared between the fuzz targets and a replay test"
)]

use std::sync::{Arc, OnceLock};

use bk_core::Address;
use bk_sla::{Limits, Sla};
use bk_sleigh::{Decoder, Language, SliceBytes};

#[path = "../../../crates/bk-sleigh/tests/fixture/mod.rs"]
mod fixture;

/// The languages the decode target selects from: the `bkfix` fixture, and
/// some reference `.sla` files when `BASILISK_REFERENCE_DIR` names the
/// reference directory.
fn languages() -> &'static [Arc<Language>] {
    static LANGS: OnceLock<Vec<Arc<Language>>> = OnceLock::new();
    LANGS.get_or_init(|| {
        let mut out = vec![Arc::new(Language::from_sla(Arc::new(fixture::build())).expect("fixture"))];
        if let Some(root) = std::env::var_os("BASILISK_REFERENCE_DIR") {
            let root = std::path::PathBuf::from(root).join("Ghidra").join("Processors");
            for (module, file) in [
                ("x86", "x86-64.sla"),
                ("ARM", "ARM8_le.sla"),
                ("AARCH64", "AARCH64.sla"),
                ("MIPS", "mips32be.sla"),
                ("PowerPC", "ppc_32_be.sla"),
                ("Toy", "toy_be.sla"),
                ("V850", "V850.sla"),
            ] {
                let path = root.join(module).join("data").join("languages").join(file);
                if let Ok(sla) = Sla::read_file(&path, &Limits::default())
                    && let Ok(lang) = Language::from_sla(Arc::new(sla))
                {
                    out.push(Arc::new(lang));
                }
            }
        }
        out
    })
}

/// Decodes, prints and prepares the instruction in `bytes` at `offset`
/// with `words` as the context.
fn exercise(lang: &Arc<Language>, offset: u64, words: &[u32], bytes: &[u8]) {
    let mut db = lang.empty_context();
    for (i, &w) in words.iter().enumerate().take(lang.context_words()) {
        db.set_default(i, u32::MAX, w);
    }
    let mut decoder = Decoder::new(Arc::clone(lang));
    let source = SliceBytes::new(offset, bytes);
    let addr = Address::new(lang.default_space(), offset);
    let mut text = String::new();
    if decoder.decode(addr, &source, &db).is_ok() {
        let _ = decoder.mnemonic(&mut text);
        let _ = decoder.body(&mut text);
        let _ = decoder.prepare(addr, &source, &mut db);
    }
}

/// Input: a language selector byte, eight context bytes, then the
/// instruction bytes.
pub(crate) fn decode(data: &[u8]) {
    let langs = languages();
    let Some((&selector, rest)) = data.split_first() else { return };
    let lang = &langs[selector as usize % langs.len()];
    let (context, bytes) = rest.split_at(rest.len().min(8));
    let words: Vec<u32> = context.chunks(4).map(|c| c.iter().fold(0u32, |w, &b| (w << 8) | u32::from(b))).collect();
    let offset = u64::from(selector) * 2;
    exercise(lang, offset, &words, bytes);
}

/// Input: an inflated `.sla` stream. A model that passes validation must
/// decode fixed byte patterns without panicking or looping.
pub(crate) fn hostile_sla(data: &[u8]) {
    let limits = Limits {
        inflated_size: 1 << 22,
        ..Limits::default()
    };
    let Ok(sla) = Sla::decode_packed(data, &limits) else { return };
    let Ok(lang) = Language::from_sla(Arc::new(sla)) else { return };
    let lang = Arc::new(lang);
    let patterns: [&[u8]; 4] = [&[0; 16], &[0xff; 16], &[0x55, 0xaa, 0x0f, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], &[0x80; 16]];
    for (i, bytes) in patterns.iter().enumerate() {
        exercise(&lang, 0x1000 * i as u64, &[0, u32::MAX], bytes);
    }
}
