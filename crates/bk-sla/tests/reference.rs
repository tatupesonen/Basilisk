//! Differential tests against Ghidra's reference build (`features/sla.md`
//! section 6, tests 1–3). They need `BASILISK_REFERENCE_DIR` (default
//! `../reference`) and skip with a printed reason when it is absent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

use bk_sla::{Limits, PackedReader, Sla, inflate};

/// Test 1: for every reference `.sla`, the packed stream re-encoded from the
/// model equals the inflated file byte for byte, through both packed
/// decoders, and the two decoders give equal models.
#[test]
fn packed_round_trip_is_byte_exact() {
    let Some(reference) = bk_testkit::require_reference() else {
        return;
    };
    let files = reference.sla_files().unwrap();
    assert_eq!(files.len(), 150, "expected the 150 reference languages");
    let limits = Limits::default();
    let mut failures = Vec::new();
    for file in &files {
        let bytes = std::fs::read(&file.path).unwrap();
        let stream = inflate(&bytes, &limits).unwrap();
        let sla = match Sla::decode_packed(&stream, &limits) {
            Ok(sla) => sla,
            Err(error) => {
                failures.push(format!("{}/{}: {error}", file.module, file.name));
                continue;
            }
        };
        let encoded = sla.encode_packed().unwrap();
        if encoded != stream {
            let at = encoded.iter().zip(&stream).position(|(a, b)| a != b);
            failures.push(format!(
                "{}/{}: re-encoded stream differs (lengths {} vs {}, first difference at {at:?})",
                file.module,
                file.name,
                encoded.len(),
                stream.len()
            ));
            continue;
        }
        let other = Sla::decode_packed_using(&stream, &limits, PackedReader::Marshal).unwrap();
        if other != sla {
            failures.push(format!(
                "{}/{}: the two packed decoders disagree",
                file.module, file.name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The options the reference build compiled a module's specifications with
/// (`scripts/build-reference.sh` keeps them in `.state/lang/<Module>.opts`).
fn module_options(reference: &bk_testkit::ReferenceDir, module: &str) -> Vec<String> {
    let path = reference
        .root()
        .join(".state")
        .join("lang")
        .join(format!("{module}.opts"));
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Tests 2 and 3: for every `.slaspec`, `sleigh -y` writes the same text as
/// `encode_xml` of the reference `.sla`, and `decode_xml` of that text gives
/// the same model as the packed file.
#[test]
fn xml_text_equals_sleigh_y_and_reads_back() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Sleigh) else {
        return;
    };
    let specs = bk_testkit::corpus::language_files(&reference.processors_dir(), "slaspec").unwrap();
    assert_eq!(
        specs.len(),
        150,
        "expected the 150 reference specifications"
    );
    let out = tempfile::tempdir().unwrap();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    let limits = Limits::default();
    std::thread::scope(|scope| {
        for _ in 0..3 {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(spec) = specs.get(index) else { break };
                    if let Err(message) = check_xml(&reference, spec, out.path(), &limits) {
                        failures
                            .lock()
                            .unwrap()
                            .push(format!("{}/{}: {message}", spec.module, spec.name));
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn check_xml(
    reference: &bk_testkit::ReferenceDir,
    spec: &bk_testkit::LanguageFile,
    out: &std::path::Path,
    limits: &Limits,
) -> Result<(), String> {
    let mut sleigh = reference.sleigh().switch('y');
    for option in module_options(reference, &spec.module) {
        if let Some((name, value)) = option.strip_prefix("-D").and_then(|d| d.split_once('=')) {
            sleigh = sleigh.define(name, value);
        } else if let Some(letter) = option.strip_prefix('-').and_then(|s| s.chars().next()) {
            sleigh = sleigh.switch(letter);
        }
    }
    sleigh = sleigh.define("BaseDir", &reference.root().display().to_string());
    let target = out.join(format!("{}-{}.sla", spec.module, spec.name));
    sleigh
        .compile(&spec.path, &target)
        .map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(&target).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&target);
    let sla_path = reference.sla_file(&spec.module, &spec.name);
    let sla = Sla::read_file(&sla_path, limits).map_err(|e| e.to_string())?;
    let ours = sla.encode_xml().map_err(|e| e.to_string())?;
    if ours != text {
        let at = ours
            .bytes()
            .zip(text.bytes())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| ours.len().min(text.len()));
        let lo = at.saturating_sub(200);
        return Err(format!(
            "XML differs at byte {at}:\n--- ours\n{}\n--- sleigh -y\n{}",
            ours.get(lo..(at + 200).min(ours.len())).unwrap_or(""),
            text.get(lo..(at + 200).min(text.len())).unwrap_or("")
        ));
    }
    let from_xml = Sla::decode_xml(&text, limits).map_err(|e| format!("decode_xml: {e}"))?;
    if from_xml != sla {
        return Err("decode_xml gives a different model than the packed file".to_owned());
    }
    Ok(())
}
