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

/// Test 4, the mutation check: a model that differs from the reference in
/// one attribute value fails both comparisons of tests 1 and 2. Each
/// mutation edits one attribute in the model's XML, decodes it, and checks
/// that the packed stream no longer equals the inflated reference file and
/// the XML no longer equals `sleigh -y`'s text.
#[test]
fn mutated_models_fail_the_differential_checks() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Sleigh) else {
        return;
    };
    let limits = Limits::default();
    let sla_path = reference.sla_file("Toy", "toy_be");
    let stream = inflate(&std::fs::read(&sla_path).unwrap(), &limits).unwrap();
    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("toy_be.sla");
    let spec = reference.language_dir("Toy").join("toy_be.slaspec");
    reference.sleigh().switch('y').compile(&spec, &target).unwrap();
    let oracle_xml = std::fs::read_to_string(&target).unwrap();
    let xml = Sla::decode_packed(&stream, &limits).unwrap().encode_xml().unwrap();
    assert_eq!(xml, oracle_xml, "the unmutated model passes");
    // (description, attribute text found first in the document, replacement)
    let mutations = [
        ("header uniqbase", "uniqbase=\"0x3d00\"", "uniqbase=\"0x3d01\""),
        ("space delay", "name=\"ram\" index=\"3\" bigendian=\"true\" delay=\"1\"", "name=\"ram\" index=\"3\" bigendian=\"true\" delay=\"2\""),
        ("symbol name", "name=\"r0\"", "name=\"r0x\""),
        ("varnode offset", "space=\"register\" off=\"0x1000\"", "space=\"register\" off=\"0x1001\""),
        ("constructor line", " line=\"", " line=\"1"),
        ("print piece", "<print piece=\" \"/>", "<print piece=\"  \"/>"),
        ("operand minlen", "minlen=\"0\"", "minlen=\"1\""),
        ("token field signbit", "signbit=\"false\"", "signbit=\"true\""),
        ("decision number", "<decision number=\"", "<decision number=\"9"),
        ("mask word", "<mask_word mask=\"0x80000000\" val=\"0x0\"", "<mask_word mask=\"0x80000000\" val=\"0x80000000\""),
        ("const_real", "<const_real val=\"0x4\"/>", "<const_real val=\"0x5\"/>"),
        ("opcode", "code=\"COPY\"", "code=\"INT_ZEXT\""),
    ];
    let mut tried = 0;
    for (name, find, replace) in mutations {
        let Some(at) = xml.find(find) else {
            panic!("{name}: `{find}` not in the toy_be document");
        };
        let mut mutated = xml.clone();
        mutated.replace_range(at..at + find.len(), replace);
        let model = match Sla::decode_xml(&mutated, &limits) {
            Ok(model) => model,
            Err(error) => panic!("{name}: the mutated model does not decode: {error}"),
        };
        assert_ne!(model.encode_packed().unwrap(), stream, "{name}: test 1 still passes");
        assert_ne!(model.encode_xml().unwrap(), oracle_xml, "{name}: test 2 still passes");
        tried += 1;
    }
    eprintln!("mutation check: {tried} single-attribute mutations, each failed tests 1 and 2");
}
