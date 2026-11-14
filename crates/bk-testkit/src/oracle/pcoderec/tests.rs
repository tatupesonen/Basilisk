use super::*;
use crate::oracle::strategies::mutated;
use crate::oracle::{read_text, sample_dir};
use proptest::prelude::*;

fn sample() -> String {
    read_text(&sample_dir().join("elseif.pcoderec.gz")).unwrap()
}

#[test]
fn the_elseif_recording_is_read() {
    let text = sample();
    let rec = Recording::parse(&text).unwrap();
    assert_eq!(rec.write(), text);
    assert_eq!(rec.language, "x86:LE:64:default");
    assert_eq!(rec.compiler, "gcc");
    assert_eq!(rec.context_dependent, []);
    let replay = RecordedPcode::new(rec);
    let entry = OracleAddress {
        space: "ram".into(),
        offset: 0x0010_06ca,
    };
    let Answer::Instruction { length, ops } = replay.instruction(&entry).unwrap() else {
        panic!()
    };
    assert_eq!(length, 1);
    assert_eq!(ops.len(), 3);
    assert_eq!(ops[2].opcode, "STORE");
    assert_eq!(
        ops[2].inputs[0],
        RecVarnode {
            space: "const".into(),
            offset: 3,
            size: 8,
            name: Some("ram".into())
        }
    );
    assert_eq!(ops[0].inputs[0].name.as_deref(), Some("RBP"));
    let nowhere = OracleAddress {
        space: "ram".into(),
        offset: 1,
    };
    assert_eq!(
        replay.instruction(&nowhere),
        Err(LookupError::NoRecord(nowhere.clone()))
    );
    assert_eq!(replay.length(&nowhere), Err(LookupError::NoRecord(nowhere)));
}

const SMALL: &str = "H\tpcoderec\t1\tx\tgcc\nI\tram:0x10\t2\t1\nP\tram:0x10\tCOPY\t(register,0x0,4,EAX)\t(const,0x1,4)\n\
U\tram:0x12\tunimplemented\t4\tUnimplemented instruction\nL\tram:0x10\t2\nT\t1\t1\t1\n";

#[test]
fn errors_lengths_and_context_dependence() {
    let rec = Recording::parse(SMALL).unwrap();
    assert_eq!(rec.write(), SMALL);
    let replay = RecordedPcode::new(rec.clone());
    let a12 = OracleAddress::parse("ram:0x12").unwrap();
    assert_eq!(
        replay.instruction(&a12).unwrap(),
        Answer::Error {
            kind: "unimplemented",
            length: Some(4),
            message: "Unimplemented instruction"
        }
    );
    assert_eq!(
        replay.length(&OracleAddress::parse("ram:0x10").unwrap()),
        Ok(2)
    );
    // The same address answered differently: X record required.
    let twice = SMALL.replace("T\t1\t1\t1\n", "I\tram:0x10\t3\t0\nT\t2\t1\t1\n");
    let error = Recording::parse(&twice).unwrap_err().to_string();
    assert!(error.contains("differing"), "{error}");
    let with_x = twice.replace("gcc\n", "gcc\nX\tram:0x10\n");
    let rec = Recording::parse(&with_x).unwrap();
    assert_eq!(rec.write(), with_x);
    let replay = RecordedPcode::new(rec);
    let a10 = OracleAddress::parse("ram:0x10").unwrap();
    assert_eq!(
        replay.instruction(&a10),
        Err(LookupError::ContextDependent(a10.clone()))
    );
    // An instruction record and a length record at one address do not conflict.
    assert!(
        Recording::parse(SMALL)
            .unwrap()
            .differing_addresses()
            .is_empty()
    );
    for bad in [
        SMALL.replace("T\t1\t1\t1", "T\t2\t1\t1"),
        SMALL.replace("\t1\nP", "\t2\nP"),
        SMALL.replace("unimplemented", "weird"),
        SMALL.replace("(const,0x1,4)", "(const,1,4)"),
    ] {
        assert!(Recording::parse(&bad).is_err(), "{bad}");
    }
}

proptest! {
    #[test]
    fn no_input_panics(text in "\\PC{0,200}") {
        let _ = Recording::parse(&text);
    }

    #[test]
    fn damaged_files_never_panic(text in mutated(Just(SMALL.to_owned()))) {
        if let Ok(rec) = Recording::parse(&text) {
            prop_assert_eq!(rec.write(), text);
        }
    }
}
