//! Tests for the `pcodedump` listing parser.

use super::*;
use proptest::prelude::*;

/// A listing in the shape the tool prints for x86-64 (abridged p-code).
const SAMPLE: &str = "H\t1\tx86:LE:64:default\tram\t0x1000\t10\n\
    I\t0x1000\t1\t1\t55\tPUSH\tRBP\n\
    P\tCOPY\t(unique,0x4f900,8)\t(register,0x28,8,RBP)\n\
    P\tINT_SUB\t(register,0x20,8,RSP)\t(register,0x20,8,RSP)\t(const,0x8,8)\n\
    P\tSTORE\t-\t(const,0x3,8,ram)\t(register,0x20,8,RSP)\t(unique,0x4f900,8)\n\
    I\t0x1001\t1\t1\tc3\tRET\t\n\
    P\tRETURN\t-\t(register,0x288,8,RIP)\n\
    E\t0x1002\t1\t06\tbad-data\tr0x00001002: Unable to resolve constructor\n\
    I\t0x1003\t2\t2\t0f0b\tWEIRD\ta\\tb\\\\c\n\
    U\tunimplemented\tInstruction not implemented in pcode:\\n r0x00001003: WEIRD\n\
    I\t0x1005\t4\t8\t0c100000\tjal\t0x400000\n\
    E\t0x1009\t1\tff\ttruncated\tinstruction extends past the end of the input\n\
    T\t4\t3\n";

#[test]
fn sample_parses_into_the_model() {
    let dump = parse_dump(SAMPLE).unwrap();
    assert_eq!(dump.language, "x86:LE:64:default");
    assert_eq!(
        (dump.space.as_str(), dump.base, dump.byte_count),
        ("ram", 0x1000, 10)
    );
    assert_eq!(dump.records.len(), 6);

    let instructions: Vec<_> = dump.instructions().collect();
    assert_eq!(instructions.len(), 4);
    let push = instructions[0];
    assert_eq!(
        (push.address, push.length, push.flow_length),
        (0x1000, 1, 1)
    );
    assert_eq!(push.bytes, [0x55]);
    assert_eq!(
        (push.mnemonic.as_str(), push.body.as_str()),
        ("PUSH", "RBP")
    );
    assert_eq!(push.pcode.len(), 3);
    assert_eq!(push.lift_error, None);

    let copy = &push.pcode[0];
    assert_eq!(copy.opcode, "COPY");
    let unique = DumpVarnode {
        space: "unique".to_owned(),
        offset: 0x4f900,
        size: 8,
        name: None,
    };
    assert_eq!(copy.output.as_ref(), Some(&unique));
    let rbp = DumpVarnode {
        space: "register".to_owned(),
        offset: 0x28,
        size: 8,
        name: Some("RBP".to_owned()),
    };
    assert_eq!(copy.inputs, [rbp]);

    let store = &push.pcode[2];
    assert_eq!(store.output, None);
    assert_eq!(store.inputs.len(), 3);
    assert_eq!(store.inputs[0].space, "const");
    assert_eq!(
        store.inputs[0].offset, 3,
        "the space's index, not a pointer"
    );
    assert_eq!(store.inputs[0].name.as_deref(), Some("ram"));

    assert_eq!(instructions[1].body, "", "an instruction without operands");

    let weird = instructions[2];
    assert_eq!(weird.body, "a\tb\\c", "escapes are undone");
    assert_eq!(weird.pcode, []);
    let lift_error = weird.lift_error.as_ref().unwrap();
    assert_eq!(lift_error.kind, LiftErrorKind::Unimplemented);
    assert_eq!(
        lift_error.message,
        "Instruction not implemented in pcode:\n r0x00001003: WEIRD"
    );

    assert_eq!(
        (instructions[3].length, instructions[3].flow_length),
        (4, 8),
        "delay slot"
    );

    let errors: Vec<_> = dump.errors().collect();
    assert_eq!(errors.len(), 2);
    assert_eq!(
        (errors[0].address, errors[0].kind),
        (0x1002, DumpErrorKind::BadData)
    );
    assert_eq!(errors[0].bytes, [0x06]);
    assert_eq!(errors[1].kind, DumpErrorKind::Truncated);
}

#[test]
fn empty_input_is_a_valid_listing() {
    let dump = parse_dump("H\t1\tToy:BE:32:default\tram\t0x0\t0\nT\t0\t0\n").unwrap();
    assert_eq!(dump.records, []);
}

#[test]
fn unknown_error_kinds_are_kept_as_other() {
    let text = "H\t1\tl\tram\t0x0\t1\nE\t0x0\t1\t00\tnovel\tmsg\nT\t0\t1\n";
    assert_eq!(
        parse_dump(text).unwrap().errors().next().unwrap().kind,
        DumpErrorKind::Other
    );
    let text = "H\t1\tl\tram\t0x0\t1\nI\t0x0\t1\t1\t00\tm\t\nU\tnovel\tmsg\nT\t1\t1\n";
    let dump = parse_dump(text).unwrap();
    let kind = dump
        .instructions()
        .next()
        .unwrap()
        .lift_error
        .as_ref()
        .unwrap()
        .kind;
    assert_eq!(kind, LiftErrorKind::Other);
}

#[test]
fn malformed_listings_are_rejected_with_the_line() {
    let header = "H\t1\tl\tram\t0x0\t4\n";
    let cases: &[(&str, &str)] = &[
        ("", "does not start with an H record"),
        ("I\t0x0\t1\t1\t00\tm\t\n", "does not start with an H record"),
        (
            "H\t1\tl\tram\n",
            "line 1: H record has 4 fields, expected 6",
        ),
        ("H\t2\tl\tram\t0x0\t4\nT\t0\t0\n", "format version 2"),
        (
            "H\t1\tl\tram\t16\t4\nT\t0\t0\n",
            "line 1: bad base address: \"16\"",
        ),
        (
            "{H}T\t0\t0\nI\t0x0\t1\t1\t00\tm\t\n",
            "line 3: text after the T record",
        ),
        ("{H}", "no T record"),
        ("{H}I\t0x0\t1\t1\t00\tm\t\n", "no T record"),
        (
            "{H}T\t1\t0\n",
            "T record counts 1 instructions and 0 errors, but the listing has 0 and 0",
        ),
        (
            "{H}P\tCOPY\t-\nT\t0\t0\n",
            "line 2: P record does not follow an instruction",
        ),
        (
            "{H}E\t0x0\t1\t00\tbad-data\tm\nP\tCOPY\t-\nT\t0\t1\n",
            "line 3: P record does not follow",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\t\nU\tunimplemented\tm\nP\tCOPY\t-\nT\t1\t1\n",
            "line 4: P record",
        ),
        (
            "{H}U\tunimplemented\tm\nT\t0\t1\n",
            "line 2: U record does not follow an instruction",
        ),
        ("{H}Q\t1\nT\t0\t0\n", "line 2: unknown record \"Q\""),
        ("{H}\nT\t0\t0\n", "line 2: unknown record \"\""),
        (
            "{H}I\t0x0\t1\t1\t00\tm\nT\t1\t0\n",
            "line 2: I record has 6 fields, expected 7",
        ),
        (
            "{H}I\t0\t1\t1\t00\tm\t\nT\t1\t0\n",
            "line 2: bad address: \"0\"",
        ),
        (
            "{H}I\t0x0\t+1\t1\t00\tm\t\nT\t1\t0\n",
            "line 2: bad length: \"+1\"",
        ),
        (
            "{H}I\t0x0\t1\t1\t0\tm\t\nT\t1\t0\n",
            "line 2: bad bytes: \"0\"",
        ),
        (
            "{H}I\t0x0\t1\t1\t0G\tm\t\nT\t1\t0\n",
            "line 2: bad bytes: \"0G\"",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\\q\t\nT\t1\t0\n",
            "line 2: bad mnemonic",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\t\nP\tCOPY\nT\t1\t0\n",
            "line 3: P record has 2 fields",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\t\nP\tCOPY\t-\t(ram,0x0)\nT\t1\t0\n",
            "line 3: bad varnode: \"(ram,0x0)\"",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\t\nP\tCOPY\t-\tram,0x0,1\nT\t1\t0\n",
            "line 3: bad varnode",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\t\nP\tCOPY\t-\t(ram,0,1)\nT\t1\t0\n",
            "line 3: bad varnode",
        ),
        (
            "{H}I\t0x0\t1\t1\t00\tm\t\nP\tCOPY\t-\t(,0x0,1)\nT\t1\t0\n",
            "line 3: bad varnode",
        ),
        ("{H}T\t0\n", "line 2: T record has 2 fields, expected 3"),
        (
            "{H}E\t0x0\t1\t00\tbad-data\nT\t0\t1\n",
            "line 2: E record has 5 fields, expected 6",
        ),
    ];
    for (template, expected) in cases {
        let text = template.replace("{H}", header);
        let error = parse_dump(&text).unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "{text:?}\n  gave: {error}\n  wanted: {expected}"
        );
    }
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
        let _ = parse_dump(&text);
    }

    #[test]
    fn arbitrary_records_never_panic(
        body in "([HIPUET]\t([0-9a-fx(),\\\\-]{0,12}\t?){0,8}\n){0,8}"
    ) {
        let _ = parse_dump(&format!("H\t1\tl\tram\t0x0\t4\n{body}"));
    }

    #[test]
    fn escaped_text_round_trips(text in "[a-z\\\\\t\n\r ,()]{0,24}") {
        let escaped: String = text.chars().map(|c| match c {
            '\\' => "\\\\".to_owned(),
            '\t' => "\\t".to_owned(),
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            other => other.to_string(),
        }).collect();
        prop_assert!(!escaped.contains(['\t', '\n', '\r']));
        prop_assert_eq!(unescape(1, "text", &escaped).unwrap(), text);
    }
}
