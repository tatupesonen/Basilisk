//! Golden snapshots of the syntax tree (`insta`, under `tests/golden/`):
//! hand-written fragments for each construct of the spec's section 4, and
//! the `Toy` processor shipped with Ghidra. Each snapshot holds the source
//! and the tree rendered by `ast::dump` (S-expressions; `ws` is a display
//! whitespace piece, `q"…"` a quoted string, `"…"` literal print text).
//!
//! Update with `INSTA_UPDATE=always` and review the diff before committing.

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

mod common;

use bk_sleigh_syntax::ast::dump;
use bk_sleigh_syntax::{Defines, FsLoader, parse_file, parse_str};

fn golden(name: &str, source: &str) {
    let parsed = parse_str("fragment.slaspec", source, &Defines::new());
    let tree = dump::spec(&parsed.spec, &parsed.names, Some(&parsed.sources));
    let mut text = format!("--- source\n{source}\n--- tree\n{tree}");
    if !parsed.diagnostics.is_empty() {
        text.push_str("--- diagnostics\n");
        for line in parsed.rendered_diagnostics() {
            text.push_str(&line);
            text.push('\n');
        }
    }
    insta::with_settings!({ snapshot_path => "golden", prepend_module_to_snapshot => false }, {
        insta::assert_snapshot!(name, text);
    });
}

#[test]
fn definitions() {
    golden(
        "definitions",
        r#"define endian=little;
define alignment=2;
define space ram type=ram_space size=4 wordsize=2 default;
define space register type=register_space size=4;
define register offset=0x100 size=4 [ r0 _ r2 sp ];
define register offset=0 size=1 contextreg;
define bitrange zf=flags[0,1] cf=flags[1,1] lo=r0[0,16];
define token instr(16) endian=big op=(10,15) rd=(0,4) signed hex imm=(0,7) signed dec;
define token data8(8) d8=(0,7);
define context contextreg mode=(0,0) noflow phase=(1,2) signed;
define pcodeop sync;
define pcodeop [ a b ];
attach variables [ rd ] [ r0 r1 _ sp ];
attach names rd [ "a" b _ "x y" ];
attach values [ imm d8 ] [ -1 0x2 _ 0b11 7 ];
attach values imm 5;
"#,
    );
}

#[test]
fn keywords_as_names_in_definitions() {
    golden(
        "keywords_as_names",
        r"define endian=big;
define space token type=ram_space size=4;
define token offset=0 size=4 [ size type default ];
define token instr(8) is=(0,3) unimpl=(4,7);
define context ctx signed=(0,0) hex=(1,1) noflow=(2,2) noflow;
define pcodeop export;
",
    );
}

#[test]
fn display_sections() {
    golden(
        "display",
        r#"define endian=big;
:mov^"."^cc rd, [rs + imm] is epsilon unimpl
:ADD   rd,rs	is epsilon unimpl
:  lead is epsilon unimpl
:^x is epsilon unimpl
:a, is epsilon unimpl
:"" is epsilon unimpl
:p #1, @x $y ?z !w ~v *u &t |s =r -q +p /o %n <m >l {k} is epsilon unimpl
:n 0x10 0b11 12 is epsilon unimpl
:x.y_z .w is epsilon unimpl
:multi
  line is epsilon unimpl
tab:	t is epsilon unimpl
"#,
    );
}

#[test]
fn display_errors() {
    golden(
        "display_errors",
        r#"define endian=big;
:a _ b is epsilon unimpl
:a 0n12 is epsilon unimpl
:a with is epsilon unimpl
:a "unterminated is epsilon unimpl
:b is epsilon unimpl
"#,
    );
}

#[test]
fn with_blocks() {
    golden(
        "with",
        r"define endian=big;
with : mode=1 [ phase=1; ] {
  :a is rd unimpl
  with sub : op=1 & rd {
    :b is rs unimpl
    other: c is epsilon unimpl
    with : [ phase=2; ] {
      :d is epsilon unimpl
    }
  }
  define pcodeop inside;
  macro m() { }
}
with tbl : { tbl: e is epsilon unimpl }
",
    );
}

#[test]
fn macros() {
    golden(
        "macros",
        r"define endian=big;
macro none() { }
macro one(a) { a = a + 1; }
macro two(dst, src) {
  local t:4 = src;
  dst = zext(t);
  <done>
}
",
    );
}

#[test]
fn patterns_and_context_blocks() {
    golden(
        "patterns",
        r"define endian=big;
:a is op=1 & rd=2 | op=3 ; imm unimpl
:b is (op=1 ; rd) ... & imm < 4 unimpl
:c is ... imm >= 0x10 & op != 0b1 unimpl
:d is op=1 [ mode = 1; phase = (rd << 2) | 1 + 2 * 3; globalset(inst_next, mode); ] unimpl
:e is imm=-1 & rd = (imm $and 0xf) $or ~op unimpl
:f is epsilon [ disp = inst_start + (imm << 2); ] unimpl
",
    );
}

#[test]
fn semantic_bodies() {
    golden(
        "semantics",
        r"define endian=big;
:a is epsilon {
  local t:4 = *[ram]:4 (r0 + 4);
  *:2 r1 = t:2;
  r2[0,8] = &:4 r3;
  if (r0 s< 0) goto <neg>;
  call [r1];
  goto 0x1000[ram];
  r0 = zext(r1 f+ r2) >> 3 & ~r4;
  build sub;
  crossbuild inst_next, other;
  sync();
  <neg>
  return [lr];
  export *[ram]:4 r0;
}
:b is epsilon {
  r0 = 1:4;
  <<other>>
  r1 = r2(2);
  <<third>>
}
",
    );
}

#[test]
fn recovery_from_several_errors() {
    golden(
        "recovery",
        r"define endian=big;
define token t(8) a=(0,3) b=(4;
:ok1 is a=1 { r0 = 1; }
:bad is a=1 { r0 = ; r1 = 2; r2 = (3; }
define space ram type=ram_space size=;
:ok2 is b=2 { r0 = 2; }
attach names [ a ] [ ;
:bad2 is & { }
:ok3 is epsilon unimpl
",
    );
}

#[test]
fn toy_processor() {
    let Some(ghidra) = common::ghidra_dir() else {
        return;
    };
    let path = ghidra.join("Ghidra/Processors/Toy/data/languages/toy_be.slaspec");
    let parsed = parse_file(&path, &common::build_defines(), &mut FsLoader);
    assert_eq!(parsed.diagnostics, []);
    let tree = dump::spec(&parsed.spec, &parsed.names, Some(&parsed.sources));
    insta::with_settings!({ snapshot_path => "golden", prepend_module_to_snapshot => false }, {
        insta::assert_snapshot!("toy_be", tree);
    });
}
