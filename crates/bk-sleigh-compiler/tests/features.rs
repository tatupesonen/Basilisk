//! Self-contained checks of each feature of the front half (spec 6.4):
//! small hand-written specifications whose elaboration is an `insta`
//! snapshot — the canonical form (`canon`), the pattern equations, and
//! every template in the XML form of the `.sla` file. These need neither
//! the Ghidra tree nor the reference tools.

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

use std::fmt::Write as _;

use bk_sla::SpaceTable;
use bk_sleigh_compiler::pattern::{ConstraintOp, Equation};
use bk_sleigh_compiler::{Elaborated, Options, canon};

const LITTLE: &str = "define endian=little;\n";
const BIG: &str = "define endian=big;\n";
const COMMON: &str = "\
define alignment=2;
define space ram type=ram_space size=4 wordsize=1 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 r1 _ r3 ];
define register offset=0x40 size=2 [ h0 h1 ];
define register offset=0x80 size=1 [ c0 c1 ];
define register offset=0x100 size=8 [ q0 ];
define token instr(16) op=(8,15) reg=(0,1) imm=(0,7) simm=(0,7) signed low4=(0,3) hi4=(4,7);
define pcodeop sync;
";

fn equation_text(spec: &Elaborated, id: bk_sleigh_compiler::ids::EquationId, out: &mut String) {
    match spec.patterns.get_equation(id) {
        Some(Equation::And(a, b)) => binary(spec, "&", *a, *b, out),
        Some(Equation::Or(a, b)) => binary(spec, "|", *a, *b, out),
        Some(Equation::Cat(a, b)) => binary(spec, ";", *a, *b, out),
        Some(Equation::LeftEllipsis(a)) => {
            out.push_str("(... ");
            equation_text(spec, *a, out);
            out.push(')');
        }
        Some(Equation::RightEllipsis(a)) => {
            out.push('(');
            equation_text(spec, *a, out);
            out.push_str(" ...)");
        }
        Some(Equation::Constraint { op, value, expr }) => {
            let op = match op {
                ConstraintOp::Equal => "=",
                ConstraintOp::NotEqual => "!=",
                ConstraintOp::Less => "<",
                ConstraintOp::LessEqual => "<=",
                ConstraintOp::Greater => ">",
                ConstraintOp::GreaterEqual => ">=",
            };
            let _ = write!(out, "[{value:?} {op} {expr:?}]");
        }
        Some(Equation::Operand(op)) => {
            let symbol = spec.operands[op.slot()].symbol;
            let _ = write!(out, "operand({})", spec.symbol_name(symbol));
        }
        Some(Equation::Unconstrained(e)) => {
            let _ = write!(out, "unconstrained({e:?})");
        }
        None => out.push('?'),
    }
}

fn binary(
    spec: &Elaborated,
    op: &str,
    a: bk_sleigh_compiler::ids::EquationId,
    b: bk_sleigh_compiler::ids::EquationId,
    out: &mut String,
) {
    out.push('(');
    equation_text(spec, a, out);
    let _ = write!(out, " {op} ");
    equation_text(spec, b, out);
    out.push(')');
}

/// With the reference compiler present, compiles `source` with it and
/// requires the canonical forms to be equal.
fn compare_with_ghidra(name: &str, source: &str, ours: Option<&Elaborated>) {
    let Some(reference) =
        bk_testkit::reference_dir().filter(|r| r.tool(bk_testkit::Tool::Sleigh).is_some())
    else {
        eprintln!("SKIPPED (Ghidra comparison): reference sleigh compiler not found");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bk-features-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let slaspec = dir.join("test.slaspec");
    let sla = dir.join("test.sla");
    std::fs::write(&slaspec, source).unwrap();
    let result = reference.sleigh().compile(&slaspec, &sla);
    let theirs = result
        .ok()
        .map(|_| bk_sla::Sla::read_file(&sla, &bk_sla::Limits::default()).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    match (ours, theirs) {
        (Some(ours), Some(theirs)) => {
            let (diffs, total) =
                canon::diff(&canon::of_elaborated(ours), &canon::of_sla(&theirs), 20);
            let text: Vec<String> = diffs.iter().map(ToString::to_string).collect();
            assert_eq!(total, 0, "{name} differs from Ghidra:\n{}", text.join("\n"));
        }
        (None, None) => {}
        (ours, theirs) => panic!(
            "{name}: basilisk produced {} but Ghidra {}",
            ours.is_some(),
            theirs.is_some()
        ),
    }
}

/// Elaborates `source` and renders everything the snapshot holds.
fn render(name: &str, source: &str, options: Options) -> String {
    let (parsed, outcome) = common::elaborate_text(source, options);
    compare_with_ghidra(name, source, outcome.spec.as_ref());
    let mut out = String::new();
    for d in &parsed.diagnostics {
        let _ = writeln!(out, "parse: {}", d.message);
    }
    for d in &outcome.diagnostics {
        let _ = writeln!(out, "{:?}: {}", d.severity, d.message.trim_end());
    }
    let Some(spec) = outcome.spec else {
        out.push_str("=> no output\n");
        return out;
    };
    for (path, value) in canon::of_elaborated(&spec).iter() {
        let _ = writeln!(out, "{path} = {value}");
    }
    let mut spaces = SpaceTable::new();
    for space in spec.spaces.iter().filter(|s| s.index != 0) {
        spaces.insert(&space.name, space.index);
    }
    for table in &spec.tables {
        for (i, ctor) in table.constructors.iter().enumerate() {
            let c = &spec.constructors[ctor.slot()];
            let name = spec.symbol_name(table.symbol);
            if let Some(eq) = c.equation {
                let mut text = String::new();
                equation_text(&spec, eq, &mut text);
                let _ = writeln!(out, "equation {name}[{i}] = {text}");
            }
            if let Some(main) = &c.main {
                let _ = writeln!(
                    out,
                    "xml {name}[{i}] main:\n{}",
                    main.to_template(None).encode_xml(&spaces)
                );
            }
            for (n, tpl) in c.sections.iter().enumerate() {
                if let Some(tpl) = tpl {
                    let _ = writeln!(
                        out,
                        "xml {name}[{i}] section {n}:\n{}",
                        tpl.to_template(Some(n as u32)).encode_xml(&spaces)
                    );
                }
            }
        }
    }
    out
}

fn spec(endian: &str, body: &str) -> String {
    format!("{endian}{COMMON}{body}")
}

macro_rules! feature {
    ($name:ident, $endian:expr, $body:expr) => {
        feature!($name, $endian, $body, Options::default());
    };
    ($name:ident, $endian:expr, $body:expr, $options:expr) => {
        #[test]
        fn $name() {
            insta::assert_snapshot!(render(stringify!($name), &spec($endian, $body), $options));
        }
    };
}

feature!(
    definitions,
    LITTLE,
    "define bitrange rlo=r0[0,16] rhi=r0[16,16] rbit=r0[3,2];
define token big16(16) endian=big bop=(8,15) bfield=(0,3) signed;
define pcodeop [ fence _ halt ];
:a r0 is op=1 & r0 { rlo = rhi; c0 = rbit; rbit = 1; }
:b bfield is bop=2 & bfield { fence(); r0 = sext(bfield:2); }
"
);
feature!(
    bitranges_big_endian,
    BIG,
    "define bitrange rlo=r0[0,16] rhi=r0[16,16] rbit=r0[3,2];
:a r0 is op=1 & r0 { rlo = rhi; h1 = r0[8,16]; r0[4,8] = h0:1; c0 = q0[60,4]; }
"
);
feature!(
    bitranges_little_endian,
    LITTLE,
    ":a r0 is op=1 & r0 { h0 = r0[8,16]; r0[4,8] = h0:1; c0 = q0[60,4]; h1 = r1(2); }
"
);
feature!(
    context_layout,
    LITTLE,
    "define register offset=0x200 size=4 [ zctx ];
define register offset=0x210 size=8 [ actx ];
define context zctx zf=(0,3) zg=(2,5) zh=(10,10) noflow;
define context actx aa=(0,20) ab=(21,40) ac=(41,41) signed ad=(40,40);
:a r0 is op=1 & r0 & zf=1 [ zh = 1; aa = zg + 1; globalset(inst_next, zh); ] { r0 = 1; }
"
);
feature!(
    attach,
    LITTLE,
    "define register offset=0x200 size=4 [ ctx ];
define context ctx mode=(0,1) sub=(2,3);
attach variables [ reg ] [ r0 r1 r3 r0 ];
attach names [ low4 ] [ a b c d e f g h i j k l m n o _ ];
attach values [ hi4 ] [ 0 -1 2 3 4 5 6 7 8 9 10 11 12 13 14 0x7f ];
attach values [ sub ] [ 10 20 30 40 ];
:a reg, low4, hi4 is op=1 & reg & low4 & hi4 [ mode = 2; ] { reg = hi4; }
:b sub is op=2 & sub { r0 = sub; }
"
);
feature!(
    with_blocks,
    LITTLE,
    "define register offset=0x200 size=4 [ ctx ];
define context ctx mode=(0,1) sub=(2,3);
with outer : op=1 [ mode = 1; ] {
  with : reg=1 [ sub = 2; ] {
    :\"a\" is hi4=7 [ mode = 3; ] { r0 = 1; export r0; }
  }
  with inner : low4=2 {
    :\"b\" is hi4=0 { export r1; }
  }
}
:use outer is op=1 & outer { }
"
);
feature!(
    expressions,
    LITTLE,
    ":a r0 is op=1 & r0 {
  r0 = r1 + 1 - r3 * 2 / r1 % 3 s/ r3 s% 5;
  r0 = (r1 & 3) | (r3 ^ 4) << 1 >> 2 s>> 3;
  c0 = r1 == 1 || r1 != 2 && r1 < 3 ^^ r1 > 4;
  c0 = r1 <= 5 || r1 >= 6 || r1 s< 7 || r1 s> 8 || r1 s<= 9 || r1 s>= 10;
  c0 = r1 f< r3 || r1 f> r3 || r1 f<= r3 || r1 f>= r3 || r1 f== r3 || r1 f!= r3;
  r0 = r1 f+ r3 f- r1 f* r3 f/ r1;
  r0 = -r1; r0 = ~r1; c0 = !c1; r0 = f- r1;
  r0 = zext(h0); r0 = sext(c0); c0 = carry(r0, r1); c0 = scarry(r0, r1); c0 = sborrow(r0, r1);
  c0 = nan(r0); r0 = abs(r1); r0 = sqrt(r1); r0 = ceil(r1); r0 = floor(r1); r0 = round(r1);
  r0 = int2float(r1); q0 = float2float(r1); r0 = trunc(q0);
  r0 = popcount(r1); r0 = lzcount(r1); r0 = newobject(r1); r0 = newobject(r1, r3);
  r0 = cpool(r1, 2, 3); r0 = sync(r1, 4:4); h0 = r0(2); r0 = &r1; h0 = &:2 r1; r0 = 0x10:4;
  r0 = *r1; r0 = *[register]:4 r1; r0 = *:4 r1;
}
"
);
feature!(
    statements,
    LITTLE,
    ":a r0 is op=1 & r0 {
  tmp = r1 + 1;
  local t2:2 = h0;
  local t3;
  t3 = r1;
  t4:4 = r1;
  *[ram]:4 r0 = tmp;
  *r1 = t3;
  sync(r0);
  if (r0 == 0) goto <skip>;
  r0 = t3 + t4;
  <skip>
  if (t2 == 0) goto inst_next;
  goto [r1];
  call [r1];
  call 0x1000;
  goto 0x20[ram];
  return [r0];
}
:b r0 is op=2 & r0 { goto r0; }
:c is op=3 { delayslot(2); goto inst_start; }
"
);
feature!(
    exports_and_builds,
    LITTLE,
    "src: r0 is reg=0 & r0 { export r0; }
src: imm is reg=1 & imm { export *[ram]:4 imm; }
src: is reg=2 { export 0x12:4; }
src: is reg=3 { tmp:4 = r1 + 1; export tmp; }
dst: imm is imm { export *:2 imm; }
:a src, dst is op=1 & src; dst { r0 = src; }
:b src is op=2 & src { build src; r0 = src; }
:c src is op=3 & src unimpl
"
);
feature!(
    sections_and_crossbuild,
    LITTLE,
    ":a r0 is op=1 & r0 { r0 = 1; <<lo>> r1 = 2; <<hi>> local t:4 = r0; r3 = t; }
:b r0 is op=2 & r0 { crossbuild r0, lo; tmp:4 = r0; r1 = tmp; }
"
);
feature!(
    macros,
    LITTLE,
    "macro setflags(res, val) { <done> res = val; if (val == 0) goto <done>; res = res + 1; }
macro low(a) { c0 = a:1; }
macro inner(x) { x = 0; }
macro outer(y) { inner(y); }
:a r0 is op=1 & r0 { <top> setflags(r0, r1); setflags(r1, r0); goto <top>; }
:b r0 is op=2 & r0 { local t:4 = r0; low(t); low(r0); outer(r1); }
"
);
feature!(
    size_propagation,
    LITTLE,
    ":a r0 is op=1 & r0 { local t; local u; u = 5; t = u + 1; r0 = t; }
:b r0 is op=2 & r0 { r0 = (r1 + 1) << 2; c0 = (h0 & 3) == 1; }
"
);
feature!(
    optimiser,
    LITTLE,
    ":a r0 is op=1 & r0 { tmp:4 = r1 + 1; r0 = tmp; }
:b r0 is op=2 & r0 { tmp:4 = r1; r0 = tmp + 1; }
:c r0 is op=3 & r0 { tmp:4 = r1; r1 = 5; r0 = tmp; }
:d r0 is op=4 & r0 { tmp:4 = r1 + 1; r1 = r0; r0 = tmp; }
:e r0 is op=5 & r0 { tmp:4 = r1; sync(); r0 = tmp; }
"
);
feature!(
    truncation_fixup,
    BIG,
    "src: r0 is reg=0 & r0 { export r0; }
src: r1 is reg=1 & r1 { export r1; }
:a src is op=1 & src { h0 = src:2; c0 = src(1); src[8,8] = 1; }
"
);
feature!(
    display,
    LITTLE,
    ":mov^\".w\" r0,\"  \" r1 is op=1 & r0 & r1 & reg=0 { r0 = r1; }
sub: \"[\"^r0^\"]\" is r0 { export r0; }
:ld sub is op=2 & sub { r1 = sub; }
:nop  is op=3 { }
"
);

#[test]
fn snippet_builder_without_a_constructor() {
    use bk_sleigh_compiler::pcode::{
        BuildEnv, DefineError, LabelId, NameRef, SymbolResolver, compile_snippet,
    };
    use bk_sleigh_compiler::spaces::{SpaceInfo, SpaceKind};
    use bk_sleigh_compiler::template::Vn;

    /// A resolver over two registers and one user op, as a `.cspec`
    /// snippet would see a language.
    #[derive(Default)]
    struct Snippet {
        next: u64,
        locals: Vec<(String, Vn)>,
        labels: Vec<(String, LabelId)>,
    }
    impl SymbolResolver for Snippet {
        fn lookup(&self, name: &str) -> NameRef {
            let reg = |off: u64| {
                Vn::new(
                    bk_sla::ConstTpl::Space(3),
                    bk_sla::ConstTpl::Real(off),
                    bk_sla::ConstTpl::Real(4),
                )
            };
            match name {
                "sp" => NameRef::Varnode(reg(0)),
                "lr" => NameRef::Varnode(reg(4)),
                "inst_next" => NameRef::Jump(Vn::new(
                    bk_sla::ConstTpl::Space(0),
                    bk_sla::ConstTpl::Next,
                    bk_sla::ConstTpl::Real(0),
                )),
                "syscall" => NameRef::UserOp(0),
                "ram" => NameRef::Space(4),
                _ => {
                    if let Some((_, vn)) = self.locals.iter().find(|(n, _)| n == name) {
                        return NameRef::Varnode(*vn);
                    }
                    if let Some((_, id)) = self.labels.iter().find(|(n, _)| n == name) {
                        return NameRef::Label(*id);
                    }
                    NameRef::Unknown
                }
            }
        }
        fn location_of(&self, _: &str) -> Option<bk_sleigh_syntax::Span> {
            None
        }
        fn allocate_temp(&mut self) -> u64 {
            let t = 0x1000 + self.next;
            self.next += 0x10;
            t
        }
        fn define_local(
            &mut self,
            name: &str,
            varnode: Vn,
            _: bk_sleigh_syntax::Span,
        ) -> Result<(), DefineError> {
            self.locals.push((name.to_owned(), varnode));
            Ok(())
        }
        fn define_label(
            &mut self,
            name: &str,
            label: LabelId,
            _: bk_sleigh_syntax::Span,
        ) -> Result<(), DefineError> {
            self.labels.push((name.to_owned(), label));
            Ok(())
        }
        fn mark_code_address(&mut self, _: u32) {}
        fn macro_param_is_code(&self, _: u32, _: u32) -> bool {
            false
        }
        fn new_section(&mut self, _: &str, _: bk_sleigh_syntax::Span) -> Result<u32, DefineError> {
            Err(DefineError("no sections in snippets".to_owned()))
        }
    }

    let space = |name: &str, index, kind, size| SpaceInfo {
        name: name.to_owned(),
        index,
        kind,
        is_other: false,
        big_endian: false,
        addr_size: size,
        word_size: 1,
        delay: 0,
        physical: true,
    };
    let env = BuildEnv {
        spaces: vec![
            space("const", 0, SpaceKind::Constant, 8),
            space("unique", 2, SpaceKind::Unique, 4),
            space("register", 3, SpaceKind::Processor, 4),
            space("ram", 4, SpaceKind::Processor, 4),
        ],
        default_space: Some(4),
        enforce_local_key: false,
    };
    let body = bk_sleigh_syntax::parse_semantic_body(
        "local t:4 = sp + 8; *[ram]:4 t = lr; if (lr == 0) goto <out>; syscall(t); <out> sp = t;",
    );
    let mut resolver = Snippet::default();
    let result = compile_snippet(&body, &env, &mut resolver);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    let tpl = result.template.unwrap();
    let mut spaces = SpaceTable::new();
    spaces.insert("unique", 2);
    spaces.insert("register", 3);
    spaces.insert("ram", 4);
    insta::assert_snapshot!(tpl.to_template(None).encode_xml(&spaces));

    let bad = bk_sleigh_syntax::parse_semantic_body("x = nosuch; goto <never>;");
    let result = compile_snippet(&bad, &env, &mut Snippet::default());
    assert!(result.template.is_none());
    assert_eq!(result.diagnostics.len(), 1, "{:?}", result.diagnostics);
    assert_eq!(
        result.diagnostics[0].message,
        "Unknown varnode parameter: nosuch"
    );
}
