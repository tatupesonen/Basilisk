//! Ports of Ghidra's Java prototype-model tests (`ghidra.program.model.lang`
//! `X64PrototypeModelTest`, `X64WinPrototypeModelTest`,
//! `X64GoPrototypeModelTest`, `AArch64ProtoModelTest`,
//! `MipsPrototypeModelTest`, `PowerPCPrototypeModelTest`,
//! `Sparc32ProtoModelTest`, `Sparc64ProtoModelTest`, `VarargsStorageTest`;
//! 13 tests) against the real `.cspec` files, through the C++ model (which
//! is authoritative). C type names are mapped through the file's data
//! organisation as `AbstractProtoModelTest` does. Needs the spec root
//! (kind G). Rows where the C++ model answers differently from the Java
//! expectation are listed in `EXCEPTIONS` with both values.

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
mod oracle_common;

use bk_core::{SpaceManager, SpaceType, VarnodeData};
use bk_cspec::CompilerSpec;
use bk_cspec::proto::{ParameterPieces, PieceFlags, PrototypePieces};
use bk_cspec::types::ParamTypes;
use common::testtypes::TestTypes;
use common::{cparse, parse_store};

/// (pair, model, signature, Java expectation, C++ result): rows where the
/// C++ model differs from the Java test. None found.
const EXCEPTIONS: &[(&str, &str, &str, &str, &str)] = &[];

struct Env {
    pair: String,
    spec: CompilerSpec,
    m: SpaceManager,
    types: TestTypes,
}

impl Env {
    fn new(pair: &str) -> Option<Self> {
        let ghidra = bk_testkit::require_ghidra()?;
        let (spec, m, types) = oracle_common::arch(&ghidra, pair);
        Some(Self {
            pair: pair.to_owned(),
            spec,
            m,
            types,
        })
    }

    fn parse_structure(&mut self, name: &str, body: &str) {
        cparse::java_structure(&mut self.types, name, body);
    }

    fn assign(&mut self, model: &str, proto: &PrototypePieces) -> Vec<ParameterPieces> {
        let mut res = Vec::new();
        self.spec
            .model_by_name(model)
            .unwrap()
            .assign_parameter_storage(&self.m, &mut self.types, proto, &mut res, true)
            .unwrap();
        res
    }

    /// The pieces of a piece's storage: the join's pieces, or itself.
    fn storage(&self, p: &ParameterPieces) -> Vec<VarnodeData> {
        if p.addr.is_invalid() {
            return Vec::new();
        }
        let is_join = self
            .m
            .space_of(p.addr)
            .is_some_and(|s| s.space_type() == SpaceType::Join);
        if is_join {
            let rec = self.m.find_join(p.addr.offset()).unwrap();
            return rec.pieces().to_vec();
        }
        vec![VarnodeData::from_address(
            p.addr,
            self.types.size(p.ty) as u32,
        )]
    }

    /// `AbstractProtoModelTest.comparePiece` for one expected entry.
    fn matches(&self, want: &str, p: &ParameterPieces) -> bool {
        let want = want.trim();
        if want == "void" {
            return p.addr.is_invalid();
        }
        let expected: Vec<VarnodeData> = match want.strip_prefix("join ") {
            Some(rest) => rest.split(' ').map(|s| java_store(&self.m, s)).collect(),
            None => vec![java_store(&self.m, want)],
        };
        self.storage(p) == expected
    }

    fn test(&mut self, model: &str, sig: &str, stores: &str) {
        let proto = cparse::proto(&mut self.types, model, sig);
        let res = self.assign(model, &proto);
        let want: Vec<&str> = stores.split(',').collect();
        let ok = want.len() == res.len() && want.iter().zip(&res).all(|(w, p)| self.matches(w, p));
        if ok {
            return;
        }
        let got: Vec<String> = res
            .iter()
            .map(|p| {
                format!(
                    "{:?}",
                    self.storage(p)
                        .iter()
                        .map(|v| (v.space(), v.offset, v.size))
                        .collect::<Vec<_>>()
                )
            })
            .collect();
        let excepted = EXCEPTIONS
            .iter()
            .any(|e| e.0 == self.pair && e.1 == model && e.2 == sig);
        assert!(
            excepted,
            "{} {model}: {sig}\n  want {stores}\n  got  {}",
            self.pair,
            got.join(", ")
        );
    }
}

/// `AbstractProtoModelTest.parseStore`: like Ghidra's C++ one, but a sized
/// register is moved by the language's endianness and a `pad` is a
/// constant of that size.
fn java_store(m: &SpaceManager, name: &str) -> VarnodeData {
    parse_store(m, name).unwrap()
}

#[test]
fn x64_prototype_model_std_call() {
    let Some(mut e) = Env::new("x86:LE:64:default:gcc") else {
        return;
    };
    let m = "__stdcall";
    e.test(m, "void func(int a,int b)", "void,EDI,ESI");
    e.test(m, "void func(float,float)", "void,XMM0:4,XMM1:4");
    e.test(m, "void func(short a,int b,char c)", "void,DI,ESI,DX:1");
    e.test(m, "void func(long,long)", "void,RDI,RSI");
    e.test(m, "void func(double,double)", "void,XMM0:8,XMM1:8");
    e.test(
        m,
        "void func(int,float,int,float)",
        "void,EDI,XMM0:4,ESI,XMM1:4",
    );
    e.test(
        m,
        "void func(float,int,float,int)",
        "void,XMM0:4,EDI,XMM1:4,ESI",
    );
    e.test(
        m,
        "void func(int,double,double,int)",
        "void,EDI,XMM0:8,XMM1:8,ESI",
    );
    e.test(
        m,
        "void func(double,long,long,double)",
        "void,XMM0:8,RDI,RSI,XMM1:8",
    );
    e.test(m, "void func(long double)", "void,stack8:10");
    e.test(
        m,
        "void func(float,long double,float)",
        "void,XMM0:4,stack8:10,XMM1:4",
    );
    e.parse_structure("intfloatpair", "int,float");
    e.test(m, "void func(intfloatpair)", "void,RDI");
    e.parse_structure("longfloatpair", "long,float");
    e.test(
        m,
        "void func(int,longfloatpair)",
        "void,EDI,join XMM0:8 RSI",
    );
    e.parse_structure("longdoublepair", "long,double");
    e.test(
        m,
        "void func(int,longdoublepair)",
        "void,EDI,join XMM0:8 RSI",
    );
    e.parse_structure("intdoublepair", "int,double");
    e.test(
        m,
        "void func(int,intdoublepair)",
        "void,EDI,join XMM0:8 RSI",
    );
    e.parse_structure("floatintpair", "float,int");
    e.test(m, "void func(int,floatintpair)", "void,EDI,RSI");
    e.parse_structure("doubleintpair", "double,int");
    e.test(
        m,
        "void func(int,doubleintpair)",
        "void,EDI,join RSI XMM0:8",
    );
    e.parse_structure("intintfloat", "int,int,float");
    e.test(m, "void func(int,intintfloat)", "void,EDI,join XMM0:4 RSI");
    e.parse_structure("intintfloatfloat", "int,int,float,float");
    e.test(
        m,
        "void func(int,intintfloatfloat)",
        "void,EDI,join XMM0:8 RSI",
    );
    e.parse_structure("intfloatfloatint", "int,float,float,int");
    e.test(
        m,
        "void func(int,intfloatfloatint)",
        "void,EDI,join RDX RSI",
    );
    e.parse_structure("intfloatfloat", "int,float,float");
    e.test(
        m,
        "void func(int,intfloatfloat)",
        "void,EDI,join XMM0:4 RSI",
    );
    e.parse_structure("floatfloatpair", "float,float");
    e.test(m, "void func(int,floatfloatpair)", "void,EDI,XMM0:8");
    e.parse_structure("doublefloatpair", "double,float");
    e.test(
        m,
        "void func(int,doublefloatpair)",
        "void,EDI,join XMM1:8 XMM0:8",
    );
    e.parse_structure("floatfloatfloat", "float,float,float");
    e.test(
        m,
        "void func(floatfloatfloat,long)",
        "void,join XMM1:4 XMM0:8,RDI",
    );
    e.parse_structure("intintintint", "int,int,int,int");
    e.test(m, "void func(intintintint)", "void,join RSI RDI");
    e.test(m, "void func(int,intintintint)", "void,EDI,join RDX RSI");
    e.parse_structure("intintintintint", "int,int,int,int,int");
    e.test(m, "void func(intintintintint)", "void,stack8:20");
    e.test(
        m,
        "void func(float,float,float,float,float,float,float,float,longfloatpair)",
        "void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,stack8:16",
    );
    e.test(m, "void func(undefined4,undefined8)", "void,EDI,RSI");
    e.test(m, "intintintint func(void)", "join RDX RAX");
    e.test(m, "floatintpair func(void)", "RAX");
    e.test(m, "longfloatpair func(void)", "join XMM0:8 RAX");
    e.test(m, "longdoublepair func(void)", "join XMM0:8 RAX");
    e.test(m, "doubleintpair func(void)", "join RAX XMM0:8");
    e.test(m, "floatfloatfloat func(void)", "join XMM1:4 XMM0:8");
    e.parse_structure("doubledoublepair", "double,double");
    e.test(m, "doubledoublepair func(void)", "join XMM1:8 XMM0:8");
    e.test(m, "floatfloatpair func(void)", "XMM0:8");
    e.test(m, "intintintintint func(void)", "RAX,RDI");
    e.parse_structure("doubleintintint", "double,int,int,int");
    e.test(m, "doubleintintint func(void)", "RAX,RDI");
}

fn this_call(pair: &str, hidden: usize, this: usize) {
    let Some(mut e) = Env::new(pair) else { return };
    e.parse_structure("bigstruct", "int,int,int,int,int");
    let proto = cparse::proto(&mut e.types, "__thiscall", "bigstruct func(int *,int)");
    let res = e.assign("__thiscall", &proto);
    assert_eq!(res.len(), 4);
    assert!(res[hidden].flags.contains(PieceFlags::HIDDENRETPARM));
    assert!(res[this].flags.contains(PieceFlags::ISTHIS));
}

#[test]
fn x64_prototype_model_this_call() {
    this_call("x86:LE:64:default:gcc", 1, 2);
}

#[test]
fn x64_win_prototype_model_this_call() {
    this_call("x86:LE:64:default:windows", 2, 1);
}

#[test]
fn x64_go_prototype_model_abi_internal() {
    let Some(mut e) = Env::new("x86:LE:64:default:golang") else {
        return;
    };
    let m = "abi-internal";
    e.test(m, "void func(short a,int b,char c)", "void,AX,RBX,CL");
    e.test(m, "void func(float a,float b)", "void,XMM0:4,XMM1:4");
    e.test(m, "void func(float a,double c)", "void,XMM0:4,XMM1:8");
    e.test(
        m,
        "void func(int a,int b,int c,int d,int e,float f,float g,int h,int i,int j,int k,int l)",
        "void,RAX,RBX,RCX,RDI,RSI,XMM0:4,XMM1:4,R8,R9,R10,R11,stack8:8",
    );
    e.test(
        m,
        "void func(float a,float b,float c,float d,float e,float f,float g,float h,float i,float j,float k,float l,float m,float n,float o,float p)",
        "void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,XMM8:4,XMM9:4,XMM10:4,XMM11:4,XMM12:4,XMM13:4,XMM14:4,stack8:4",
    );
    e.test(
        m,
        "void func(int a,int[3] b,int c)",
        "void,RAX,stack8:24,RBX",
    );
    e.parse_structure("Person", "bool,int32_t");
    e.parse_structure("Myriad", "int,bool,Person,float");
    e.test(m, "void func(Person a)", "void,join EBX pad:3 AL");
    e.test(
        m,
        "void func(bool a,Myriad b)",
        "void,AL,join XMM0:4 ESI pad:3 DIL pad:3 CL RBX",
    );
    e.test(m, "Person func(void)", "join EBX pad:3 AL");
    e.test(
        m,
        "double[5] func(int a,int[10] b)",
        "stack58:40,RAX,stack8:80",
    );
    e.test(
        m,
        "char[5] func(char[3] a,char[7] b,int c)",
        "stack18:5,stack8:3,stackb:7,RAX",
    );
    e.test(
        m,
        "void func(float a,int[1] b,int[2] c)",
        "void,XMM0:4,RAX,stack8:16",
    );
}

#[test]
fn aarch64_proto_model_std_call() {
    let Some(mut e) = Env::new("AARCH64:LE:64:v8A:default") else {
        return;
    };
    let m = "__cdecl";
    e.test(m, "void func(short a,int b,char c)", "void,w0:2,w1,w2:1");
    e.test(m, "void func(int, int)", "void,w0,w1");
    e.test(m, "void func(long,long)", "void,x0,x1");
    e.test(m, "void func(float,float)", "void,s0,s1");
    e.test(m, "void func(double,double)", "void,d0,d1");
    e.test(m, "void func(int,float,int,float)", "void,w0,s0,w1,s1");
    e.test(m, "void func(float,int,float,int)", "void,s0,w0,s1,w1");
    e.test(m, "void func(int,double,double,int)", "void,w0,d0,d1,w1");
    e.test(m, "void func(double,long,long,double)", "void,d0,x0,x1,d1");
    e.test(m, "void func(float16)", "void,q0");
    e.test(m, "void func(float,float16)", "void,s0,q1");
    e.test(
        m,
        "void func(int,int,int,int,int,int,int,int,int,int)",
        "void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,stack8:4",
    );
    e.test(
        m,
        "void func(float,float,float,float,float,float,float,float,float,float)",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack8:4",
    );
    e.test(
        m,
        "void func(float,float,float,float,float,float,float,float,float16)",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:16",
    );
    e.test(
        m,
        "void func(float,float,float,float,float,float,float,float,float,float16)",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack10:16",
    );
    e.test(
        m,
        "void func(int,int,int,int,int,int,int,int,int,float)",
        "void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,s0",
    );
    e.test(
        m,
        "void func(float,float,float,float,float,float,float,float,float,int)",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,w0",
    );
    e.parse_structure("intpair", "int,int");
    e.test(m, "void func(intpair)", "void,x0");
    e.parse_structure("longpair", "long,long");
    e.test(m, "void func(longpair)", "void,join x1 x0");
    e.parse_structure("longquad", "long,long,long,long");
    e.test(m, "void func(longquad)", "void,x0");
    e.parse_structure("floatdouble", "float,double");
    e.test(m, "void func(floatdouble)", "void,join x1 x0");
    e.parse_structure("intfloat", "int,float");
    e.test(m, "void func(intfloat)", "void,x0");
    e.parse_structure("longdoublestruct", "long,double");
    e.test(m, "void func(longdoublestruct)", "void,join x1 x0");
    e.test(m, "int func()", "w0");
    e.test(m, "float func()", "s0");
    e.test(m, "double func()", "d0");
    e.test(m, "intpair func()", "x0");
    e.test(m, "longpair func()", "join x1 x0");
    e.test(m, "longquad func()", "void,x8");
    e.parse_structure("floatpair", "float,float");
    e.test(m, "void func(floatpair)", "void,join s1 s0");
    e.parse_structure("floatpairpair", "floatpair,floatpair");
    e.test(m, "void func(floatpairpair)", "void,join s3 s2 s1 s0");
    e.parse_structure("doublequad", "double,double,double,double");
    e.test(m, "void func(doublequad)", "void,join d3 d2 d1 d0");
}

#[test]
fn mips_prototype_model_std_call() {
    let Some(mut e) = Env::new("MIPS:BE:32:default:default") else {
        return;
    };
    let m = "__stdcall";
    for (sig, st) in [
        ("void func(short a,int b,char c)", "void,a0:2,a1,a2:1"),
        ("void func(double a,double b)", "void,f12_13,f14_15"),
        ("void func(float a,float b)", "void,f12,f14"),
        ("void func(float a,double b)", "void,f12,f14_15"),
        ("void func(double a,float b)", "void,f12_13,f14"),
        ("void func(int a,int b,int c,int d)", "void,a0,a1,a2,a3"),
        (
            "void func(double a,int b,double c)",
            "void,f12_13,a2,stack10:8",
        ),
        ("void func(double a,int b,int c)", "void,f12_13,a2,a3"),
        ("void func(float a,int b,int c)", "void,f12,a1,a2"),
        (
            "void func(int a,int b,int c,double d)",
            "void,a0,a1,a2,stack10:8",
        ),
        ("void func(int a,int b,int c,float d)", "void,a0,a1,a2,a3"),
        ("void func(int a,int b,double c)", "void,a0,a1,join a2 a3"),
        ("void func(int a,double b)", "void,a0,join a2 a3"),
        (
            "void func(float a,float b,float c,float d)",
            "void,f12,f14,a2,a3",
        ),
        (
            "void func(float a,int b,float c,int d)",
            "void,f12,a1,a2,a3",
        ),
        ("void func(double a,float b,float c)", "void,f12_13,f14,a3"),
        (
            "void func(float a,float b,double c)",
            "void,f12,f14,join a2 a3",
        ),
        ("void func(int a,float b,int c,float d)", "void,a0,a1,a2,a3"),
        ("void func(int a,float b,int c,int d)", "void,a0,a1,a2,a3"),
        ("void func(int a,int b,float c,int d)", "void,a0,a1,a2,a3"),
        ("int func(void)", "v0"),
        ("float func(void)", "f0"),
        ("double func(void)", "f0_1"),
    ] {
        e.test(m, sig, st);
    }
    e.parse_structure("onefieldstruct", "int");
    e.parse_structure("twofieldstruct", "int,int");
    e.test(m, "onefieldstruct func(int a)", "v0,a0,a1");
    e.test(m, "twofieldstruct func(int a)", "v0,a0,a1");
    e.test(m, "void func(twofieldstruct a)", "void,join a0 a1");
    e.parse_structure("intdouble", "int,double");
    e.test(m, "void func(intdouble a)", "void,join a0 a1 a2 a3");
}

#[test]
fn powerpc_prototype_model_std_call() {
    let Some(mut e) = Env::new("PowerPC:BE:64:default:default") else {
        return;
    };
    let m = "__stdcall";
    e.test(
        m,
        "void func(int a,float b,double c)",
        "void,r3:4,join f1,f2",
    );
    e.test(m, "void func(double a,long b,double c)", "void,f1,r4,f2");
    e.parse_structure("sparm", "int,double");
    e.test(
        m,
        "void func(int c,double ff,int d,float16 ld,sparm s,double gg,sparm t,int e,double hh)",
        "void,r3:4,f1,r5:4,join f2 f3,join r8 r9,f4,stack70:16,stack84:4,f5",
    );
}

#[test]
fn sparc32_proto_model_std_call() {
    let Some(mut e) = Env::new("sparc:BE:32:default:default") else {
        return;
    };
    let m = "__stdcall";
    e.test(
        m,
        "void func(int,long long,int,long long,int,int)",
        "void,o0,join o1 o2,o3,o4_5,stack5c:4,stack60:4",
    );
    e.test(
        m,
        "void func(float,double,float,double,float,float)",
        "void,o0,join o1 o2,o3,o4_5,stack5c:4,stack60:4",
    );
    e.test(
        m,
        "void func(int,double,long long,float,float)",
        "void,o0,join o1 o2,join o3 o4,o5,stack5c:4",
    );
    e.test(m, "void func(int,long double,float)", "void,o0,o1,o2");
    e.parse_structure("intpair", "int,int");
    e.test(m, "void func(int,intpair,double)", "void,o0,o1,o2_3");
    e.test(m, "int func()", "o0");
    e.test(m, "long long func()", "o0_1");
    e.test(m, "float func()", "fs0");
    e.test(m, "double func()", "fd0");
    e.test(m, "long double func(int,int)", "o0,stack40:4,o0,o1");
    e.test(m, "intpair func(long long)", "o0,stack40:4,o0_1");
}

#[test]
fn sparc64_proto_model_std_call() {
    let Some(mut e) = Env::new("sparc:BE:64:default:default") else {
        return;
    };
    let m = "__stdcall";
    e.test(
        m,
        "void func(int,long long,int,long long,int,int,int)",
        "void,o0:4,o1,o2:4,o3,o4:4,o5:4,stack8b3:4",
    );
    e.test(m, "void func(float,float,char)", "void,fs1,fs3,o2:1");
    e.test(m, "void func(double,double)", "void,fd0,fd2");
    e.test(m, "void func(long double,int)", "void,fq0,o4:4");
    e.test(
        m,
        "void func(int,double,float,long long)",
        "void,o0:4,fd2,fs5,o3",
    );
    e.test(
        m,
        "void func(float,double,float,double,float,float)",
        "void,fs1,fd2,fs5,fd6,fs9,fs11",
    );
    e.test(
        m,
        "void func(int,double,long long,float,float)",
        "void,o0:4,fd2,o2,fd6:4,fs9",
    );
    e.test(
        m,
        "void func(int,double,long long,float,float)",
        "void,o0:4,fd2,o2,fs7,fs9",
    );
    e.test(m, "char func()", "o0:1");
    e.test(m, "int func()", "o0:4");
    e.test(m, "long long func()", "o0");
    e.test(m, "float func()", "fs1");
    e.test(m, "double func()", "fd0");
    e.parse_structure("intpair", "int,int");
    e.test(m, "void func(int,intpair,double)", "void,o0:4,o1,fd4");
    e.test(m, "intpair func(long long)", "o0,stack7ef:8,o0");
    e.test(m, "long double func(int,int)", "fq0,o0:4,o1:4");
}

/// `VarargsStorageTest`: `getStorageLocations` with the last parameter the
/// last fixed argument of a variadic call (`firstVarArgSlot` = count).
fn varargs(pair: &str, ty: &str, fixed: [&str; 3], variadic: [Option<&str>; 3]) {
    let Some(mut e) = Env::new(pair) else { return };
    let t = e.types.get(ty);
    let void = e.types.get("void");
    for (is_var, expect) in [(false, fixed.map(Some)), (true, variadic)] {
        let mut proto = PrototypePieces::new(void).with_inputs(vec![t, t, t]);
        if is_var {
            proto.first_vararg = 3;
        }
        let res = e.assign("__stdcall", &proto);
        for (i, want) in expect.iter().enumerate() {
            let p = &res[i + 1];
            match want {
                Some(reg) => {
                    let r = e.m.registers().register(reg).unwrap();
                    assert_eq!(p.addr, r.addr(), "{pair} {reg} varargs={is_var}");
                }
                None => assert_eq!(
                    e.m.space_of(p.addr).map(bk_core::Space::space_type),
                    Some(SpaceType::Spacebase),
                    "{pair} param {i} on the stack, varargs={is_var}"
                ),
            }
        }
    }
}

#[test]
fn varargs_storage_msp430_stdcall() {
    varargs(
        "TI_MSP430:LE:16:default:default",
        "unsigned int",
        ["R12", "R13", "R14"],
        [Some("R12"), Some("R13"), None],
    );
}

#[test]
fn varargs_storage_avr8_stdcall() {
    varargs(
        "avr8:LE:16:default:gcc",
        "unsigned int",
        ["R25R24", "R23R22", "R21R20"],
        [None, None, None],
    );
}

#[test]
fn varargs_storage_x64_stdcall() {
    varargs(
        "x86:LE:64:default:gcc",
        "unsigned long",
        ["RDI", "RSI", "RDX"],
        [Some("RDI"), Some("RSI"), Some("RDX")],
    );
}
