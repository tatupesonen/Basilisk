//! Port of Ghidra's `unittests/testparamstore.cc` (5 tests): storage
//! assignment under the real `.cspec` files of x86-64 gcc and golang,
//! PowerPC 64 BE, MIPS 32 BE and AArch64. Needs the spec root (kind G); the
//! spaces and registers come from the checked-in oracle table.

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

use bk_core::SpaceManager;
use bk_cspec::CompilerSpec;
use common::testtypes::TestTypes;
use common::{compare_piece, cparse, parse_store};

struct Env {
    spec: CompilerSpec,
    m: SpaceManager,
    types: TestTypes,
    model: String,
}

impl Env {
    fn new(pair: &str, model: &str) -> Option<Self> {
        let ghidra = bk_testkit::require_ghidra()?;
        let (spec, m, types) = oracle_common::arch(&ghidra, pair);
        Some(Self {
            spec,
            m,
            types,
            model: model.to_owned(),
        })
    }

    fn parse_type(&mut self, text: &str) {
        cparse::structure(&mut self.types, text);
    }

    /// Ghidra's `ParamStoreEnvironment::test`.
    fn test(&mut self, signature: &str, stores: &str) -> bool {
        let model = self.spec.model_by_name(&self.model).unwrap();
        let proto = cparse::proto(&mut self.types, &self.model, signature);
        let mut res = Vec::new();
        model
            .assign_parameter_storage(&self.m, &mut self.types, &proto, &mut res, false)
            .unwrap();
        let want: Vec<_> = stores
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| parse_store(&self.m, s))
            .collect();
        want.len() == res.len()
            && want
                .iter()
                .zip(&res)
                .all(|(w, p)| compare_piece(&self.types, *w, p))
    }
}

macro_rules! check {
    ($env:expr, $sig:expr, $stores:expr) => {
        assert!($env.test($sig, $stores), "{} -> {}", $sig, $stores);
    };
}

#[test]
fn paramstore_x64() {
    let Some(mut e) = Env::new("x86:LE:64:default:gcc", "__stdcall") else { return };
    check!(e, "void func(int4,int4);", "void,EDI,ESI");
    check!(e, "void func(float4,float4);", "void,XMM0:4,XMM1:4");
    check!(e, "void func(int2 a,int4 b,int1 c);", "void,DI,ESI,DX:1");
    check!(e, "void func(int8,int8);", "void,RDI,RSI");
    check!(e, "void func(float8,float8);", "void,XMM0:8,XMM1:8");
    check!(e, "void func(int4,float4,int4,float4);", "void,EDI,XMM0:4,ESI,XMM1:4");
    check!(e, "void func(float4,int4,float4,int4);", "void,XMM0:4,EDI,XMM1:4,ESI");
    check!(e, "void func(int4,float8,float8,int4);", "void,EDI,XMM0:8,XMM1:8,ESI");
    check!(e, "void func(float8,int8,int8,float8);", "void,XMM0:8,RDI,RSI,XMM1:8");
    check!(e, "void func(float10);", "void,stack8:10");
    check!(e, "void func(float4,float10,float4);", "void,XMM0:4,stack8:10,XMM1:4");
    e.parse_type("struct intfloatpair { int4 a; float4 b;};");
    check!(e, "void func(intfloatpair);", "void,RDI");
    e.parse_type("struct longfloatpair { int8 a; float4 b;};");
    check!(e, "void func(int4,longfloatpair);", "void,EDI,join XMM0:8 RSI");
    e.parse_type("struct longdoublepair { int8 a; float8 b;};");
    check!(e, "void func(int4,longdoublepair);", "void,EDI,join XMM0:8 RSI");
    e.parse_type("struct intdoublepair { int4 a; float8 b;};");
    check!(e, "void func(int4,intdoublepair);", "void,EDI,join XMM0:8 RSI");
    e.parse_type("struct floatintpair { float4 a; int4 b;};");
    check!(e, "void func(int4,floatintpair);", "void,EDI,RSI");
    e.parse_type("struct doubleintpair { float8 a; int4 b;};");
    check!(e, "void func(int4,doubleintpair);", "void,EDI,join RSI XMM0:8");
    e.parse_type("struct intintfloat { int4 a; int4 b; float4 c; };");
    check!(e, "void func(int4,intintfloat);", "void,EDI,join XMM0:4 RSI");
    e.parse_type("struct intintfloatfloat { int4 a; int4 b; float4 c; float4 d;};");
    check!(e, "void func(int4,intintfloatfloat);", "void,EDI,join XMM0:8 RSI");
    e.parse_type("struct intfloatfloatint { int4 a; float4 b; float4 c; int4 d;};");
    check!(e, "void func(int4,intfloatfloatint);", "void,EDI,join RDX RSI");
    e.parse_type("struct intfloatfloat { int4 a; float4 b; float4 c; };");
    check!(e, "void func(int4,intfloatfloat);", "void,EDI,join XMM0:4 RSI");
    e.parse_type("struct floatfloatpair { float4 a; float4 b; };");
    check!(e, "void func(int4,floatfloatpair);", "void,EDI,XMM0:8");
    e.parse_type("struct doublefloatpair { float8 a; float4 b; };");
    check!(e, "void func(int4,doublefloatpair);", "void,EDI,join XMM1:8 XMM0:8");
    e.parse_type("struct floatfloatfloat { float4 a; float4 b; float4 c; };");
    check!(e, "void func(floatfloatfloat,int8);", "void,join XMM1:4 XMM0:8,RDI");
    e.parse_type("struct intintintint { int4 a; int4 b; int4 c; int4 d; };");
    check!(e, "void func(intintintint);", "void,join RSI RDI");
    check!(e, "void func(int4,intintintint);", "void,EDI,join RDX RSI");
    e.parse_type("struct intintintintint { int4 a; int4 b; int4 c; int4 d; int4 e;};");
    check!(e, "void func(intintintintint);", "void,stack8:20");
    check!(
        e,
        "void func(float4,float4,float4,float4,float4,float4,float4,float4,longfloatpair);",
        "void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,stack8:16"
    );
    check!(e, "void func(xunknown4,xunknown8);", "void,EDI,RSI");
    check!(e, "intintintint func(void);", "join RDX RAX");
    check!(e, "floatintpair func(void);", "RAX");
    check!(e, "longfloatpair func(void);", "join XMM0:8 RAX");
    check!(e, "longdoublepair func(void);", "join XMM0:8 RAX");
    check!(e, "doubleintpair func(void);", "join RAX XMM0:8");
    check!(e, "floatfloatfloat func(void);", "join XMM1:4 XMM0:8");
    e.parse_type("struct doubledoublepair { float8 a; float8 b; };");
    check!(e, "doubledoublepair func(void);", "join XMM1:8 XMM0:8");
    check!(e, "floatfloatpair func(void);", "XMM0:8");
    check!(e, "intintintintint func(void);", "RAX,RDI");
    e.parse_type("struct doubleintintint { float8 a; int4 b; int4 c; int4 d; };");
    check!(e, "doubleintintint func(void);", "RAX,RDI");
}

#[test]
fn paramstore_x64_go() {
    let Some(mut e) = Env::new("x86:LE:64:default:golang", "abi-internal") else { return };
    check!(e, "void func(int2 a,int8 b,char c);", "void,AX,RBX,CL");
    check!(e, "void func(float4 a,float4 b);", "void,XMM0:4,XMM1:4");
    check!(e, "void func(float4 a,float8 c);", "void,XMM0:4,XMM1:8");
    check!(
        e,
        "void func(int8 a,int8 b,int8 c,int8 d,int8 e,float4 f,float4 g,int8 h,int8 i,int8 j,int8 k,int8 l);",
        "void,RAX,RBX,RCX,RDI,RSI,XMM0:4,XMM1:4,R8,R9,R10,R11,stack8:8"
    );
    check!(
        e,
        "void func(float4 a,float4 b,float4 c,float4 d,float4 e,float4 f,float4 g,float4 h, \
         float4 i,float4 j,float4 k,float4 l,float4 m,float4 n,float4 o,float4 p);",
        "void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,XMM8:4,XMM9:4,XMM10:4,\
         XMM11:4,XMM12:4,XMM13:4,XMM14:4,stack8:4"
    );
    check!(e, "void func(int8 a,int8 b[3],int8 c);", "void,RAX,stack8:24,RBX");
    e.parse_type("struct Person { bool a; int4 b; };");
    e.parse_type("struct Myriad { int8 a; bool b; Person c; float4 d; };");
    check!(e, "void func(Person a);", "void,join EBX pad:3 AL");
    check!(e, "void func(bool a,Myriad b);", "void,AL,join XMM0:4 ESI pad:3 DIL pad:3 CL RBX");
    check!(e, "Person func(void);", "join EBX pad:3 AL");
    check!(e, "float8 func(int8 a,int8 b[10])[5];", "stack58:40,RAX,stack8:80");
    check!(e, "char func(char a[3],char b[7],int8 c)[5];", "stack18:5,stack8:3,stackb:7,RAX");
    check!(e, "void func(float4 a,int8 b[1],int8 c[2]);", "void,XMM0:4,RAX,stack8:16");
}

#[test]
fn paramstore_ppc64be_stdcall() {
    let Some(mut e) = Env::new("PowerPC:BE:64:default:default", "__stdcall") else { return };
    check!(e, "void func(int4 a,float4 b,float8 c);", "void,r3:4,join f1,f2");
    check!(e, "void func(float8 a,int8 b,float8 c);", "void,f1,r4,f2");
    e.parse_type("struct sparm { int4 a; float8 dd; };");
    check!(
        e,
        "void func(int4 c,float8 ff,int4 d,float16 ld,sparm s,float8 gg,sparm t,int4 e,float8 hh);",
        "void,r3:4,f1,r5:4,join f2 f3,join r8 r9,f4,stack70:16,stack84:4,f5"
    );
}

#[test]
fn paramstore_mips32be_stdcall() {
    let Some(mut e) = Env::new("MIPS:BE:32:default:default", "__stdcall") else { return };
    check!(e, "void func(int2 a,int4 b,char c);", "void,a0:2,a1,a2:1");
    check!(e, "void func(float8 a,float8 b);", "void,f12_13,f14_15");
    check!(e, "void func(float4 a,float4 b);", "void,f12,f14");
    check!(e, "void func(float4 a,float8 b);", "void,f12,f14_15");
    check!(e, "void func(float8 a,float4 b);", "void,f12_13,f14");
    check!(e, "void func(int4 a,int4 b,int4 c,int4 d);", "void,a0,a1,a2,a3");
    check!(e, "void func(float8 a,int4 b,float8 c);", "void,f12_13,a2,stack10:8");
    check!(e, "void func(float8 a,int4 b,int4 c);", "void,f12_13,a2,a3");
    check!(e, "void func(float4 a,int4 b,int4 c);", "void,f12,a1,a2");
    check!(e, "void func(int4 a,int4 b,int4 c,float8 d);", "void,a0,a1,a2,stack10:8");
    check!(e, "void func(int4 a,int4 b,int4 c,float4 d);", "void,a0,a1,a2,a3");
    check!(e, "void func(int4 a,int4 b,float8 c);", "void,a0,a1,join a2 a3");
    check!(e, "void func(int4 a,float8 b);", "void,a0,join a2 a3");
    check!(e, "void func(float4 a,float4 b,float4 c,float4 d);", "void,f12,f14,a2,a3");
    check!(e, "void func(float4 a,int4 b,float4 c,int4 d);", "void,f12,a1,a2,a3");
    check!(e, "void func(float8 a,float4 b,float4 c);", "void,f12_13,f14,a3");
    check!(e, "void func(float4 a,float4 b,float8 c);", "void,f12,f14,join a2 a3");
    check!(e, "void func(int4 a,float4 b,int4 c,float4 d);", "void,a0,a1,a2,a3");
    check!(e, "void func(int4 a,float4 b,int4 c,int4 d);", "void,a0,a1,a2,a3");
    check!(e, "void func(int4 a,int4 b,float4 c,int4 d);", "void,a0,a1,a2,a3");
    check!(e, "int4 func(void);", "v0");
    check!(e, "float4 func(void);", "f0");
    check!(e, "float8 func(void);", "f0_1");
    e.parse_type("struct onefieldstruct { int4 a; };");
    e.parse_type("struct twofieldstruct { int4 a; int4 b; };");
    check!(e, "onefieldstruct func(int4 a);", "v0,a0,a1");
    check!(e, "twofieldstruct func(int4 a);", "v0,a0,a1");
    check!(e, "void func(twofieldstruct a);", "void,join a0 a1");
    e.parse_type("struct intdouble { int4 a; float8 b; };");
    check!(e, "void func(intdouble a);", "void,join a0 a1 a2 a3");
}

#[test]
fn paramstore_aarch64_cdecl() {
    let Some(mut e) = Env::new("AARCH64:LE:64:v8A:default", "__cdecl") else { return };
    check!(e, "void func(int2 a,int4 b,int1 c);", "void,w0:2,w1,w2:1");
    check!(e, "void func(int4, int4);", "void,w0,w1");
    check!(e, "void func(int8,int8);", "void,x0,x1");
    check!(e, "void func(float4,float4);", "void,s0,s1");
    check!(e, "void func(float8,float8);", "void,d0,d1");
    check!(e, "void func(int4,float4,int4,float4);", "void,w0,s0,w1,s1");
    check!(e, "void func(float4,int4,float4,int4);", "void,s0,w0,s1,w1");
    check!(e, "void func(int4,float8,float8,int4);", "void,w0,d0,d1,w1");
    check!(e, "void func(float8,int8,int8,float8);", "void,d0,x0,x1,d1");
    check!(e, "void func(float16);", "void,q0");
    check!(e, "void func(float4,float16);", "void,s0,q1");
    check!(
        e,
        "void func(int4,int4,int4,int4,int4,int4,int4,int4,int4,int4);",
        "void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,stack8:4"
    );
    check!(
        e,
        "void func(float4,float4,float4,float4,float4,float4,float4,float4,float4,float4);",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack8:4"
    );
    check!(
        e,
        "void func(float4,float4,float4,float4,float4,float4,float4,float4,float16);",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:16"
    );
    check!(
        e,
        "void func(float4,float4,float4,float4,float4,float4,float4,float4,float4,float16);",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack10:16"
    );
    check!(
        e,
        "void func(int4,int4,int4,int4,int4,int4,int4,int4,int4,float4);",
        "void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,s0"
    );
    check!(
        e,
        "void func(float4,float4,float4,float4,float4,float4,float4,float4,float4,int4);",
        "void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,w0"
    );
    e.parse_type("struct intpair { int4 a; int4 b;};");
    check!(e, "void func(intpair);", "void,x0");
    e.parse_type("struct longpair { int8 a; int8 b; };");
    check!(e, "void func(longpair);", "void,join x1 x0");
    e.parse_type("struct longquad { int8 a; int8 b; int8 c; int8 d; };");
    check!(e, "void func(longquad);", "void,x0");
    e.parse_type("struct floatdouble { float4 a; float8 b; };");
    check!(e, "void func(floatdouble);", "void,join x1 x0");
    e.parse_type("struct intfloat { int4 a; float4 b; };");
    check!(e, "void func(intfloat);", "void,x0");
    e.parse_type("struct longdoublestruct { int8 a; float8 b; };");
    check!(e, "void func(longdoublestruct);", "void,join x1 x0");
    check!(e, "int4 func(void);", "w0");
    check!(e, "float4 func(void);", "s0");
    check!(e, "float8 func(void);", "d0");
    check!(e, "intpair func(void);", "x0");
    check!(e, "longpair func(void);", "join x1 x0");
    check!(e, "longquad func(void);", "void,x8");
    e.parse_type("struct floatpair { float4 a; float4 b; };");
    check!(e, "void func(floatpair);", "void,join s1 s0");
    e.parse_type("struct floatpairpair { floatpair a; floatpair b; };");
    check!(e, "void func(floatpairpair);", "void,join s3 s2 s1 s0");
    e.parse_type("struct doublequad { float8 a; float8 b; float8 c; float8 d; };");
    check!(e, "void func(doublequad);", "void,join d3 d2 d1 d0");
}
