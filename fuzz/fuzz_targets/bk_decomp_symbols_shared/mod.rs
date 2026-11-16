//! Shared by the `bk_decomp_symbols_*` targets and by the crate's
//! `tests/fuzz_regressions.rs`: a small architecture (const, OTHER, unique,
//! an 8-byte ram, register, fspec, iop, join, stack), one sample document
//! per format, and what each target does with its input. The input is a
//! text of its own (first byte 0) or edits of the sample (any other first
//! byte; `bk_testkit_shared::text`). Nothing may panic, overflow the stack
//! or hang; what decodes must encode again.

#![allow(dead_code, reason = "each target uses one entry point")]

#[path = "../bk_testkit_shared/mod.rs"]
mod edits;

use std::sync::{Arc, OnceLock};

use bk_core::{Address, Space, SpaceId, SpaceManager};
use bk_cspec::FuncProto;
use bk_decomp_symbols::comment::CommentDb;
use bk_decomp_symbols::cpool::ConstantPool;
use bk_decomp_symbols::image::{LoadImage, XmlImage};
use bk_decomp_symbols::overrides::{Overrides, ProtoCodec};
use bk_decomp_symbols::strings::{CharType, StringCache};
use bk_decomp_symbols::{ArchEnv, ContextNames, Database, SymbolError, ids};
use bk_decomp_types::{DataOrganization, SpaceInfo, TypeEnv, TypeFactory};
use bk_marshal::{Decoder, Document, Encoder, XmlDecoder, XmlEncoder};

const RAM: SpaceId = SpaceId::new(3);

/// The targets.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Target {
    /// A `<db>` or `<scope>` into a database, queried and encoded again.
    Scope,
    /// A `<binaryimage>`, read from and encoded again.
    BinaryImage,
    /// A `<commentdb>`.
    CommentDb,
    /// A `<stringmanage>`, plus the input's bytes as an internal string.
    StringManage,
    /// A `<constantpool>`.
    ConstantPool,
    /// A `<context_points>` over three registered variables.
    ContextPoints,
    /// An `<override>`.
    Override,
}

impl Target {
    /// Every target with its name.
    pub(crate) const ALL: [(Self, &'static str); 7] = [
        (Self::Scope, "bk_decomp_symbols_scope"),
        (Self::BinaryImage, "bk_decomp_symbols_binaryimage"),
        (Self::CommentDb, "bk_decomp_symbols_commentdb"),
        (Self::StringManage, "bk_decomp_symbols_stringmanage"),
        (Self::ConstantPool, "bk_decomp_symbols_constantpool"),
        (Self::ContextPoints, "bk_decomp_symbols_context_points"),
        (Self::Override, "bk_decomp_symbols_override"),
    ];

    fn sample(self) -> &'static str {
        match self {
            Self::Scope => SCOPE_SAMPLE,
            Self::BinaryImage => IMAGE_SAMPLE,
            Self::CommentDb => COMMENT_SAMPLE,
            Self::StringManage => STRING_SAMPLE,
            Self::ConstantPool => CPOOL_SAMPLE,
            Self::ContextPoints => CONTEXT_SAMPLE,
            Self::Override => OVERRIDE_SAMPLE,
        }
    }
}

const SCOPE_SAMPLE: &str = r#"<db scopeidbyname="true">
<property_changepoint space="ram" offset="0x1000" val="0x2000"/>
<property_changepoint space="ram" offset="0x1010" val="0x0"/>
<scope name="" id="0x0">
<rangelist><range space="ram" first="0x1000" last="0x1fff"/></rangelist>
<symbollist>
<mapsym><symbol name="a" id="0x10" readonly="true" cat="-1"><typeref name="int4" id="0xc000fe2ec290219f"/></symbol><addr space="ram" offset="0x1000"/><rangelist/></mapsym>
<mapsym><labelsym name="lab" id="0x11" cat="-1"/><addr space="ram" offset="0x1004"/><rangelist/></mapsym>
<mapsym><equatesymbol name="e" cat="1" index="0"><value>0x5</value></equatesymbol><hash val="0x1234"/><addr space="ram" offset="0x1008"/><rangelist><range space="ram" first="0x1008" last="0x1008"/></rangelist></mapsym>
<mapsym><symbol name="b" cat="0" index="2"><type name="" size="8" metatype="array" arraysize="8"><typeref name="uint1"/></type></symbol><addr space="stack" offset="0x10"/><rangelist><range space="ram" first="0x1000" last="0x1000"/></rangelist></mapsym>
<hole space="ram" first="0x1100" last="0x11ff" readonly="true" volatile="true"/>
<collision name="c"/>
</symbollist>
</scope>
<scope name="ns" id="0x20"><parent id="0x0"/><rangeequalssymbols/>
<symbollist><mapsym><symbol name="n" cat="-1"><typeref name="int8"/></symbol><addr space="ram" offset="0x3000"/><rangelist/></mapsym></symbollist>
</scope>
</db>"#;

const IMAGE_SAMPLE: &str = r#"<binaryimage arch="x86:LE:64:default">
<bytechunk space="ram" offset="0x1000" readonly="true">
4889e5 c3
0001020304050607
</bytechunk>
<bytechunk space="ram" offset="0x1004">ff</bytechunk>
<symbol space="ram" offset="0x1000" name="start"/>
</binaryimage>"#;

const COMMENT_SAMPLE: &str = r#"<commentdb>
<comment type="user1"><addr space="ram" offset="0x1000"/><addr space="ram" offset="0x1004"/><text>hello &amp; more</text></comment>
<comment type="warningheader"><addr space="ram" offset="0x1000"/><addr space="ram" offset="0x1000"/><text>w</text></comment>
<comment type="header"><addr space="ram" offset="0x2000"/><addr space="ram" offset="0x2000"/></comment>
</commentdb>"#;

const STRING_SAMPLE: &str = r#"<stringmanage>
<string><addr space="ram" offset="0x10"/><bytes trunc="false">
68656c6c6f00
</bytes></string>
<string><addr space="const" offset="0x1234"/><bytes trunc="true">41 42 4 3</bytes></string>
</stringmanage>"#;

const CPOOL_SAMPLE: &str = r#"<constantpool>
<ref a="0x1" b="0x2"/>
<cpoolrec tag="primitive"><value>0x7</value><token>seven</token><typeref name="int4" id="0xc000fe2ec290219f"/></cpoolrec>
<ref a="0x3" b="0x0"/>
<cpoolrec tag="string"><data length="3">41 42 0x43</data><typeref name="uint1"/></cpoolrec>
<ref a="0x4" b="0x0"/>
<cpoolrec tag="method" constructor="true"><token>m</token><type name="" size="8" metatype="ptr"><type name="" size="1" metatype="code"/></type></cpoolrec>
</constantpool>"#;

const CONTEXT_SAMPLE: &str = r#"<context_points>
<context_pointset space="ram" offset="0x1000"><set name="mode" val="1"/><set name="wide" val="0x3"/></context_pointset>
<context_pointset space="ram" offset="0x2000"/>
<tracked_pointset space="ram" offset="0x1000"><set space="register" offset="0x0" size="4" val="0x10"/></tracked_pointset>
</context_points>"#;

const OVERRIDE_SAMPLE: &str = r#"<override>
<forcegoto><addr space="ram" offset="0x10"/><addr space="ram" offset="0x20"/></forcegoto>
<deadcodedelay space="stack" delay="2"/>
<multistagejump><addr space="ram" offset="0x30"/></multistagejump>
<flow type="callreturn"><addr space="ram" offset="0x40"/></flow>
<calldest type="call_call"><addr space="ram" offset="0x50"/><addr space="ram" offset="0x60"/></calldest>
<unknown><x/></unknown>
</override>"#;

/// The architecture, built once.
fn spaces() -> &'static Arc<SpaceManager> {
    static S: OnceLock<Arc<SpaceManager>> = OnceLock::new();
    S.get_or_init(|| {
        let mut m = SpaceManager::new();
        let ram = Space::processor("ram", false, 8, 1, 3, true, 0, 0).ok();
        let parts = [
            Some(Space::constant()),
            Some(Space::other()),
            Space::unique(2, false).ok(),
            ram.clone(),
            Space::processor("register", false, 4, 1, 4, false, 0, 0).ok(),
            Space::fspec(5).ok(),
            Space::iop(6).ok(),
            Space::join(7, false).ok(),
            ram.as_ref()
                .and_then(|r| Space::spacebase("stack", 8, 8, r, 0, true, false).ok()),
        ];
        for space in parts.into_iter().flatten() {
            let _ = m.insert_space(space);
        }
        let _ = m.set_default_code_space(RAM);
        let _ = m.set_default_data_space(RAM);
        Arc::new(m)
    })
}

/// A type factory with the default core types, cloned for every input.
fn types() -> TypeFactory {
    static F: OnceLock<TypeFactory> = OnceLock::new();
    F.get_or_init(|| {
        let m = spaces();
        let info = |s: &Space| SpaceInfo {
            id: s.id(),
            name: s.name().to_owned(),
            addr_size: s.addr_size() as i32,
            word_size: s.word_size(),
            big_endian: s.is_big_endian(),
        };
        let mut env = TypeEnv::simple(8, false);
        if let Some(ram) = m.space(RAM) {
            env.data_space = info(ram);
        }
        env.other_spaces = m.spaces().filter(|s| s.id() != RAM).map(info).collect();
        TypeFactory::with_core_types(env.clone(), DataOrganization::default())
            .unwrap_or_else(|_| TypeFactory::new(env, DataOrganization::default()))
    })
    .clone()
}

/// Prototype overrides need `bk-cspec`'s codec (D07): refused here.
struct NoProtos;

impl ProtoCodec for NoProtos {
    fn encode(&self, _: &FuncProto, _: &mut dyn Encoder) -> bk_decomp_symbols::Result<()> {
        Err(SymbolError::Unimplemented("prototype encoding"))
    }
    fn decode(&self, _: &mut dyn Decoder<'_>) -> bk_decomp_symbols::Result<FuncProto> {
        Err(SymbolError::Unimplemented("prototype decoding"))
    }
    fn print_raw(&self, _: &FuncProto) -> String {
        String::new()
    }
}

/// Runs one input through a target.
pub(crate) fn run(target: Target, data: &[u8]) {
    let Some(text) = edits::text(data, target.sample()) else {
        return;
    };
    let Ok(doc) = Document::parse(&text) else {
        return;
    };
    let sp = spaces();
    let table = ids::id_table();
    let mut dec = XmlDecoder::new(&doc, &table, &**sp);
    let mut enc = XmlEncoder::new(false);
    match target {
        Target::Scope => scope(&mut dec, &mut enc),
        Target::BinaryImage => {
            if let Ok(image) = XmlImage::decode(&mut dec, Arc::clone(sp), "fuzz") {
                let mut buf = [0u8; 64];
                for (addr, _) in image.chunks().take(8) {
                    let _ = image.load_fill(&mut buf, *addr);
                }
                let _ = image.encode(&mut enc);
            }
        }
        Target::CommentDb => {
            let mut db = CommentDb::new();
            if db.decode(&mut dec, sp).is_ok() {
                let _ = db.encode(&mut enc, sp);
            }
        }
        Target::StringManage => {
            let mut cache = StringCache::default();
            if cache.decode(&mut dec, sp).is_ok() {
                let _ = cache.encode(&mut enc, sp);
            }
            for size in [1, 2, 4] {
                let _ = cache.register_internal(Address::new(RAM, 0x10), data, size, sp);
            }
            let image =
                bk_decomp_symbols::image::RawImage::new(data.to_vec(), RAM, 0, Arc::clone(sp));
            for size in [1, 2, 4] {
                let ch = CharType {
                    size,
                    opaque: false,
                };
                let _ = StringCache::default().string_data(Address::new(RAM, 0), ch, &image, sp);
            }
        }
        Target::ConstantPool => {
            let mut types = types();
            let mut pool = ConstantPool::new();
            if pool.decode(&mut dec, &mut types).is_ok() {
                let _ = pool.encode(&mut enc, &types);
            }
        }
        Target::ContextPoints => {
            let mut ctx = ContextNames::new();
            ctx.set_space_limits(sp);
            let _ = ctx.register_variable("mode", 0, 3);
            let _ = ctx.register_variable("wide", 28, 31);
            let _ = ctx.register_variable("high", 60, 63);
            if ctx.decode(&mut dec, sp).is_ok() {
                let _ = ctx.encode(&mut enc, sp);
            }
        }
        Target::Override => {
            let mut ov = Overrides::default();
            if ov.decode(&mut dec, sp, &NoProtos).is_ok() {
                let _ = ov.print_raw(sp, &NoProtos);
                let _ = ov.override_messages(sp);
                let _ = ov.encode(&mut enc, sp, &NoProtos);
            }
        }
    }
}

/// A `<db>` into an empty database, or a `<scope>` body into the global
/// scope of a fresh one; then queries, printing and encoding.
fn scope(dec: &mut XmlDecoder<'_>, enc: &mut XmlEncoder) {
    let sp = spaces();
    let mut types = types();
    let env = ArchEnv::new(Arc::clone(sp));
    let db = if dec.peek_element() == Some(ids::ELEM_DB.code()) {
        let mut db = Database::without_global(env, true);
        if db.decode(dec, &mut types, None).is_err() {
            return;
        }
        db
    } else {
        let mut db = Database::new(env, true);
        let Some(global) = db.global() else { return };
        let Ok(Some(el)) = dec.open_element() else {
            return;
        };
        if db.decode_scope_body(global, dec, &mut types, None).is_err() {
            return;
        }
        let _ = dec.close_element(el);
        db
    };
    let Some(global) = db.global() else { return };
    let mut scopes = vec![global];
    let mut i = 0;
    while let Some(&s) = scopes.get(i) {
        if let Ok(data) = db.scope(s) {
            scopes.extend(data.children());
        }
        i += 1;
        if i > 64 {
            break;
        }
    }
    for &s in &scopes {
        for off in [0u64, 0x1000, 0x1004, 0x1008, 0x3000, u64::MAX] {
            let a = Address::new(RAM, off);
            let _ = db.query_by_addr(s, a, Address::INVALID);
            let _ = db.query_container(s, a, 8, a);
            let _ = db.query_properties(s, a, 4, Address::INVALID);
        }
        let _ = db.query_by_name(s, "a");
        let _ = db.print_entries(s, &types);
    }
    let _ = db.encode(enc, &types, None);
}
