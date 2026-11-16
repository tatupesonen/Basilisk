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
//! The cache layer against `ScriptedHost` (spec 6.1, last bullet; 4.19):
//! what is asked, when, and in which order.

mod common;

use std::sync::Arc;

use bk_core::{Address, Provenance, Range, RangeList};
use bk_decomp_symbols::comment::{Comment, kind};
use bk_decomp_symbols::host::cache::{HostComments, HostConstantPool, HostDatabase, HostStrings};
use bk_decomp_symbols::host::test::ScriptedHost;
use bk_decomp_symbols::host::{
    HostEntry, HostNamespace, HostReply, HostString, HostSymbol, HostSymbolKind, ProgramHost,
    SymbolRecord, is_dynamic_symbol_name,
};
use bk_decomp_symbols::{SymbolError, VarnodeFlags};
use bk_decomp_types::Metatype;
use common::small::{RAM, STACK, env};

fn ram(off: u64) -> Address {
    Address::new(RAM, off)
}

fn data_symbol(scope: u64, name: &str, at: u64, ty: bk_decomp_types::TypeId) -> HostReply {
    HostReply::Symbol(HostSymbol {
        scope,
        record: SymbolRecord {
            kind: HostSymbolKind::Data { ty },
            name: name.to_owned(),
            id: 0x77,
            flags: VarnodeFlags::READONLY,
            entries: vec![HostEntry {
                addr: ram(at),
                use_limit: RangeList::default(),
            }],
        },
        name_provenance: Provenance::User,
        type_provenance: Provenance::DebugInfo,
    })
}

#[test]
fn spaces_without_a_global_range_are_never_asked() {
    let (env, mut types) = env();
    let host = Arc::new(ScriptedHost::new());
    let mut h = HostDatabase::new(env, Arc::clone(&host) as Arc<dyn ProgramHost>);
    let glob = h.db().global().unwrap();
    assert!(
        h.query_by_addr(glob, ram(0x1000), Address::INVALID, &mut types)
            .unwrap()
            .is_none()
    );
    assert_eq!(host.calls(), [] as [String; 0]);
    h.add_global_range(RAM, 0, u64::MAX).unwrap();
    h.query_by_addr(glob, ram(0x1000), Address::INVALID, &mut types)
        .unwrap();
    assert_eq!(host.calls().len(), 1);
    // "Nothing" is not cached: asked again.
    h.query_by_addr(glob, ram(0x1000), Address::INVALID, &mut types)
        .unwrap();
    assert_eq!(host.calls().len(), 2);
    // A stack address is never asked: its space has no global range.
    h.query_by_addr(
        glob,
        Address::new(STACK, 0x10),
        Address::INVALID,
        &mut types,
    )
    .unwrap();
    assert_eq!(host.calls().len(), 2);
}

#[test]
fn holes_stop_repeat_queries_and_clear_restores_properties() {
    let (env, mut types) = env();
    let mut sh = ScriptedHost::new();
    sh.mapped.insert(
        ram(0x2000),
        HostReply::Hole {
            range: Range::new(RAM, 0x2000, 0x20ff),
            readonly: true,
            volatile: false,
        },
    );
    let host = Arc::new(sh);
    let mut h = HostDatabase::new(env, Arc::clone(&host) as Arc<dyn ProgramHost>);
    h.add_global_range(RAM, 0, u64::MAX).unwrap();
    h.lock_default_properties();
    let glob = h.db().global().unwrap();
    let (_, flags) = h
        .query_properties(glob, ram(0x2000), 4, Address::INVALID, &mut types)
        .unwrap();
    assert!(flags.contains(VarnodeFlags::READONLY));
    assert_eq!(host.calls().len(), 1);
    // Inside the hole: not asked again.
    h.query_properties(glob, ram(0x2080), 4, Address::INVALID, &mut types)
        .unwrap();
    assert_eq!(host.calls().len(), 1);
    assert!(
        h.db()
            .property(ram(0x2010))
            .contains(VarnodeFlags::READONLY)
    );
    h.clear().unwrap();
    assert!(
        !h.db()
            .property(ram(0x2010))
            .contains(VarnodeFlags::READONLY)
    );
    assert!(h.holes().is_empty());
    h.query_properties(glob, ram(0x2080), 4, Address::INVALID, &mut types)
        .unwrap();
    assert_eq!(host.calls().len(), 2);
}

#[test]
fn namespace_symbols_are_cached_with_their_path_and_marked_as_holes() {
    let (env, mut types) = env();
    let int4 = types.base(4, Metatype::Int).unwrap();
    let mut sh = ScriptedHost::new();
    sh.mapped
        .insert(ram(0x3000), data_symbol(0x55, "counter", 0x3000, int4));
    sh.paths.insert(
        0x55,
        vec![
            HostNamespace {
                id: 0x44,
                name: "outer".into(),
                label: None,
            },
            HostNamespace {
                id: 0x55,
                name: "inner".into(),
                label: None,
            },
        ],
    );
    sh.used_names.push("taken".into());
    let host = Arc::new(sh);
    let mut h = HostDatabase::new(env, Arc::clone(&host) as Arc<dyn ProgramHost>);
    h.add_global_range(RAM, 0, u64::MAX).unwrap();
    let glob = h.db().global().unwrap();
    let e = h
        .query_by_addr(glob, ram(0x3000), Address::INVALID, &mut types)
        .unwrap()
        .unwrap();
    let sym = h.db().entry(e).unwrap().symbol();
    let data = h.db().symbol(sym).unwrap();
    assert_eq!(data.name(), "counter");
    assert_eq!(data.name_provenance(), Provenance::User);
    assert_eq!(data.type_provenance(), Provenance::DebugInfo);
    let ns = data.scope();
    assert_eq!(h.db().full_name(ns), "outer::inner");
    assert_eq!(
        host.calls(),
        ["mapped_symbol(Some(3):0x3000)", "namespace_path(0x55)"]
    );
    // The symbol's range is a hole, its readonly flag a property.
    assert!(h.holes().in_range(ram(0x3002), 1));
    assert!(
        h.db()
            .property(ram(0x3001))
            .contains(VarnodeFlags::READONLY)
    );
    // Namespace ownership grew with the entry (ScopeGhidraNamespace).
    assert!(h.db().in_scope(ns, ram(0x3000), 4).unwrap());
    host.clear_calls();
    h.query_by_addr(glob, ram(0x3000), Address::INVALID, &mut types)
        .unwrap();
    assert!(host.calls().is_empty(), "{:?}", host.calls());
    // Names: FUN_/DAT_ never asked; others asked.
    assert!(!h.is_name_used(ns, "FUN_00401000", None).unwrap());
    assert_eq!(host.calls(), [] as [String; 0]);
    assert!(h.is_name_used(ns, "taken", None).unwrap());
    assert_eq!(host.calls(), ["is_name_used(taken,0x55,0x0)"]);
    assert!(is_dynamic_symbol_name("DAT_0040abcd"));
    assert!(!is_dynamic_symbol_name("DAT_0040ABCD"));
    assert!(!is_dynamic_symbol_name("FUN_12"));
}

#[test]
fn code_labels_are_asked_once_where_nothing_starts() {
    let (env, mut types) = env();
    let mut sh = ScriptedHost::new();
    sh.labels.insert(ram(0x4000), "loop_top".into());
    let host = Arc::new(sh);
    let mut h = HostDatabase::new(env, Arc::clone(&host) as Arc<dyn ProgramHost>);
    h.add_global_range(RAM, 0, u64::MAX).unwrap();
    let glob = h.db().global().unwrap();
    let l = h
        .query_code_label(glob, ram(0x4000), &mut types)
        .unwrap()
        .unwrap();
    assert_eq!(h.db().symbol(l).unwrap().name(), "loop_top");
    assert_eq!(
        h.db().symbol(l).unwrap().name_provenance(),
        Provenance::User
    );
    h.query_code_label(glob, ram(0x4000), &mut types).unwrap();
    assert_eq!(host.calls(), ["code_label(Some(3):0x4000)"]);
}

#[test]
fn one_comment_fill_per_clear_and_other_service_caches() {
    let mut sh = ScriptedHost::new();
    sh.comments.push(Comment {
        kind: kind::HEADER,
        func_addr: ram(0x100),
        addr: ram(0x100),
        uniq: 0,
        text: "hello".into(),
        emitted: false,
    });
    sh.strings.insert(
        ram(0x500),
        HostString {
            bytes: b"hi\0".to_vec(),
            truncated: false,
        },
    );
    let host = Arc::new(sh);
    let dynhost = Arc::clone(&host) as Arc<dyn ProgramHost>;
    let mut c = HostComments::new(Arc::clone(&dynhost));
    assert_eq!(c.comments(ram(0x100), kind::HEADER).unwrap().len(), 1);
    assert_eq!(c.comments(ram(0x200), kind::HEADER).unwrap().len(), 0);
    assert_eq!(host.calls().len(), 1);
    c.clear();
    c.comments(ram(0x200), kind::HEADER).unwrap();
    assert_eq!(host.calls().len(), 2);
    // A zero mask asks nothing.
    c.clear();
    c.comments(ram(0x100), 0).unwrap();
    assert_eq!(host.calls().len(), 2);

    let (_, mut types) = env();
    let ch = types.base(1, Metatype::Int).unwrap();
    let mut s = HostStrings::new(Arc::clone(&dynhost), 2048);
    assert_eq!(s.string_data(ram(0x500), ch).unwrap().bytes, b"hi\0");
    assert_eq!(s.string_data(ram(0x600), ch).unwrap().bytes, [] as [u8; 0]);
    s.string_data(ram(0x500), ch).unwrap();
    s.string_data(ram(0x600), ch).unwrap();
    assert_eq!(host.calls().len(), 4, "{:?}", host.calls());

    let mut p = HostConstantPool::new(dynhost);
    let err = p.record(&[0x1234, 5], &mut types).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Could not retrieve constant pool record for reference: 0x1234"
    );
    assert!(matches!(err, SymbolError::Host(_)));
}

#[test]
fn the_three_d_hooks_default_to_no_opinion() {
    struct Silent;
    impl ProgramHost for Silent {
        fn mapped_symbol(&self, _: Address) -> Result<HostReply, bk_decomp_symbols::HostError> {
            Ok(HostReply::Nothing)
        }
        fn external_ref(
            &self,
            _: Address,
        ) -> Result<Option<HostSymbol>, bk_decomp_symbols::HostError> {
            Ok(None)
        }
        fn namespace_path(
            &self,
            _: u64,
        ) -> Result<Vec<HostNamespace>, bk_decomp_symbols::HostError> {
            Ok(Vec::new())
        }
        fn is_name_used(
            &self,
            _: &str,
            _: u64,
            _: u64,
        ) -> Result<bool, bk_decomp_symbols::HostError> {
            Ok(false)
        }
        fn code_label(
            &self,
            _: Address,
        ) -> Result<Option<(String, Provenance)>, bk_decomp_symbols::HostError> {
            Ok(None)
        }
        fn comments(
            &self,
            _: Address,
            _: u32,
        ) -> Result<Vec<Comment>, bk_decomp_symbols::HostError> {
            Ok(Vec::new())
        }
        fn bytes(&self, addr: Address, _: &mut [u8]) -> Result<(), bk_decomp_symbols::DataUnavail> {
            Err(bk_decomp_symbols::DataUnavail {
                addr,
                message: "no".into(),
            })
        }
        fn string_data(
            &self,
            _: Address,
            _: bk_decomp_types::TypeId,
            _: usize,
        ) -> Result<Option<HostString>, bk_decomp_symbols::HostError> {
            Ok(None)
        }
        fn cpool_record(
            &self,
            _: &[u64],
        ) -> Result<Option<bk_decomp_symbols::cpool::CPoolRecord>, bk_decomp_symbols::HostError>
        {
            Ok(None)
        }
        fn tracked_registers(
            &self,
            _: Address,
        ) -> Result<Vec<bk_context::TrackedValue>, bk_decomp_symbols::HostError> {
            Ok(Vec::new())
        }
    }
    let host: Arc<dyn ProgramHost> = Arc::new(Silent);
    assert!(host.function_summary(ram(0x10)).is_none());
    assert!(host.call_returns(ram(0x10), Some(ram(0x20))).is_none());
    assert!(host.data_type("int", 1, 4).is_none());
    // Plugin constraint 2: the trait object is Send + Sync + 'static.
    is_send_sync::<dyn ProgramHost>();
    let mut sh = ScriptedHost::new();
    sh.returns.insert(ram(0x30), false);
    assert_eq!(sh.call_returns(ram(0x30), None), Some(false));
}

fn is_send_sync<T: Send + Sync + 'static + ?Sized>() {}
