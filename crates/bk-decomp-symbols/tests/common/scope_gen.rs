//! The scope oracle's generator (`tests/oracle/scope.cc`) driving Basilisk:
//! the same random draws, the same operations in the same order, the same
//! row texts. Comparing its output with the table is the replay.

use std::fmt::Write as _;

use bk_core::{Address, Range};
use bk_decomp_symbols::flags::category;
use bk_decomp_symbols::{Database, EntryId, ScopeId, SymbolError, SymbolId, VarnodeFlags, ids};
use bk_decomp_types::{Metatype, TypeFactory, TypeId};
use bk_marshal::{Document, XmlDecoder, XmlEncoder};

use super::oracle::{Arch, esc};

const NAMES: [&str; 9] = ["a", "b", "sym", "sym_00", "sym_01", "Var1", "x", "lab", "f"];

/// xorshift64*, as the generator.
pub struct Rng(pub u64);

impl Rng {
    pub fn rnd(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn r(&mut self, n: u32) -> u32 {
        (self.rnd() % u64::from(n)) as u32
    }
}

pub struct Gen<'a> {
    pub arch: &'a mut Arch,
    pub rng: Rng,
    pub out: String,
    pub kase: i64,
    db: Option<Database>,
    scopes: Vec<ScopeId>,
    syms: Vec<Option<SymbolId>>,
    /// The name each function had when its `Funcdata` was made (Ghidra
    /// prints `Funcdata::getName`, which a later rename does not change).
    fd_names: std::collections::HashMap<SymbolId, String>,
}

type R<T> = Result<T, SymbolError>;

impl<'a> Gen<'a> {
    pub fn new(arch: &'a mut Arch, seed: u64) -> Self {
        Self {
            arch,
            rng: Rng(seed | 1),
            out: String::new(),
            kase: 0,
            db: None,
            scopes: Vec::new(),
            syms: Vec::new(),
            fd_names: std::collections::HashMap::new(),
        }
    }

    fn db(&mut self) -> &mut Database {
        self.db.as_mut().unwrap()
    }

    fn row(&mut self, kind: &str, text: &str) {
        let _ = writeln!(self.out, "{}\t{kind}\t{}", self.kase, esc(text));
        let warnings = self
            .db
            .as_mut()
            .map(Database::take_warnings)
            .unwrap_or_default();
        if !warnings.is_empty() {
            let w: String = warnings.iter().map(|m| format!("WARNING: {m}\n")).collect();
            let _ = writeln!(self.out, "{}\tW\t{}", self.kase, esc(&w));
        }
    }

    fn addr_str(&self, a: Address) -> String {
        if a.is_invalid() {
            return "-".into();
        }
        let db = self.db.as_ref().unwrap();
        let name = db.spaces().space_of(a).map_or("?", bk_core::Space::name);
        format!("{name}:0x{:x}", a.offset())
    }

    fn scope_name(&self, s: ScopeId) -> String {
        self.db
            .as_ref()
            .unwrap()
            .scope(s)
            .map(|d| d.name().to_owned())
            .unwrap_or_default()
    }

    fn sym_str(&self, sym: Option<SymbolId>) -> String {
        let Some(sym) = sym else { return "-".into() };
        let db = self.db.as_ref().unwrap();
        let s = db.symbol(sym).unwrap();
        format!(
            "s{:x}:{}:{}:f{:x}:d{}:c{}:{}:t{}",
            s.ghidra_id(),
            s.name(),
            self.scope_name(s.scope()),
            s.flags().bits(),
            s.display_format(),
            s.category(),
            s.category_index() as u16,
            s.type_size()
        )
    }

    fn entry_str(&self, e: Option<EntryId>) -> String {
        let Some(e) = e else { return "-".into() };
        let db = self.db.as_ref().unwrap();
        let entry = db.entry(e).unwrap();
        let sym = entry.symbol();
        let flags = entry.extra_flags() | db.symbol(sym).unwrap().flags();
        format!(
            "{}@{}:{}:o{}:x{:x}:u{}",
            self.sym_str(Some(sym)),
            self.addr_str(entry.addr().unwrap_or(Address::INVALID)),
            entry.size(),
            entry.offset(),
            flags.bits(),
            entry.use_limit().bounds(db.spaces())
        )
    }

    fn fd_name(&self, f: SymbolId) -> String {
        self.fd_names.get(&f).cloned().unwrap_or_default()
    }

    fn rand_type(&mut self) -> TypeId {
        const SIZES: [i32; 6] = [1, 2, 4, 8, 16, 3];
        let sz = SIZES[self.rng.r(6) as usize];
        let types = &mut self.arch.types;
        if sz <= 8 && sz != 3 {
            return types.base(sz, Metatype::Unknown).unwrap();
        }
        let byte = types.base(1, Metatype::Unknown).unwrap();
        types.array(sz, byte).unwrap()
    }

    fn rand_data(&mut self) -> Address {
        if self.rng.r(4) == 0 {
            let off = 0xffff_ffff_ffff_ffc0u64 + u64::from(self.rng.r(0x20));
            return Address::new(self.arch.stack, off);
        }
        Address::new(self.arch.ram, 0x1000 + u64::from(self.rng.r(0x80)))
    }

    fn rand_use(&mut self) -> Address {
        if self.rng.r(3) == 0 {
            return Address::INVALID;
        }
        Address::new(self.arch.ram, 0x40_0000 + u64::from(self.rng.r(0x40)))
    }

    fn rand_name(&mut self) -> &'static str {
        NAMES[self.rng.r(9) as usize]
    }

    fn rand_scope(&mut self) -> ScopeId {
        let n = self.scopes.len() as u32;
        self.scopes[self.rng.r(n) as usize]
    }

    fn ram(&self, off: u64) -> Address {
        Address::new(self.arch.ram, off)
    }

    pub fn one_case(&mut self) {
        let result = self
            .build()
            .and_then(|()| self.populate())
            .and_then(|()| self.mutate())
            .and_then(|()| self.query())
            .and_then(|()| self.dump());
        if let Err(e) = result {
            self.row("!case", &e.to_string());
        }
    }

    fn build(&mut self) -> R<()> {
        self.db = Some(Database::new(self.arch.env.clone(), true));
        let glob = self.db().global().unwrap();
        self.scopes = vec![glob];
        self.syms.clear();
        let ram = self.arch.ram;
        if self.rng.r(2) != 0 {
            self.db().add_range(glob, ram, 0, u64::MAX)?;
        } else {
            self.db().add_range(glob, ram, 0x1000, 0x103f)?;
        }
        self.rng.r(2);
        self.row("global", "");
        let nns = self.rng.r(4);
        const PATHS: [&str; 3] = ["ns1::x", "ns2::x", "ns1::ns3::x"];
        for path in PATHS.iter().take(nns as usize) {
            let (ns, _) = self.db().find_create_scope_from_symbol_name(path, None)?;
            if !self.scopes.contains(&ns) {
                self.scopes.push(ns);
            }
            let mut p = self.db().scope(ns)?.parent();
            while let Some(s) = p {
                if !self.scopes.contains(&s) {
                    self.scopes.push(s);
                }
                p = self.db().scope(s)?.parent();
            }
            let nr = self.rng.r(3);
            for _ in 0..nr {
                let f = 0x1000 + u64::from(self.rng.r(0x80));
                if self.rng.r(3) == 0 {
                    let s1 = 0xffff_ffff_ffff_ffc0u64 + u64::from(self.rng.r(0x10));
                    let s2 = 0xffff_ffff_ffff_ffcfu64 + u64::from(self.rng.r(0x10));
                    let stack = self.arch.stack;
                    self.db().add_range(ns, stack, s1, s2)?;
                } else {
                    let len = u64::from(self.rng.r(0x30));
                    self.db().add_range(ns, ram, f, f + len)?;
                }
            }
            let db = self.db.as_ref().unwrap();
            let text = format!(
                "{} id=0x{:x} {}",
                db.full_name(ns),
                db.scope(ns)?.ghidra_id(),
                db.print_bounds(ns)?
            );
            self.row("scope", &text);
        }
        let nprop = self.rng.r(3);
        for _ in 0..nprop {
            let f = 0x1000 + u64::from(self.rng.r(0x80));
            let fl = if self.rng.r(2) != 0 {
                VarnodeFlags::READONLY
            } else {
                VarnodeFlags::VOLATILE
            };
            let len = u64::from(self.rng.r(0x20));
            let rng = Range::new(ram, f, f + len);
            if self.rng.r(4) == 0 {
                self.db().clear_property_range(fl, &rng);
            } else {
                self.db().set_property_range(fl, &rng);
            }
            self.row("prop", &format!("{:x} {f:x}", fl.bits()));
        }
        Ok(())
    }

    fn populate(&mut self) -> R<()> {
        let n = 1 + self.rng.r(40);
        for _ in 0..n {
            let sc = self.rand_scope();
            if let Err(e) = self.populate_one(sc) {
                self.row("!add", &e.to_string());
            }
        }
        Ok(())
    }

    fn populate_one(&mut self, sc: ScopeId) -> R<()> {
        match self.rng.r(9) {
            0..=2 => {
                let a = self.rand_data();
                let u = self.rand_use();
                let nm = self.rand_name();
                let ct = self.rand_type();
                let types = &self.arch.types;
                let e = self
                    .db
                    .as_mut()
                    .unwrap()
                    .add_symbol_at(sc, nm, ct, a, u, types)?;
                let sym = self.db().entry(e)?.symbol();
                self.syms.push(Some(sym));
                let text = format!("{} use={}", self.entry_str(Some(e)), self.addr_str(u));
                self.row("+sym", &text);
            }
            3 => {
                let a = {
                    let off = 0x1000 + u64::from(self.rng.r(0x80));
                    self.ram(off)
                };
                let nm = self.rand_name();
                let f = self
                    .db
                    .as_mut()
                    .unwrap()
                    .add_function(sc, a, nm, &mut self.arch.types)?;
                self.syms.push(Some(f));
                let fname = self.db().symbol(f)?.name().to_owned();
                self.fd_names.insert(f, fname);
                self.db().create_function_scope(f)?;
                let text = format!("{} {}", self.sym_str(Some(f)), self.addr_str(a));
                self.row("+func", &text);
            }
            4 => {
                let a = {
                    let off = 0x1000 + u64::from(self.rng.r(0x80));
                    self.ram(off)
                };
                let nm = self.rand_name();
                let l =
                    self.db
                        .as_mut()
                        .unwrap()
                        .add_code_label(sc, a, nm, &mut self.arch.types)?;
                self.syms.push(Some(l));
                let text = self.sym_str(Some(l));
                self.row("+label", &text);
            }
            5 => {
                let a = {
                    let off = 0x1000 + u64::from(self.rng.r(0x80));
                    self.ram(off)
                };
                let reference = {
                    let off = 0x1000 + u64::from(self.rng.r(0x80));
                    self.ram(off)
                };
                let nm = if self.rng.r(2) != 0 {
                    self.rand_name()
                } else {
                    ""
                };
                let x = self.db.as_mut().unwrap().add_external_ref(
                    sc,
                    a,
                    reference,
                    nm,
                    &mut self.arch.types,
                )?;
                self.syms.push(Some(x));
                let text = format!("{} ref={}", self.sym_str(Some(x)), self.addr_str(reference));
                self.row("+extref", &text);
            }
            6 => {
                let nm = self.rand_name();
                let fmt = self.rng.r(6);
                let val = self.rng.rnd() & 0xff;
                let u = self.rand_use();
                let h = self.rng.rnd();
                let q = self.db.as_mut().unwrap().add_equate_symbol(
                    sc,
                    nm,
                    fmt,
                    val,
                    u,
                    h,
                    &mut self.arch.types,
                )?;
                self.syms.push(Some(q));
                let text = self.sym_str(Some(q));
                self.row("+equate", &text);
            }
            7 => self.add_decoded(sc)?,
            _ => {
                if self.syms.is_empty() {
                    return Ok(());
                }
                let k = self.rng.r(self.syms.len() as u32) as usize;
                let Some(s) = self.syms[k] else { return Ok(()) };
                if self.db().symbol(s)?.is_function() {
                    return Ok(());
                }
                let a = self.rand_data();
                let u = self.rand_use();
                let e = self.db().add_map_point(s, a, u)?;
                let multi = if self.db().symbol(s)?.is_multi_entry() {
                    " multi"
                } else {
                    ""
                };
                let text = format!("{}{multi}", self.entry_str(Some(e)));
                self.row("+map", &text);
            }
        }
        Ok(())
    }

    fn add_decoded(&mut self, sc: ScopeId) -> R<()> {
        use bk_marshal::Encoder as _;
        let ct = self.rand_type();
        let a = self.rand_data();
        let mut enc = XmlEncoder::new(true);
        enc.open_element(ids::ELEM_MAPSYM);
        enc.open_element(bk_marshal::ids::ELEM_SYMBOL);
        let name = self.rand_name();
        enc.write_string(bk_marshal::ids::ATTRIB_NAME, name)?;
        if self.rng.r(2) != 0 {
            enc.write_bool(bk_marshal::ids::ATTRIB_TYPELOCK, true);
        }
        if self.rng.r(3) == 0 {
            enc.write_bool(bk_marshal::ids::ATTRIB_NAMELOCK, true);
        }
        if self.rng.r(4) == 0 {
            enc.write_bool(bk_marshal::ids::ATTRIB_READONLY, true);
        }
        enc.write_signed(ids::ATTRIB_CAT, -1);
        self.arch.types.encode_ref(&mut enc, ct)?;
        enc.close_element(bk_marshal::ids::ELEM_SYMBOL);
        a.encode(&mut enc, self.db().spaces())?;
        enc.open_element(bk_core::ids::ELEM_RANGELIST);
        let n = self.rng.r(4);
        let ram = self.arch.ram;
        for _ in 0..n {
            let f = 0x40_0000 + u64::from(self.rng.r(0x40));
            let last = f + u64::from(self.rng.r(8));
            Range::new(ram, f, last).encode(&mut enc, self.db().spaces())?;
        }
        enc.close_element(bk_core::ids::ELEM_RANGELIST);
        enc.close_element(ids::ELEM_MAPSYM);
        let xml = enc.into_string();
        let doc = Document::parse(&xml).map_err(bk_marshal::DecodeError::from)?;
        let table = ids::id_table();
        let spaces = std::sync::Arc::clone(&self.arch.env.spaces);
        let mut dec = XmlDecoder::new(&doc, &table, &*spaces);
        let types = &mut self.arch.types;
        let sym = self
            .db
            .as_mut()
            .unwrap()
            .add_map_sym(sc, &mut dec, types, None)?;
        if let Some(s) = sym {
            self.syms.push(Some(s));
        }
        let text = format!("{} {xml}", self.sym_str(sym));
        self.row("+mapsym", &text);
        Ok(())
    }

    fn mutate(&mut self) -> R<()> {
        let n = self.rng.r(8);
        for _ in 0..n {
            if self.syms.is_empty() {
                return Ok(());
            }
            let k = self.rng.r(self.syms.len() as u32) as usize;
            let Some(s) = self.syms[k] else { continue };
            if let Err(e) = self.mutate_one(k, s) {
                self.row("!mut", &e.to_string());
            }
        }
        Ok(())
    }

    fn mutate_one(&mut self, k: usize, s: SymbolId) -> R<()> {
        match self.rng.r(6) {
            0 => {
                let nm = self.rand_name();
                self.db().rename_symbol(s, nm)?;
                let t = self.sym_str(Some(s));
                self.row("rename", &t);
            }
            1 => {
                let d = self.db().symbol(s)?;
                if d.is_function() || d.category() == category::EQUATE {
                    return Ok(());
                }
                let ct = self.rand_type();
                let types = &self.arch.types;
                self.db.as_mut().unwrap().retype_symbol(s, ct, types)?;
                let t = self.sym_str(Some(s));
                self.row("retype", &t);
            }
            2 => {
                if self.db().symbol(s)?.is_function() {
                    return Ok(());
                }
                let t = self.sym_str(Some(s));
                self.row("remove", &t);
                self.db().remove_symbol(s)?;
                self.syms[k] = None;
            }
            3 => {
                self.db().set_attribute(s, VarnodeFlags::TYPELOCK)?;
                let t = self.sym_str(Some(s));
                self.row("lock", &t);
            }
            4 => {
                self.db()
                    .clear_attribute(s, VarnodeFlags::NAMELOCK | VarnodeFlags::TYPELOCK)?;
                let t = self.sym_str(Some(s));
                self.row("unlock", &t);
            }
            _ => {
                if self.db().symbol(s)?.category() == category::EQUATE {
                    return Ok(());
                }
                let ind = self.rng.r(3);
                self.db().set_category(s, 0, ind)?;
                let t = self.sym_str(Some(s));
                self.row("cat", &t);
            }
        }
        Ok(())
    }

    fn query(&mut self) -> R<()> {
        for _ in 0..40 {
            let sc = self.rand_scope();
            let a = self.rand_data();
            let sz = 1 + self.rng.r(8) as i32;
            let u = self.rand_use();
            let q = format!(
                "{} {} {sz} {} -> ",
                self.scope_name(sc),
                self.addr_str(a),
                self.addr_str(u)
            );
            if let Err(e) = self.query_one(sc, a, sz, u, &q) {
                self.row("!query", &e.to_string());
            }
        }
        for _ in 0..12 {
            let sc = self.rand_scope();
            let nm = self.rand_name();
            if let Err(e) = self.name_one(sc, nm) {
                self.row("!name", &e.to_string());
            }
        }
        for _ in 0..6 {
            if self.syms.is_empty() {
                break;
            }
            let k = self.rng.r(self.syms.len() as u32) as usize;
            let Some(s) = self.syms[k] else { continue };
            let use_scope = self.rand_scope();
            let depth = self.db().resolution_depth(s, Some(use_scope))?;
            let t = format!(
                "{} in {} -> {depth}",
                self.sym_str(Some(s)),
                self.scope_name(use_scope)
            );
            self.row("depth", &t);
        }
        for _ in 0..6 {
            let sc = self.scopes[0];
            let a = self.rand_data();
            let u = self.rand_use();
            const FLS: [u32; 6] = [0, 0x8000, 0x4000, 0x08, 0x8000 | 0x4000, 0x40_0000];
            let fl = FLS[self.rng.r(6) as usize];
            let mut index = self.rng.r(3) as i32;
            let ct = if self.rng.r(4) != 0 {
                Some(self.rand_type())
            } else {
                None
            };
            let types = &self.arch.types;
            let nm = self.db.as_ref().unwrap().build_variable_name(
                sc,
                a,
                u,
                ct,
                &mut index,
                VarnodeFlags::from_bits_retain(fl),
                types,
            )?;
            let t = format!("{} {fl:x} -> {nm} index={index}", self.addr_str(a));
            self.row("buildVariableName", &t);
        }
        Ok(())
    }

    fn query_one(&mut self, sc: ScopeId, a: Address, sz: i32, u: Address, q: &str) -> R<()> {
        let db = self.db.as_ref().unwrap();
        let (kind, text) = match self.rng.r(13) {
            0 => ("queryByAddr", self.entry_str(db.query_by_addr(sc, a, u)?)),
            1 => (
                "queryContainer",
                self.entry_str(db.query_container(sc, a, sz, u)?),
            ),
            2 => {
                let (e, fl) = db.query_properties(sc, a, sz, u)?;
                (
                    "queryProperties",
                    format!("{} flags={:x}", self.entry_str(e), fl.bits()),
                )
            }
            3 => ("findAddr", self.entry_str(db.find_addr(sc, a, u)?)),
            4 => (
                "findContainer",
                self.entry_str(db.find_container(sc, a, sz, u)?),
            ),
            5 => (
                "findClosestFit",
                self.entry_str(db.find_closest_fit(sc, a, sz, u)?),
            ),
            6 => ("findOverlap", self.entry_str(db.find_overlap(sc, a, sz)?)),
            7 => (
                "findSymbolBefore",
                self.entry_str(db.find_symbol_before(sc, a, u)?),
            ),
            8 => (
                "findSymbolAfter",
                self.entry_str(db.find_symbol_after(sc, a, u)?),
            ),
            9 => {
                let t = match db.query_function(sc, a)? {
                    Some(f) => {
                        let fa = db
                            .entry(db.first_whole_map(f)?)?
                            .addr()
                            .unwrap_or(Address::INVALID);
                        format!("{}@{}", self.fd_name(f), self.addr_str(fa))
                    }
                    None => "-".into(),
                };
                ("queryFunction", t)
            }
            10 => ("queryCodeLabel", self.sym_str(db.query_code_label(sc, a)?)),
            11 => {
                let t = match db.query_external_ref_function(sc, a)? {
                    Some(f) => self.fd_name(f),
                    None => "-".into(),
                };
                ("queryExternalRefFunction", t)
            }
            _ => {
                let d = db.discover_scope(sc, a, sz)?;
                let m = db.map_scope(sc, a);
                let dt = match d {
                    Some(d) => format!("{}|{}", db.full_name(d), self.scope_name(d)),
                    None => "-".into(),
                };
                ("discoverScope", format!("{dt} map={}", self.scope_name(m)))
            }
        };
        self.row(kind, &format!("{q}{text}"));
        Ok(())
    }

    fn name_one(&mut self, sc: ScopeId, nm: &str) -> R<()> {
        let scn = self.scope_name(sc);
        match self.rng.r(5) {
            0 => {
                let res = self.db().query_by_name(sc, nm)?;
                let mut t = format!("{scn} {nm} ->");
                for s in res {
                    let _ = write!(t, " {}", self.sym_str(Some(s)));
                }
                self.row("queryByName", &t);
            }
            1 => {
                let used = self.db().is_name_used(sc, nm, None)?;
                self.row("isNameUsed", &format!("{scn} {nm} -> {}", u8::from(used)));
            }
            2 => {
                let r = self.db().make_name_unique(sc, nm)?;
                self.row("makeNameUnique", &format!("{scn} {nm} -> {r}"));
            }
            3 => {
                let r = self.db().build_undefined_name(sc)?;
                self.row("buildUndefinedName", &format!("{scn} -> {r}"));
            }
            _ => {
                const FULL: [&str; 6] = ["ns1::a", "ns1::ns3::b", "::x", "ns9::y", "ns2::f", "a"];
                let full = FULL[self.rng.r(6) as usize];
                let t = match self
                    .db
                    .as_ref()
                    .unwrap()
                    .resolve_scope_from_symbol_name(full, Some(sc))
                {
                    Some((s, base)) => format!("{}|{base}", self.db.as_ref().unwrap().full_name(s)),
                    None => "-".into(),
                };
                self.row(
                    "resolveScopeFromSymbolName",
                    &format!("{scn} {full} -> {t}"),
                );
            }
        }
        Ok(())
    }

    fn dump(&mut self) -> R<()> {
        for i in 0..self.scopes.len() {
            let sc = self.scopes[i];
            let types: &TypeFactory = &self.arch.types;
            let db = self.db.as_ref().unwrap();
            let print = db.print_entries(sc, types)?;
            let mut enc = XmlEncoder::new(true);
            db.encode_scope(sc, &mut enc, types, None)?;
            let xml = enc.into_string();
            let data = db.scope(sc)?;
            let multi: String = data
                .multi_entry()
                .map(|s| format!("{} ", self.sym_str(Some(s))))
                .collect();
            let mut cats = String::new();
            for j in 0..data.category_count() {
                let _ = write!(cats, "[{j}:");
                for slot in data.category(j as i16) {
                    let _ = write!(cats, " {}", self.sym_str(*slot));
                }
                cats.push(']');
            }
            self.row("print", &print);
            self.row("xml", &xml);
            self.row("multi", &multi);
            self.row("cats", &cats);
        }
        let db = self.db.as_ref().unwrap();
        let props: String = db
            .property_points()
            .map(|(a, v)| format!("{}={v:x} ", self.addr_str(a)))
            .collect();
        self.row("props", &props);
        Ok(())
    }
}
