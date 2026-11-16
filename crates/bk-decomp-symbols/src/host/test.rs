//! A host that answers from tables and records every call (spec 5.4), so
//! tests can assert what the cache layer asked and in which order.

use std::collections::BTreeMap;
use std::sync::Mutex;

use bk_context::TrackedValue;
use bk_core::{Address, Provenance};
use bk_cspec::FunctionSummary;
use bk_decomp_types::TypeId;

use super::{HostNamespace, HostReply, HostString, HostSymbol, ProgramHost};
use crate::comment::Comment;
use crate::cpool::CPoolRecord;
use crate::error::{DataUnavail, HostError};

/// Answers from tables; every call is appended to [`calls`](Self::calls).
#[derive(Debug, Default)]
pub struct ScriptedHost {
    /// Replies to `mapped_symbol` by address.
    pub mapped: BTreeMap<Address, HostReply>,
    /// Replies to `external_ref` by address.
    pub external: BTreeMap<Address, HostSymbol>,
    /// Namespace paths by scope id.
    pub paths: BTreeMap<u64, Vec<HostNamespace>>,
    /// Names the host says are used.
    pub used_names: Vec<String>,
    /// Code labels by address.
    pub labels: BTreeMap<Address, String>,
    /// Comments (all functions).
    pub comments: Vec<Comment>,
    /// Bytes by start address.
    pub bytes: BTreeMap<Address, Vec<u8>>,
    /// Strings by address.
    pub strings: BTreeMap<Address, HostString>,
    /// Constant-pool records by first reference.
    pub cpool: BTreeMap<u64, CPoolRecord>,
    /// Tracked sets by address.
    pub tracked: BTreeMap<Address, Vec<TrackedValue>>,
    /// Function summaries by entry.
    pub summaries: BTreeMap<Address, FunctionSummary>,
    /// "Does it return" answers by call site.
    pub returns: BTreeMap<Address, bool>,
    calls: Mutex<Vec<String>>,
}

impl ScriptedHost {
    /// An empty host.
    pub fn new() -> Self {
        Self::default()
    }

    fn log(&self, call: String) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }

    /// The calls made so far, in order (`name(args)`).
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Forgets the calls made so far.
    pub fn clear_calls(&self) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.clear();
        }
    }
}

fn a(addr: Address) -> String {
    format!(
        "{:?}:{:#x}",
        addr.space().map(bk_core::SpaceId::index),
        addr.offset()
    )
}

impl ProgramHost for ScriptedHost {
    fn mapped_symbol(&self, addr: Address) -> Result<HostReply, HostError> {
        self.log(format!("mapped_symbol({})", a(addr)));
        Ok(self
            .mapped
            .get(&addr)
            .cloned()
            .unwrap_or(HostReply::Nothing))
    }
    fn external_ref(&self, addr: Address) -> Result<Option<HostSymbol>, HostError> {
        self.log(format!("external_ref({})", a(addr)));
        Ok(self.external.get(&addr).cloned())
    }
    fn namespace_path(&self, scope: u64) -> Result<Vec<HostNamespace>, HostError> {
        self.log(format!("namespace_path({scope:#x})"));
        self.paths
            .get(&scope)
            .cloned()
            .ok_or_else(|| HostError::Failed("Could not get namespace info".into()))
    }
    fn is_name_used(&self, name: &str, start: u64, stop: u64) -> Result<bool, HostError> {
        self.log(format!("is_name_used({name},{start:#x},{stop:#x})"));
        Ok(self.used_names.iter().any(|n| n == name))
    }
    fn code_label(&self, addr: Address) -> Result<Option<(String, Provenance)>, HostError> {
        self.log(format!("code_label({})", a(addr)));
        Ok(self
            .labels
            .get(&addr)
            .map(|n| (n.clone(), Provenance::User)))
    }
    fn comments(&self, function: Address, mask: u32) -> Result<Vec<Comment>, HostError> {
        self.log(format!("comments({},{mask:#x})", a(function)));
        Ok(self
            .comments
            .iter()
            .filter(|c| c.func_addr == function && c.kind & mask != 0)
            .cloned()
            .collect())
    }
    fn bytes(&self, addr: Address, buf: &mut [u8]) -> Result<(), DataUnavail> {
        self.log(format!("bytes({},{})", a(addr), buf.len()));
        let hit = self
            .bytes
            .range(..=addr)
            .next_back()
            .and_then(|(start, data)| {
                let off = usize::try_from(addr.offset().checked_sub(start.offset())?).ok()?;
                (start.space() == addr.space()).then_some(())?;
                data.get(off..off + buf.len())
            });
        match hit {
            Some(src) => {
                buf.copy_from_slice(src);
                Ok(())
            }
            None => Err(DataUnavail {
                addr,
                message: HostError::NoData(a(addr)).to_string(),
            }),
        }
    }
    fn string_data(
        &self,
        addr: Address,
        char_type: TypeId,
        max_bytes: usize,
    ) -> Result<Option<HostString>, HostError> {
        self.log(format!(
            "string_data({},{},{max_bytes})",
            a(addr),
            char_type.index()
        ));
        Ok(self.strings.get(&addr).cloned())
    }
    fn cpool_record(&self, refs: &[u64]) -> Result<Option<CPoolRecord>, HostError> {
        self.log(format!("cpool_record({refs:?})"));
        Ok(refs.first().and_then(|r| self.cpool.get(r)).cloned())
    }
    fn tracked_registers(&self, addr: Address) -> Result<Vec<TrackedValue>, HostError> {
        self.log(format!("tracked_registers({})", a(addr)));
        Ok(self.tracked.get(&addr).cloned().unwrap_or_default())
    }
    fn function_summary(&self, callee: Address) -> Option<FunctionSummary> {
        self.log(format!("function_summary({})", a(callee)));
        self.summaries.get(&callee).cloned()
    }
    fn call_returns(&self, call_site: Address, callee: Option<Address>) -> Option<bool> {
        self.log(format!(
            "call_returns({},{:?})",
            a(call_site),
            callee.map(a)
        ));
        self.returns.get(&call_site).copied()
    }
}
