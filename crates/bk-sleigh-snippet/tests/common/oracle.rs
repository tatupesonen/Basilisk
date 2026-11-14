//! Snippet records run through the `snippetdump` oracle (its wrapper is
//! `bk_testkit::tools::Snippetdump`) and through Basilisk.

use std::path::Path;

use bk_sleigh_snippet::{Parameter, SnippetCompiler, SnippetError, TempAllocator};
use bk_testkit::ReferenceDir;
pub(crate) use bk_testkit::tools::snippetdump::{SnippetBase as Base, SnippetOutcome as Outcome};
use bk_testkit::tools::snippetdump::{SnippetParameter, SnippetRecord};

/// One snippet to compile.
#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub(crate) source: String,
    pub(crate) base: Base,
    pub(crate) body: String,
    pub(crate) params: Vec<Parameter>,
}

impl Record {
    fn to_oracle(&self) -> SnippetRecord {
        SnippetRecord {
            source: self.source.clone(),
            base: self.base,
            body: self.body.clone(),
            params: self
                .params
                .iter()
                .map(|p| SnippetParameter {
                    index: p.index,
                    name: p.name.clone(),
                })
                .collect(),
        }
    }
}

/// Runs the oracle on `records` for language `id` under `root`.
pub(crate) fn run_oracle(
    reference: &ReferenceDir,
    root: &Path,
    id: &str,
    records: &[Record],
) -> Vec<Outcome> {
    let records: Vec<SnippetRecord> = records.iter().map(Record::to_oracle).collect();
    reference
        .snippetdump()
        .root(root)
        .compile(id, &records)
        .unwrap_or_else(|e| panic!("snippetdump {id}: {e}"))
}

/// Runs `records` through Basilisk with the oracle's base rules, starting
/// the carried base at `start`.
pub(crate) fn run_basilisk(
    compiler: &SnippetCompiler,
    start: u32,
    records: &[Record],
) -> Vec<Outcome> {
    let mut carried = TempAllocator::new(start);
    records
        .iter()
        .map(|r| {
            let mut fixed;
            let temps = match r.base {
                Base::Continue => &mut carried,
                Base::Start(b) => {
                    carried = TempAllocator::new(b);
                    &mut carried
                }
                Base::Fixed(b) => {
                    fixed = TempAllocator::new(b);
                    &mut fixed
                }
            };
            let base = temps.next;
            match compiler.compile(&r.body, &r.params, temps) {
                Ok(compiled) => Outcome::Ok {
                    base,
                    next: temps.next,
                    first_error: compiled.warnings.first().cloned(),
                    xml: compiled.template.encode_xml(compiler.space_table()),
                },
                Err(SnippetError::Aborted { message, .. }) => Outcome::Exception { base, message },
                Err(e) => Outcome::Rejected {
                    base,
                    message: e.messages().first().cloned().unwrap_or_default(),
                },
            }
        })
        .collect()
}
