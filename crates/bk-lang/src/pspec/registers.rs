//! `<register_data>`: per-register presentation and properties.

use roxmltree::Node;

use crate::{
    error::ParseError,
    reader::{Reader, children_named},
    schema::{REGISTER, REGISTER_DATA},
    value::{decode_i32, java_split},
};

/// One `<register>` of `<register_data>`.
///
/// Entries apply in file order, and a `rename` takes effect at its entry:
/// later entries (and everything else in the file, and the compiler specs)
/// must use the new name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterData {
    /// The register's name in the SLEIGH spec.
    pub name: String,
    /// The name the register gets instead.
    pub rename: Option<String>,
    /// An additional name for the register.
    pub alias: Option<String>,
    /// The group the register is listed under.
    pub group: Option<String>,
    /// Whether the register is hidden from the user.
    pub hidden: bool,
    /// Whether the register's storage is volatile.
    pub volatile: bool,
    /// The lane sizes in bytes the register can be split into as a vector;
    /// empty when the register is not a vector register.
    pub vector_lane_sizes: Vec<u32>,
}

impl RegisterData {
    /// The name the register goes by after this entry: its `rename`, or
    /// its own name.
    #[must_use]
    pub fn effective_name(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }

    /// Whether `size` is one of the register's vector lane sizes.
    #[must_use]
    pub fn is_valid_lane_size(&self, size: u32) -> bool {
        self.vector_lane_sizes.contains(&size)
    }
}

/// Reads a `<register_data>` element, appending its entries in file order.
pub(crate) fn read(
    r: &mut Reader<'_, '_>,
    node: Node<'_, '_>,
    registers: &mut Vec<RegisterData>,
) -> Result<(), ParseError> {
    r.check(node, &REGISTER_DATA)?;
    for reg in children_named(node, REGISTER.name) {
        r.check(reg, &REGISTER)?;
        let vector_lane_sizes = match reg.attribute("vector_lane_sizes") {
            None => Vec::new(),
            Some(sizes) => java_split(sizes, ',')
                .map(|lane| {
                    decode_i32(lane.trim_matches(|c: char| c <= ' '))
                        .and_then(|v| u32::try_from(v).ok())
                })
                .collect::<Option<Vec<u32>>>()
                .ok_or_else(|| {
                    r.invalid(
                        reg,
                        &REGISTER,
                        "vector_lane_sizes",
                        sizes,
                        "a comma-separated list of lane sizes",
                    )
                })?,
        };
        registers.push(RegisterData {
            name: r.required(reg, &REGISTER, "name")?.to_owned(),
            rename: reg.attribute("rename").map(str::to_owned),
            alias: reg.attribute("alias").map(str::to_owned),
            group: reg.attribute("group").map(str::to_owned),
            hidden: Reader::flag(reg, "hidden"),
            volatile: Reader::flag(reg, "volatile"),
            vector_lane_sizes,
        });
    }
    Ok(())
}
