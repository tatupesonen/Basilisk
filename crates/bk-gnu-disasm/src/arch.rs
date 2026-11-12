//! GNU architecture names, resolved as `gdis` resolves them.

use bk_binutils_sys::{ArchInfo, architecture_names, scan_architecture};

use crate::Error;

/// A binutils architecture and machine: what a GNU name in Ghidra's
/// `.ldefs` files (`external_name tool="gnu"`) stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Architecture {
    name: String,
    arch: u32,
    mach: u64,
    info: Option<ArchInfo>,
}

impl Architecture {
    /// Resolves a GNU architecture name.
    ///
    /// As in `gdis`: a name of the form `0x<arch>:0x<mach>` gives BFD's
    /// architecture and machine numbers in hexadecimal; any other name must
    /// be one of the names binutils lists ([`Architecture::names`]), and
    /// stands for the architecture and machine `bfd_scan_arch` finds for
    /// it. Beyond `gdis`, other names `bfd_scan_arch` accepts (aliases such
    /// as `tic4x` or `x86-64`) resolve as it resolves them.
    pub fn from_gnu_name(name: &str) -> Result<Self, Error> {
        if let Some(numeric) = name.strip_prefix("0x") {
            return Self::from_numeric(name, numeric);
        }
        let listed = architecture_names()?;
        let is_listed = listed.iter().any(|n| n == name);
        match scan_architecture(name)? {
            Some(info) => Ok(Self {
                name: name.to_owned(),
                arch: info.arch,
                mach: info.mach,
                info: Some(info),
            }),
            None if is_listed => Err(Error::UnresolvableArchitecture {
                name: name.to_owned(),
            }),
            None => Err(Error::UnknownArchitecture {
                name: name.to_owned(),
                available: listed,
            }),
        }
    }

    /// An architecture by BFD's numbers (`enum bfd_architecture` of binutils
    /// 2.41, and a machine number of it).
    pub fn from_numbers(arch: u32, mach: u64) -> Self {
        Self {
            name: format!("0x{arch:x}:0x{mach:x}"),
            arch,
            mach,
            info: None,
        }
    }

    /// `gdis` reads `0x<arch>` with `%X` and the machine with `%lX`; Ghidra
    /// splits the name at the colon.
    fn from_numeric(name: &str, numeric: &str) -> Result<Self, Error> {
        let bad = || Error::BadNumericArchitecture {
            text: name.to_owned(),
        };
        let (arch, mach) = numeric.split_once(':').ok_or_else(bad)?;
        let mach = mach.strip_prefix("0x").unwrap_or(mach);
        let arch = u32::from_str_radix(arch, 16).map_err(|_e| bad())?;
        let mach = u64::from_str_radix(mach, 16).map_err(|_e| bad())?;
        Ok(Self {
            name: name.to_owned(),
            arch,
            mach,
            info: None,
        })
    }

    /// Every architecture name binutils lists (`bfd_arch_list`), in its
    /// order: the names [`Architecture::from_gnu_name`] accepts as `gdis`
    /// does.
    pub fn names() -> Result<Vec<String>, Error> {
        Ok(architecture_names()?)
    }

    /// The name this architecture was resolved from.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// BFD's architecture number.
    pub fn arch(&self) -> u32 {
        self.arch
    }

    /// BFD's machine number.
    pub fn mach(&self) -> u64 {
        self.mach
    }

    /// What BFD says about the architecture, when it was resolved by name.
    pub fn info(&self) -> Option<&ArchInfo> {
        self.info.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_names_parse_as_gdis_reads_them() {
        let a = Architecture::from_gnu_name("0x18:0x5").unwrap();
        assert_eq!((a.arch(), a.mach()), (0x18, 5));
        assert_eq!(a.name(), "0x18:0x5");
        let a = Architecture::from_gnu_name("0xA:3f").unwrap();
        assert_eq!((a.arch(), a.mach()), (0xa, 0x3f));
        for bad in ["0x18", "0x:0x1", "0x1g:0", "0x1:0xz", "0x100000000:0"] {
            assert_eq!(
                Architecture::from_gnu_name(bad),
                Err(Error::BadNumericArchitecture {
                    text: bad.to_owned()
                }),
                "{bad}"
            );
        }
        assert_eq!(Architecture::from_numbers(3, 0x10).name(), "0x3:0x10");
    }
}
