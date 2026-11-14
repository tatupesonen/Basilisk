//! Shared helpers for the integration tests.

use bk_decomp_types::{DataOrganization, TypeEnv, TypeFactory, TypeId, cdecl};

/// The `<data_organization>` of `x86-64-gcc.cspec`, as Ghidra's file has
/// it (copied so the test needs no spec root).
pub const X86_64_GCC_ORG: &str = r#"<compiler_spec><data_organization>
     <machine_alignment value="2" />
     <default_alignment value="1" />
     <default_pointer_alignment value="8" />
     <pointer_size value="8" />
     <wchar_size value="4" />
     <short_size value="2" />
     <integer_size value="4" />
     <long_size value="8" />
     <long_long_size value="8" />
     <float_size value="4" />
     <double_size value="8" />
     <long_double_size value="10" />
     <size_alignment_map>
          <entry size="1" alignment="1" />
          <entry size="2" alignment="2" />
          <entry size="4" alignment="4" />
          <entry size="8" alignment="8" />
          <entry size="16" alignment="16" />
     </size_alignment_map>
  </data_organization></compiler_spec>"#;

/// The facts of `x86:LE:64:default:gcc`: 8-byte pointers, word size 1,
/// little endian, 8-byte stack pointer, `max_basetype_size` 10.
pub fn x86_64_env() -> TypeEnv {
    let mut env = TypeEnv::simple(8, false);
    env.default_model = Some("__stdcall".to_owned());
    env
}

/// A factory as `x86:LE:64:default:gcc` builds it, with the default core
/// types.
pub fn x86_64_factory() -> TypeFactory {
    let env = x86_64_env();
    let org = DataOrganization::from_cspec(X86_64_GCC_ORG, &env).unwrap();
    TypeFactory::with_core_types(env, org).unwrap()
}

/// `parse_type` with no models, panicking on error.
pub fn parse(f: &mut TypeFactory, text: &str) -> TypeId {
    cdecl::parse_type(f, text, &cdecl::no_models)
        .unwrap_or_else(|e| panic!("parse {text:?}: {e}"))
        .0
}
