# ELF fixtures

Small ELF files produced by real toolchains, so that `bk-elf` is checked
against output it did not write itself. Regenerate with `./generate.sh`
(clang and rust-lld; the files here were made with Apple clang 17.0.0 and
rust-lld from LLD 22.1.6, rustup toolchain 1.97.1, on 2026-11-12).

Sources: `lib.c` (pointer tables for relative relocations, a call through
the PLT and a data reference to another library), `dep.c` with version
script `dep.map` (versions `DEP_1.0`, `DEP_2.0`).

| File | Made by | What it covers |
|---|---|---|
| `rela-x86_64.o` | `clang -target x86_64-linux-gnu -fPIC -c` | relocatable file, `SHT_RELA`, `.symtab` |
| `rel-i686.o` | `clang -target i686-linux-gnu` | 32-bit relocatable, `SHT_REL` |
| `zdebug-x86_64.o` | `clang -g -gz=zlib` | `SHF_COMPRESSED` debug sections |
| `libdep-x86_64.so` | lld with `--version-script` | `.gnu.version`, `.gnu.version_d` |
| `plain-*.so` | lld, no packing | `RELA`/`REL` dynamic tables, `.gnu.version_r`, `DT_HASH` (`i686`, `arm`, `armbe`), `DT_GNU_HASH` (others), build id (`x86_64`) |
| `relr-*.so` | lld `-z pack-relative-relocs` | `SHT_RELR` / `DT_RELR`, 32- and 64-bit, both byte orders |
| `aps2-aarch64.so`, `aps2-arm.so`, `aps2-armbe.so` | lld `--pack-dyn-relocs=android` | Android `APS2` tables, `RELA` and `REL`, both byte orders |
| `aps2-relr-aarch64.so` | lld `--pack-dyn-relocs=android+relr --use-android-relr-tags` | `APS2` together with `SHT_ANDROID_RELR` / `DT_ANDROID_RELR` |

Targets: x86-64, i686, AArch64 (Android), ARMv7 (Android), AArch64 big-endian,
ARMv7 big-endian. Each `relr-`/`aps2-` file has a `plain-` twin linked from
the same objects without packing; `tests/packed_relocations.rs` checks that
the packed tables decode to the twin's relocations.
