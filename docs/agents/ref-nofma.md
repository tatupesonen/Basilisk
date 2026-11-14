# Track `ref-nofma` — status

Reference build with `-ffp-contract=off` (ADR-032).

## Done
- `scripts/build-reference.sh`: `-ffp-contract=off` on every compile
  (Makefile `ADDITIONAL_FLAGS`, `pcodedump`, zlib), recorded in `STAMP`
  (`fp_flags`, `zlib_cflags`, `make_overrides`).

## In progress
- Staging build into `/Users/tatu/slop/reference.staging`
  (`BASILISK_REFERENCE_DIR`), then verification.

## State of `/Users/tatu/slop/reference`
Untouched (old AArch64-fused build of 2026-11-12).
