# Decompiler oracle captures (`docs/features/decomp-oracle.md` 4.14, 4.15)

What `bk-oracle capture all <out>` produced on the two reference builds,
Ghidra commit `42db038f3c`. The captures themselves (about 160 MB) are not
checked in: they are regenerated wherever the reference tools with the
console extension exist, and compared with these files.

| File | What it is | Made on |
|---|---|---|
| `summary.txt` | Per script and per decompilation: function, ops and varnodes checked against `print raw` / `print tree varnode`, pointer-valued varnodes, trace records, structuring runs, status; totals last | macOS arm64 (Apple clang 17, libc++); identical on x86-64 Linux |
| `captures.libcxx.txt` | One FNV-1a digest per script and kind of capture (`state`, `raw`, `trace`, `structure`, `pcoderec`) | macOS arm64, libc++ |
| `captures.libstdcxx.txt` | The same | x86-64 Linux build host (Debian g++ 14.2, libstdc++) |
| `hostdiff.txt` | Every line where the two builds' captures differ, by file and named cause, with totals (`bk-oracle compare`) | both |

Regenerate (each capture runs twice and must be byte-identical):

```
cargo run -p bk-testkit --bin bk-oracle -- capture all target/oracle-cap
cargo run -p bk-testkit --bin bk-oracle -- check target/oracle-cap fixtures/decomp-oracle
```

On the build host the same commands run through `scripts/remote.sh run`
(and nightly as the `oracle` item of `tools/testbed/nightly.sh`); its
`target/…/run1` is compared with the Mac's by `bk-oracle compare`.
`crates/bk-testkit/tests/oracle_state.rs` checks that the files agree with
each other (the differing groups are exactly those `hostdiff.txt` explains;
the cause counts are pinned) and, where the reference has the extension,
that a fresh capture of four data tests matches the fixture of that build.
