# Why the reference `pcodedump` segfaults

Track `ref-nofma`, 2026-11-14. Two tracks saw Ghidra's C++ engine, run
through the reference `pcodedump`, die with SIGSEGV: `sla-host-diff` on
2 MB of seeded random `mips32le` bytes, and `sleigh-decode` 36 times in
its directed sweeps (SPARC 32 and 64: 30, ARM v8-m LE/BE: 5, MIPS micro
BE: 1), described there as "a delay-slot instruction with an `unimpl`
body". This note gives minimal reproducers, the faulting code, and what
basilisk does instead.

Ghidra commit `42db038f3c`; `CPP` =
`Ghidra/Features/Decompiler/src/decompile/cpp`. Reference tools:
`/Users/tatu/slop/reference` (macOS arm64, Apple clang 17,
`-ffp-contract=off`). Each claim is marked **[measured]**, **[source]** or
**[judgement]**.

## Reproducers [measured]

`R=/Users/tatu/slop/reference`; each command exits with status 139
(SIGSEGV) and prints nothing (the crash comes before the output buffer is
flushed):

| Language | Bytes (`--hex`) | Instructions |
|---|---|---|
| `sparc:BE:32:default` | `1080000081b80000` | `ba` (delay slot of 1) + `impdef2` (`op=2 & op3=0x37`, `SparcV9.sinc:1058`, declared `unimpl`) |
| `sparc:BE:64:default` | `1080000081b80000` | the same |
| `sparc:BE:64:default` | `02c0400081b80000` | `brz,pn %g1` + `impdef2` |
| `MIPS:LE:32:default` | `080000106ecac546` | `b` (`beq zero,zero`) + `pul.ps f9,f25,f5` (`mips32Instructions.sinc:1257`, a constructor with no semantic section) |

```
$R/bin/pcodedump $R sparc:BE:32:default 0x10000 --hex 1080000081b80000; echo $?   # 139
```

Each half alone decodes fine: `--hex 81b80000` prints `impdef2` with a
`U unimplemented` record and exits 0; a branch followed by a nop exits 0.

**The `mips32le` random crash is the same case.** The input of
`tools/sla-host-diff/scripts/pcodedump-compare.sh` (`random.Random("mips32le")`,
2 MiB, base `0x10000`) crashes at `0x202e74` (found with `lldb` on a debug
build, below): the bytes there are `487d6a14 6ecac546`, `bne v1,t2,…`
with `pul.ps` in its delay slot. `--hex 487d6a146ecac546` at base
`0x202e74` reproduces it alone; the minimal form is the table's last row.

**ARM v8-m: not reproduced, and probably a different cause.** ARM's
SLEIGH has no `delayslot` directive at all (`grep -r delayslot
Ghidra/Processors/ARM` is empty) and no `crossbuild`, so the mechanism
below cannot apply to it. Sweeps tried without a crash: 3 × 2 MiB random
in Thumb (the `.pspec` default) and ARM mode, LE and BE; every Thumb-2
first halfword `0xe800–0xffff` × 32 random second halfwords; 800 kB with
each of `TEEMode`, `itmode`, `condit`, `LRset`, `REToverride`,
`CALLoverride`, `counter`, `counter2`, `regNum`, `reg2Num`, `regInc`,
`sdOv`, `ARMcond`, `ARMcondCk` set. `sleigh-decode`'s directed sweeps set
context variables from the constructors' context patterns, so its 5 cases
probably need a configuration not tried here. Its harness records the
bytes and configuration of each crash
(`crates/bk-sleigh/tests/common/coverage.rs`, `oracle_crashes`) but does
not save them; rerunning that test prints them. **Follow-up:** get those
5 cases from the harness and run them under `lldb` as below. The MIPS
micro case was not reproduced either. MIPS micro does use `delayslot`
(`mipsmicro.sinc`), so it is very likely the same bug, but that is not
verified.

## The faulting code [source, measured]

`Sleigh::oneInstruction` (`CPP/sleigh.cc:717–769`) builds an
instruction's p-code with a `SleighBuilder` whose current walker starts
out as the instruction's own `ParserWalker`. A `delayslot` op calls
`SleighBuilder::delaySlot` (`sleigh.cc:344–373`), which builds each
delay-slot instruction with a **walker on its own stack frame**:

```cpp
    ParserWalker newwalker( pos );          // sleigh.cc:364
    walker = &newwalker;                    // :365
    walker->baseState();
    build(walker->getConstructor()->getTempl(),-1); // :367
    ...
  walker = tmp;			// Restore original context   :371
```

When the delay-slot constructor has no template (`unimpl`, or no semantic
section), `PcodeBuilder::build` throws `UnimplError`
(`CPP/semantics.cc:1045`). The exception leaves `delaySlot` before `:371`,
so `builder.walker` still points at `newwalker`, whose frame is gone.
`oneInstruction`'s handler then uses it to build its message:

```cpp
  } catch(UnimplError &err) {
    ...
    ParserWalker *cur = builder.getCurrentWalker();   // sleigh.cc:756, dangling
    cur->baseState();                                  // :757, writes to a dead frame
    Constructor *ct = cur->getConstructor();           // :758, faults
```

A debug build of the same sources (copied from `$R/src`, `-O0 -g`,
linked with `tools/reference/pcodedump.cc`) stops in `lldb` with
`EXC_BAD_ACCESS` in `ParserWalker::getConstructor` (`context.hh:182`,
`point->ct`) called from `sleigh.cc:758`. That holds for both the SPARC
reproducer and the 2 MiB MIPS input; `cur` is a stack address below the
live frames. (An AddressSanitizer build hangs in ASan's own start-up on
this macOS (`InitializeShadowMemory` spinning), so the evidence comes from
`lldb`.) What the handler reads is undefined behaviour: with other stack
contents it could print garbage instead of crashing.

`appendCrossBuild` (`sleigh.cc:388–415`) has the same pattern
(`ParserWalker newwalker` at `:403`, restored at `:413` with no
`try`). It handles a missing named section itself (`buildEmpty`), but an
`UnimplError` from a nested constructor of the crossbuilt instruction
would leave the same dangling walker. Only Hexagon uses `crossbuild`.
No crash from it has been seen; this is the same defect, found by reading.

**One bug** for SPARC, the `mips32le` random crash and (very likely) MIPS
micro: an exception that escapes `delaySlot` without restoring the
builder's walker. ARM v8-m is not explained by it (see above). The
decompiler (`decomp`, `decomp_test`) and anything else that calls
`Sleigh::oneInstruction` should crash the same way on such code
[judgement; not run]. The cause is in Ghidra, not in `pcodedump`. Ghidra's
Java engine was not examined.

## What basilisk does instead (ADR-009)

basilisk must not crash, and should give the result Ghidra evidently
meant to give:

* Lifting an instruction whose delay slot (at any depth, including an
  operand subconstructor of the delay-slot instruction) has no semantics
  is an ordinary error result: "instruction not implemented in p-code",
  with the instruction length set to the full flow length (the
  instruction plus its delay slots, which is what `oneInstruction` puts
  in `err.instruction_length`). The message names the innermost
  instruction that had no semantics, at its own address. That is what
  `getCurrentWalker()` was meant to return in the handler (for an
  `unimpl` outside a delay slot, Ghidra prints the instruction's own
  address and text).
* The walker for a delay-slot or crossbuilt instruction is a value whose
  lifetime the borrow checker ties to the build. There is no saved
  pointer to restore, so an early return (`?`) cannot leave stale state.
* In `pcodedump` terms the expected record is `I` for the branch with
  its flow length, then `U unimplemented …`, as for any unimplemented
  instruction. Until the oracle is fixed, a differential harness cannot
  get Ghidra's output for these instructions and has to list them as
  oracle crashes, as `sleigh-decode`'s harness already does (it locates
  the instruction by bisection and splits the stream there). Do not
  patch the reference tool for this: the harness's workaround is enough,
  and a patched oracle would no longer be Ghidra.
* A regression test belongs to `sleigh-pcode`: the SPARC and MIPS byte
  strings above, lifted without a crash, giving the error just described.

Upstream report (proposed): "SIGSEGV in `Sleigh::oneInstruction`'s
`UnimplError` handler when an unimplemented instruction is in a delay
slot", with the reproducers above. The fix is to restore `walker` in
`SleighBuilder::delaySlot` and `appendCrossBuild` on every exit, either
with a scope guard or by catching, restoring and rethrowing.
