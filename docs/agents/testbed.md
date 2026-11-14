# Track `testbed`: the build host as the project's testbed

Status: in progress (2026-11-14).

The Linux build host (`docs/agents/remote-build.md`) is also where the
checks that are slow or impossible on the development Mac run: Windows
tests under Wine, a newer distribution's GCC, sanitizers, Miri, fuzzing and
property tests at length, the full differential runs, and a nightly run
with a report. All of it is committed scripts under `tools/testbed/`,
started through `scripts/remote.sh`, which stays a thin dispatcher.

## Done / in progress / next

- Done: `remote.sh` plumbing (results copied back, `clean --target`,
  informative `cargo fetch`), `wine` (whole workspace passes), `long miri`,
  `long sanitizers`.
- In progress: `long fuzz` (first 600 s run), `long differential`,
  `long proptest`, `ubuntu`, nightly install and first run.
- Next: measurements into this file, proposed LOOP/RULES text, final gates.
