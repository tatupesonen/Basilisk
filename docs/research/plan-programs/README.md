# Measurements for the programs plan (track `plan-programs`)

Scripts that measure Ghidra's source tree (pinned commit `42db038f3c`,
read-only) and this repository's test checklist, with their output. They
back `docs/features/program-plan.md` and `roadmap-check.md` in this
directory. Run from this directory; `$G` is the Ghidra tree.

| Script | Command | Output | What it measures |
|---|---|---|---|
| `modules.py` | `python3 modules.py $G > modules.tsv` | `modules.tsv` | Every Ghidra module (a directory with `Module.manifest`): Java lines per source set, C, C++, Python and SLEIGH lines, and the `project(':X')` dependencies of its `build.gradle` |
| `packages.py` | `python3 packages.py $G 4 Ghidra/Framework/SoftwareModeling Ghidra/Framework/DB > packages-framework.tsv`; `… 4 Ghidra/Features/Base > packages-base-d4.tsv`; `… 6 Ghidra/Features/Base > packages-base-d6.tsv` | `packages-*.tsv` | Files and lines per Java package of `src/main/java`, folded to a depth |
| `extension-classes.py` | `python3 extension-classes.py $G > extension-classes.tsv` | `extension-classes.tsv` | Every class under the roots `Loader`, `Analyzer`, `ElfRelocationHandler`, `MachoRelocationHandler`, `CoffRelocationHandler`, `ElfExtension`, `Exporter`, `GFileSystem`, `Demangler`, `Command`, `BuiltInDataType` and others, found by following `extends`/`implements` |
| `analyzers.py` | `python3 analyzers.py $G extension-classes.tsv > analyzers.tsv` | `analyzers.tsv` | Each concrete analyzer: type, priority expression, default enablement, and flags for what its file imports (decompiler, emulation, symbolic propagation, PDB, DWARF, demangler, byte patterns, formats, block models) |
| `pkgdeps.py` | `python3 pkgdeps.py $G groups.txt deps` | `deps-groups.tsv`, `deps-edges.tsv`, `deps-scc.txt` | Import dependencies between the package groups of `groups.txt`, resolved per class; the cycles among them |
| `coarse-edges.py` | `python3 coarse-edges.py deps-edges.tsv deps-groups.tsv > coarse-edges.txt` | `coarse-edges.txt` | The same edges folded into coarse buckets (model, program database, formats, analysis, commands, user interface, one per module) |
| `class-uses.py` | `python3 class-uses.py $G Ghidra/Framework/Project Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program > uses-project-by-program.tsv`; the same with `Ghidra/Framework/DB` `> uses-db-by-program.tsv` | `uses-*.tsv` | Which classes of one module a set of source directories imports |
| `processors-java.py` | `python3 processors-java.py $G > processors-java.tsv` | `processors-java.tsv` | Java under `Ghidra/Processors` by kind of class |
| `roadmap-coverage.py` | `python3 roadmap-coverage.py modules.tsv ../../PARITY.md ../../PLAN.md > roadmap-coverage.tsv` | `roadmap-coverage.tsv` | Which module names occur in `PARITY.md` and `PLAN.md` |
| `tests-by-package.py` | `python3 tests-by-package.py ../../inventory/tests 0 > tests-by-package-full.tsv`; `… 4 > tests-by-package.tsv` | `tests-by-package*.tsv` | The test checklist summed by package |
| `tests-select.py` | `python3 tests-select.py tests-by-package-full.tsv > tests-m4-m5.txt` | `tests-m4-m5.txt` | Test classes and `@Test` methods per M4 and M5 area |

Limits, which the documents repeat where a figure is used:

* Lines are physical lines (comments and blank lines included), counted
  as newline bytes.
* Dependencies are **imports**. A use of a class in the same package but
  another module, and a fully qualified name written in code, are not
  seen. Edge counts are a floor.
* `extension-classes.py` matches super types by simple name. Two classes
  of the same simple name in different packages are both listed (for
  example the two `PefAnalyzer`s).
* `analyzers.py` reads the analyzer's own file only: a type or priority
  set by a super class shows as `inherited`, and an import made by a
  helper class is not flagged.
* Nothing here was run through Ghidra: no figure is a run-time
  measurement.
