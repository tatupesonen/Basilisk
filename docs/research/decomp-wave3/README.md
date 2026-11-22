# Research notes for the decompiler's third-wave specs (D07, D08)

Evidence behind `docs/features/decomp-core.md`, `docs/features/decomp-typeop.md`
and the plan comparison in `docs/agents/spec-decomp-wave3.md`. The
prototypes are throw-away (`docs/agents/RULES.md`): each is replaced by a
generator under `tools/reference/` in the track that uses it, and removed
from `master` when that track merges.

| File | What it is |
|---|---|
| `build.sh` | Builds one prototype against a reference build's optimised objects, with the Makefile's flags plus `-fno-access-control`: `sh build.sh REF SRC.cc OUT` (build in a scratch directory under `target/`, never in the reference) |
| `action_oracle.cc` | Ghidra's action framework (`Action::perform`, groups, the restart group, pools, breakpoints, specifiers, `clone`, `print`) on random trees of scripted actions and rules over the raw p-code of one data-test function |
| `option_oracle.cc` | Every option of `OptionDatabase` with a pool of parameters, and the configuration each command leaves behind (as changed keys), then what `resetDefaults` restores |
| `typeop_oracle.cc` | D08's oracle prototype: the type-operator table, both cast strategies, the per-opcode type answers over a grid of 39 operand types, integer promotion, call and return typing, and union scoring, for one architecture per run (`docs/features/decomp-typeop.md` 6.2; runs.md X8) |
| `plan_graph.py`, `plan_graph.txt` | Reference graph of the decompiler sources by track of `decomp-plan.md`: sizes, a track-by-track matrix of uses, the names behind each pair, the members of the D07 files with the later-track names each uses, and the users of each D07 member by track |
| `list-actions.txt` | `bk list actions` for the six root actions and `list action` for `decompile`, from `decomp_bk` |
| `runs.md` | What was run, where, and what it printed |
