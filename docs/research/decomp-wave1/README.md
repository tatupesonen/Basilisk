# Research notes for the decompiler's first-wave specs (D00, D04)

Scratch evidence behind `docs/features/decomp-oracle.md` and
`docs/features/decomp-cfg.md`. Track report: `docs/agents/spec-decomp-wave1.md`.

| File | What it is |
|---|---|
| `gen_graphs.py` | Random control-flow graphs in the XML form `structure blocks` reads (`BlockGraph::decode`): `python3 -I gen_graphs.py SEED COUNT MAXNODES OUTDIR` |
| `runs.md` | Commands run against the reference console and what they printed |
