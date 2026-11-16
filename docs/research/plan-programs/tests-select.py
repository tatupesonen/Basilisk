#!/usr/bin/env python3
"""Sums the test checklist over package prefixes that matter to M4 and M5.

Usage: tests-select.py tests-by-package-full.tsv  > tests-m4-m5.txt
Each row: area, classes, @Test methods, GUI-flagged classes, where found.
"""
import csv, sys
AREAS = [
    ("Framework/DB engine", ["db"]),
    ("program.model.address", ["ghidra.program.model.address"]),
    ("program.model.data + database.data (data types)", ["ghidra.program.model.data", "ghidra.program.database.data", "ghidra.util.data", "ghidra.app.util.cparser", "ghidra.app.util.parser", "ghidra.program.database.dtarchive"]),
    ("program.database.map / mem / model.mem", ["ghidra.program.database.map", "ghidra.program.database.mem", "ghidra.program.model.mem"]),
    ("program.database.code / model.listing", ["ghidra.program.database.code", "ghidra.program.model.listing"]),
    ("program.database.symbol / external / model.symbol", ["ghidra.program.database.symbol", "ghidra.program.database.external", "ghidra.program.model.symbol"]),
    ("program.database.references", ["ghidra.program.database.references"]),
    ("program.database.function", ["ghidra.program.database.function"]),
    ("program.database: properties, bookmark, module, register, reloc, util, sourcemap, root", ["ghidra.program.database.properties", "ghidra.program.database.bookmark", "ghidra.program.database.module", "ghidra.program.database.register", "ghidra.program.database.reloc", "ghidra.program.database.util", "ghidra.program.database.sourcemap", "ghidra.program.database"]),
    ("program.util (both modules)", ["ghidra.program.util"]),
    ("program.model: lang, pcode, scalar, util, block", ["ghidra.program.model.lang", "ghidra.program.model.pcode", "ghidra.program.model.scalar", "ghidra.program.model.util", "ghidra.program.model.block"]),
    ("framework.data / options / model (domain objects, options)", ["ghidra.framework.data", "ghidra.framework.options", "ghidra.framework.model"]),
    ("app.util.bin (readers, formats)", ["ghidra.app.util.bin"]),
    ("app.util.opinion + importer (loaders)", ["ghidra.app.util.opinion", "ghidra.app.util.importer", "ghidra.plugin.importer", "ghidra.plugins.importer"]),
    ("program.disassemble + app.cmd.disassemble", ["ghidra.program.disassemble", "ghidra.app.cmd.disassemble", "ghidra.app.plugin.core.disassembler"]),
    ("app.cmd.* (commands)", ["ghidra.app.cmd"]),
    ("app.plugin.core.analysis + analyzers", ["ghidra.app.plugin.core.analysis", "ghidra.app.analyzers", "ghidra.app.plugin.core.function", "ghidra.app.plugin.core.string", "ghidra.app.plugin.core.strings", "ghidra.app.plugin.prototype", "ghidra.app.plugin.exceptionhandlers"]),
    ("app.util.headless + script", ["ghidra.app.util.headless", "ghidra.app.script"]),
    ("app.util.demangler", ["ghidra.app.util.demangler"]),
    ("app.util.exporter + xml", ["ghidra.app.util.exporter", "ghidra.app.util.xml"]),
    ("app.merge (program merge)", ["ghidra.app.merge"]),
]
rows = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
used = set()
for name, prefs in AREAS:
    c = t = g = 0
    where = {}
    for i, r in enumerate(rows):
        if i in used:
            continue
        p = r["package"]
        if any(p == x or p.startswith(x + ".") for x in prefs):
            used.add(i)
            c += int(r["classes"]); t += int(r["tests"]); g += int(r["gui_classes"])
            where[r["file"]] = where.get(r["file"], 0) + int(r["classes"])
    print(f"{name}\t{c}\t{t}\t{g}\t" + ", ".join(f"{k} {v}" for k, v in sorted(where.items())))
