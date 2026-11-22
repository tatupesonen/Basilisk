#!/usr/bin/env python3
"""Reference graph of Ghidra's decompiler sources, by track of decomp-plan.md.

usage: plan_graph.py CPP_DIR > plan_graph.txt

CPP_DIR is Ghidra/Features/Decompiler/src/decompile/cpp (read-only).

Method.  Every .cc file is cut into segments at each definition that starts
in column 0 and has the form `... Class::member(`; a segment belongs to
`Class`.  A segment is given to a track by (1) a rule for the member, (2) a
rule for the class, (3) the file's track, in that order (tables below, taken
from the track table of docs/features/decomp-plan.md section 5 and its
amendments).  Headers are given to the track of the classes they declare.
Then, for every segment, the script counts
  * the names of classes declared in headers (word matches), and
  * calls of members (`name(` word matches of member functions whose name
    is declared in exactly one class of the headers),
and adds each count to the pair (track of the segment, track that owns the
class or the member).  The output is the size of each track, the matrix of
references between tracks, and for chosen pairs the names behind the count.

This is a text scan, not a compiler: a name in a comment counts, and an
overloaded or commonly named member (`clear`, `encode`) is left out of the
member scan.  It is evidence for "track A uses things track B owns", not a
proof of the absence of a use.
"""
import collections
import os
import re
import sys

CPP = sys.argv[1]

# ---- file -> track (plan section 5; "bk-" = already ported outside M3) ----
FILE_TRACK = {
    "rangeutil": "D13",  # CircleRange is D01 by class rule
    "type": "D02", "metatype": "D02", "grammar": "D02",
    "fspec": "D03", "modelrules": "D03",
    "block": "D04", "blockaction": "D04",
    "varnode": "D05", "op": "D05", "cover": "D05",
    "database": "D06", "comment": "D06", "stringmanage": "D06", "cpool": "D06",
    "loadimage": "D06", "loadimage_xml": "D06", "globalcontext": "D06",
    "override": "D06",
    "funcdata": "D07", "funcdata_op": "D07", "funcdata_varnode": "D07",
    "funcdata_block": "D07", "architecture": "D07", "options": "D07",
    "action": "D07", "expression": "D07", "transform": "D07", "userop": "D07",
    "pcodeinject": "D07", "dynamic": "D07",
    "typeop": "D08", "cast": "D08", "unionresolve": "D08",
    "flow": "D09", "xml_arch": "D09", "testfunction": "D09",
    "heritage": "D10", "prefersplit": "D10",
    "coreaction": "D11", "varmap": "D11",
    "condexe": "D12",
    "ruleaction": "R1-6", "subflow": "R7", "double": "R8",
    "bitfield": "R9", "constseq": "R9",
    "jumptable": "D13", "emulateutil": "D13",
    "merge": "D14", "variable": "D14",
    "printlanguage": "D16b", "printc": "D16b", "printjava": "D16b",
    "prettyprint": "D16c",
    "paramid": "D17",
    "inject_sleigh": "D18",
    # in DECCORE but in no row of the plan's table:
    "capability": "none", "graph": "none", "emulate": "none",
    "memstate": "none", "crc32": "none",
    # ported already or outside M3
    "opbehavior": "bk-pcode", "multiprecision": "bk-pcode",
    "signature": "notM3", "callgraph": "notM3", "raw_arch": "notM3",
    "codedata": "notM3", "rulecompile": "notM3", "unify": "notM3",
    "sleigh_arch": "console", "ifacedecomp": "console", "interface": "console",
    "ifaceterm": "console", "consolemain": "console", "analyzesigs": "notM3",
    "libdecomp": "console", "bfd_arch": "notM3", "loadimage_bfd": "notM3",
}

# ---- class -> track, where a file is shared between tracks ----
CLASS_TRACK = {
    "CircleRange": "D01",
    "FuncCallSpecs": "D07", "FspecSpace": "D07", "ParameterSymbol": "D07",
    "ProtoStoreSymbol": "D07",
    "BlockBasic": "D05",
    "PcodeEmitFd": "D09",
    "CastStrategy": "D08", "CastStrategyC": "D08", "CastStrategyJava": "D08",
    "ConditionalJoin": "D15",
    "ActionDatabase": "D17",   # universalAction, buildDefaultGroups (coreaction.cc)
}
# Actions of blockaction.cc (D15) and the split of coreaction.cc by the plan's rows.
D15_ACTIONS = """ActionStructureTransform ActionNormalizeBranches ActionPreferComplement
ActionBlockStructure ActionFinalStructure ActionReturnSplit ActionNodeJoin""".split()
D12_ACTIONS = """ActionLaneDivide ActionMultiCse ActionShadowVar ActionDeindirect
ActionStackPtrFlow ActionRedundBranch ActionDeterminedBranch ActionUnreachable
ActionDoNothing ActionLateDoNothing ActionConditionalConst ActionLikelyTrash
ActionSwitchNorm ActionUnjustifiedParams ActionActiveReturn ActionOutputPrototype
ActionInputPrototype ActionPrototypeWarnings ActionMappedLocalSync
ActionStartCleanUp ActionStartTypes ActionConstantPtr ActionStop
PropagationState""".split()
D14_ACTIONS = """ActionAssignHigh ActionMergeRequired ActionMarkExplicit ActionMarkImplied
ActionMergeMultiEntry ActionMergeCopy ActionDominantCopy ActionMarkIndirectOnly
ActionMergeAdjacent ActionMergeType ActionHideShadow ActionCopyMarker
ActionNameVars ActionDynamicSymbols ActionMapGlobals""".split()
for a in D15_ACTIONS:
    CLASS_TRACK[a] = "D15"
for a in D12_ACTIONS:
    CLASS_TRACK[a] = "D12"
for a in D14_ACTIONS:
    CLASS_TRACK[a] = "D14"
CLASS_TRACK["ActionSetCasts"] = "D16b"
CLASS_TRACK["ActionConditionalExe"] = "D12"
CLASS_TRACK["PropagationState"] = "D11"

# ---- Funcdata member -> track, where the plan gives it to another track ----
D05_MEMBERS = """opSetOpcode opMarkHalt opUnsetOutput opSetOutput opUnsetInput opSetInput
opSwapInput opInsert opUninsert opUnlink opDestroy opDestroyRecursive opDestroyRaw
opSetAllInput opRemoveInput opInsertInput newOp newIndirect opInsertBefore
opInsertAfter opInsertBegin opInsertEnd cloneOp newOpBefore newIndirectOp
newIndirectCreation markIndirectCreation setVarnodeProperties assignHigh newConstant
newUnique newVarnodeOut newUniqueOut newVarnode newVarnodeIop newVarnodeSpace
newVarnodeCallSpecs newCodeRef cloneVarnode destroyVarnode setInputVarnode
clearDeadVarnodes totalReplace totalReplaceConstant printRaw printVarnodeTree
debugModCheck debugModClear debugModPrint debugSetRange debugCheckRange
debugPrintRange""".split()
D09_MEMBERS = "followFlow truncatedFlow inlineFlow doLiveInject".split()
D13_MEMBERS = """linkJumpTable findJumpTable installJumpTable recoverJumpTable
earlyJumpTableFail stageJumpTable switchOverJumpTables removeJumpTable
installSwitchDefaults decodeJumpTable encodeJumpTable clearJumpTables""".split()
MEMBER_TRACK = {}
for m in D05_MEMBERS:
    MEMBER_TRACK[("Funcdata", m)] = "D05"
for m in D09_MEMBERS:
    MEMBER_TRACK[("Funcdata", m)] = "D09"
for m in D13_MEMBERS:
    MEMBER_TRACK[("Funcdata", m)] = "D13"
# type.cc: the IR-bound methods the plan gives to D08
for m in """resolveInFlow findResolve findCompatibleResolve resolveTruncation
findTruncation scoreSingleComponent resolveTruncation""".split():
    MEMBER_TRACK[("*", m)] = "D08"

DEF = re.compile(r"^[A-Za-z_][^;{}()=]*?\b([A-Z]\w*)::(~?\w+)\s*\(")
CLASSDECL = re.compile(r"^(?:class|struct)\s+(\w+)\s*(?::[^;{]*)?\{", re.M)


def base(name):
    return os.path.splitext(name)[0]


def track_of_file(b):
    return FILE_TRACK.get(b)


def seg_track(b, cls, member):
    if cls is not None:
        t = MEMBER_TRACK.get((cls, member)) or MEMBER_TRACK.get(("*", member))
        if t and (cls == "Funcdata" or b == "type"):
            return t
        if cls in CLASS_TRACK:
            return CLASS_TRACK[cls]
        if b == "ruleaction":
            return "R1-6"
    return track_of_file(b)


files = sorted(f for f in os.listdir(CPP) if f.endswith((".cc", ".hh")))
text = {}
for f in files:
    with open(os.path.join(CPP, f), encoding="latin-1") as fh:
        text[f] = fh.read()

# classes declared in headers -> owning track
class_owner = {}
for f in files:
    if not f.endswith(".hh"):
        continue
    b = base(f)
    ft = track_of_file(b)
    if ft is None:
        continue
    for m in CLASSDECL.finditer(text[f]):
        c = m.group(1)
        class_owner[c] = CLASS_TRACK.get(c, ft)
for a in list(class_owner):
    if a.startswith("Rule") and class_owner[a] == "D11":
        class_owner[a] = "R1-6"

# segments
segments = []  # (track, file, class, member, text)
funcdata_members = collections.defaultdict(set)  # member -> tracks defining it
for f in files:
    b = base(f)
    if track_of_file(b) is None:
        continue
    if f.endswith(".hh"):
        segments.append((track_of_file(b), f, None, None, text[f]))
        continue
    cur_cls, cur_mem, cur = None, None, []
    for line in text[f].split("\n"):
        m = DEF.match(line)
        if m:
            segments.append((seg_track(b, cur_cls, cur_mem), f, cur_cls, cur_mem, "\n".join(cur)))
            cur_cls, cur_mem, cur = m.group(1), m.group(2), []
        cur.append(line)
    segments.append((seg_track(b, cur_cls, cur_mem), f, cur_cls, cur_mem, "\n".join(cur)))
for t, f, c, m, _ in segments:
    if c == "Funcdata" and m:
        funcdata_members[m].add(t)

# Members usable for the call scan: a member-function name declared in the
# body of exactly one class of the headers, longer than five characters, so
# that `name(` is unambiguous enough.  The owner is the class's track, or for
# Funcdata the track of the segment that defines the member.
def class_bodies(src):
    for m in CLASSDECL.finditer(src):
        depth, i = 1, m.end()
        while i < len(src) and depth:
            ch = src[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        yield m.group(1), src[m.end():i]


MEMDECL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
KEYWORDS = set("switch return sizeof operator delete static_cast const_cast "
               "dynamic_cast reinterpret_cast defined".split())
member_classes = collections.defaultdict(set)
for f in files:
    if not f.endswith(".hh") or track_of_file(base(f)) is None:
        continue
    for cls, body in class_bodies(text[f]):
        for m in MEMDECL.finditer(body):
            member_classes[m.group(1)].add(cls)
scan_members = {}
for name, classes in member_classes.items():
    if len(classes) != 1 or len(name) <= 5 or name in class_owner or name in KEYWORDS:
        continue
    cls = next(iter(classes))
    if cls == "Funcdata":
        ts = funcdata_members.get(name)
        if ts and len(ts) == 1:
            scan_members[name] = (next(iter(ts)), cls)
        elif not ts:
            scan_members[name] = ("D07", cls)   # inline in funcdata.hh
    else:
        t = MEMBER_TRACK.get(("*", name)) or class_owner.get(cls)
        if t:
            scan_members[name] = (t, cls)

sizes = collections.Counter()
matrix = collections.defaultdict(collections.Counter)
names = collections.defaultdict(collections.Counter)
word = re.compile(r"\b[A-Za-z_]\w*\b")
call = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
for t, f, c, m, body in segments:
    if t is None:
        continue
    sizes[t] += body.count("\n") + 1
    for w in word.findall(body):
        o = class_owner.get(w)
        if o and o != t:
            matrix[t][o] += 1
            names[(t, o)][w] += 1
    for w in call.findall(body):
        oc = scan_members.get(w)
        if oc and oc[0] != t:
            matrix[t][oc[0]] += 1
            names[(t, oc[0])][oc[1] + "::" + w] += 1

order = ["D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08", "D09", "D10",
         "D11", "D12", "R1-6", "R7", "R8", "R9", "D13", "D14", "D15", "D16b",
         "D16c", "D17", "D18", "none", "console", "bk-pcode", "notM3"]
print("# plan_graph.py output; see the script's head comment for the method")
print()
print("## Lines per track (.cc and .hh, comments and blank lines included)")
for t in order:
    print(f"{t:8} {sizes[t]:7}")
print()
print("## Files of the directory that no rule assigns")
for f in files:
    if track_of_file(base(f)) is None:
        print("  " + f)
print()
print("## References: row uses names owned by column")
cols = [t for t in order if t not in ("console", "notM3", "bk-pcode")]
print("        " + "".join(f"{c:>6}" for c in cols))
for r in order:
    if r in ("bk-pcode",):
        continue
    print(f"{r:8}" + "".join(f"{matrix[r][c] or '.':>6}" for c in cols))
print()
print("## Names behind chosen pairs (top 25 each)")
PAIRS = [("D07", "D08"), ("D08", "D07"), ("D07", "D09"), ("D07", "D10"), ("D07", "D11"),
         ("D07", "D13"), ("D07", "D14"), ("D07", "D16b"), ("D07", "D15"), ("D07", "R7"),
         ("D07", "D12"), ("D07", "none"),
         ("D05", "D07"), ("D05", "D08"), ("D05", "D14"), ("D06", "D07"), ("D04", "D07"),
         ("D03", "D07"), ("D02", "D07"), ("D02", "D08"),
         ("D08", "D14"), ("D08", "D06"), ("D08", "D16b"), ("D08", "D11"),
         ("D09", "D13"), ("D09", "D10"), ("D09", "D08"), ("D09", "D11"), ("D09", "D18"),
         ("D10", "D08"), ("D10", "D11"), ("D10", "D14"), ("D10", "D13"), ("D10", "D09"),
         ("D11", "D10"), ("D11", "D14"), ("D11", "D13"), ("D11", "D12"), ("D11", "R1-6"),
         ("D11", "R7"), ("D11", "D09"), ("D11", "D16b"),
         ("D12", "D13"), ("D12", "D14"), ("D12", "D10"), ("D12", "D11"), ("D12", "R7"),
         ("R1-6", "D10"), ("R1-6", "D11"), ("R1-6", "D13"), ("R1-6", "D14"), ("R1-6", "R7"),
         ("R1-6", "R8"), ("R1-6", "R9"), ("R1-6", "D09"), ("R1-6", "D12"), ("R1-6", "D16b"),
         ("R7", "D10"), ("R7", "D11"), ("R7", "R1-6"), ("R8", "R1-6"), ("R8", "D10"),
         ("R9", "R1-6"), ("R9", "D10"), ("R9", "D11"),
         ("D13", "D09"), ("D13", "D10"), ("D13", "D11"), ("D13", "D01"), ("D13", "none"),
         ("D14", "D11"), ("D14", "D10"), ("D14", "D16b"), ("D14", "D13"),
         ("D15", "D14"), ("D15", "D11"), ("D15", "D13"), ("D15", "D12"),
         ("D16b", "D14"), ("D16b", "D13"), ("D16b", "D15"), ("D16b", "D11"),
         ("D16b", "D16c"), ("D16c", "D16b"), ("D17", "D11"), ("D17", "D14"),
         ("D17", "D16b"), ("D17", "D12"), ("D17", "D15"), ("D18", "D07")]
for p in PAIRS:
    n = names.get(p)
    if not n:
        print(f"{p[0]} -> {p[1]}: none")
        continue
    top = ", ".join(f"{k} {v}" for k, v in n.most_common(25))
    print(f"{p[0]} -> {p[1]}: {top}")
print()
print("## Members of the D07 files: lines, and names of other tracks each uses")
print("## (file, class::member, lines, then track:name pairs; D02 to D06 left out)")
LOW = ("D01", "D02", "D03", "D04", "D05", "D06", "D07", "bk-pcode", None)
for t, f, c, m, body in segments:
    b = base(f)
    if FILE_TRACK.get(b) != "D07" and not (b == "fspec" and c in ("FuncCallSpecs", "FspecSpace", "ParameterSymbol", "ProtoStoreSymbol")):
        continue
    if not f.endswith(".cc") or c is None:
        continue
    uses = collections.Counter()
    for w in word.findall(body):
        o = class_owner.get(w)
        if o not in LOW and o != t:
            uses[f"{o}:{w}"] += 1
    for w in call.findall(body):
        oc = scan_members.get(w)
        if oc and oc[0] not in LOW and oc[0] != t:
            uses[f"{oc[0]}:{oc[1]}::{w}"] += 1
    u = " ".join(sorted(uses))
    print(f"{f} {c}::{m} [{t}] {body.count(chr(10)) + 1} {u}")

print()
print("## Users of the members and classes of the D07 files, by track")
print("## (name [defining track]: track count, ...; members by the unique-name scan,")
print("## classes by name; a member no other track uses is listed with '-')")
d07_classes = set()
for f in files:
    b = base(f)
    if f.endswith(".hh") and FILE_TRACK.get(b) == "D07":
        for cls, _ in class_bodies(text[f]):
            d07_classes.add(cls)
d07_classes |= {"FuncCallSpecs", "FspecSpace", "ParameterSymbol", "ProtoStoreSymbol"}
users = collections.defaultdict(collections.Counter)
for t, f, c, m, body in segments:
    if t is None:
        continue
    for w in call.findall(body):
        oc = scan_members.get(w)
        if oc and oc[1] in d07_classes and not (c == oc[1]):
            users[f"{oc[1]}::{w} [{oc[0]}]"][t] += 1
    for w in word.findall(body):
        if w in d07_classes and c != w:
            users[f"class {w} [{class_owner.get(w)}]"][t] += 1
for name, classes in sorted(member_classes.items()):
    if len(classes) == 1 and next(iter(classes)) in d07_classes and name in scan_members:
        key = f"{scan_members[name][1]}::{name} [{scan_members[name][0]}]"
        if key not in users:
            users[key] = collections.Counter()
for key in sorted(users):
    u = ", ".join(f"{t} {n}" for t, n in sorted(users[key].items())) or "-"
    print(f"{key}: {u}")
