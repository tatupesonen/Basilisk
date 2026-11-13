# 01 — SLEIGH: the compiled language, the runtime and the compiler

Inventory of how SLEIGH works inside Ghidra at commit `42db038f3c`, written
so that the feature specs (`features/sla.md`, `sleigh-decode.md`,
`sleigh-pcode.md`, `sleigh-language.md`, `sleigh-compiler-front.md`,
`sleigh-compiler-back.md`, `sleigh-snippet.md`) and their implementers do
not have to re-read the C++ and Java. Milestones M1 and M2 of `PLAN.md`.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/`, both under
`../ghidra`. `REF` = the reference directory (`../reference`).

**How each statement was established.** Unmarked statements were read in the
source cited at the head of the section. **[run]** means the reference tools
were run and the result seen (2026-11-12/13, macOS arm64 reference build).
**[census]** means a script walked the packed stream of all 150 reference
`.sla` files (section 12). **[unverified]** marks what was neither read in
full nor run. Sections 9 and 10 (the compiler) carry `file:line` citations
because they were compiled from line-by-line notes.

## 0. Sources and authority

| Area | C++ | Java | Authority for basilisk |
|---|---|---|---|
| `.sla` format | `CPP/slaformat.*`, the `encode`/`decode` methods in `sleighbase.cc`, `slghsymbol.cc`, `slghpattern.cc`, `slghpatexpress.cc`, `semantics.cc` | `SM/pcode/utils/SlaFormat.java`, `SM/app/plugin/processors/sleigh/**` `decode` methods | C++ (both read and write version 4; the reference files are written by the C++ compiler) |
| Decoding, disassembly text, p-code | `sleigh.cc`, `context.cc`, `slghsymbol.cc`, `slghpatexpress.cc`, `slghpattern.cc`, `semantics.cc` | `SleighInstructionPrototype`, `ConstructState`, `ParserWalker`, `SleighParserContext`, `PcodeEmit*`, `Constructor.java` | C++, because `pcodedump` (the differential oracle, linked against it) and the decompiler use it. Where C++ behaviour is undefined (section 8) the spec states a defined result |
| Context database | `globalcontext.*` | `ProgramContext*`, `DisassemblerContextImpl` (program model) | C++ for the in-memory database of M1; the Java disassembler's context flow belongs to M5 |
| Registers as a model, flow types, operand types, p-code overrides, on-demand recompilation | — (C++ has only name ↔ varnode maps) | `SleighLanguage`, `SleighInstructionPrototype`, `PcodeEmit`, `RegisterBuilder`, `SleighLanguageFile` | Java (only implementation) — `features/sleigh-language.md` |
| Compiler | `slgh_compile.*`, `pcodecompile.*`, `slghparse.y`, `slghscan.l` | `SM/pcodeCPort/**`, `SleighCompiler.g` | Front end: Java (decided in `features/sleigh-syntax.md`). Everything after parsing: C++, because the runnable oracle is the C++ `sleigh`; Ghidra's own `SleighCompileRegressionTest` asserts that Java and C++ produce the same `-y` text for every shipped spec up to one whitespace print piece (section 11) |
| P-code snippets (injection) | `pcodeparse.y` (`PcodeSnippet`), `inject_sleigh.cc` | `SM/program/model/lang/PcodeParser.java`, `InjectPayloadSleigh` | C++ for the decompiler; `PcodeParserTest` (Java) is ported |

Ghidra's Gradle build compiles the shipped `.sla` files with the **Java**
compiler (`gradle/processorProject.gradle`, main class
`ghidra.pcodeCPort.slgh_compile.SleighCompile`); the reference directory's
are compiled with the **C++** one, with the same per-module options.

## 1. The compiled-language model

A compiled language is: a header, a table of source files, the address
spaces, and a symbol table whose subtable symbols own everything else
(constructors, their patterns in a decision tree, their p-code templates).

### 1.1 Header values
`bigendian`; `align` (instruction alignment in bytes, 1 = none);
`uniqbase` (first offset in the `unique` space not used by the
specification's own temporaries; analysis temporaries are allocated above
it); `maxdelay` (largest number of delay-slot bytes any constructor asks
for, 0 if none); `uniqmask` (non-zero only when the language uses
`crossbuild`: the bits of an instruction's address that are folded into its
temporaries' offsets so that p-code woven together from two instructions
does not collide — section 7.6); `numsections` (number of named p-code
sections, 0 if none). [census] `maxdelay` is present in 26 of 150 files,
`uniqmask` and `numsections` in one (Hexagon).

### 1.2 Symbols and scopes
Every symbol has a name, an id (index into one flat list) and a scope id.
Scope 0 is global; every other scope's parent is scope 0 in practice
(one scope per constructor, holding its operand symbols) [census: all
118,196 scopes have parent 0]. Kinds that reach a `.sla` (enum
`SleighSymbol::symbol_type`, `CPP/slghsymbol.hh:28`):

| Kind | Element | What it is | At run time |
|---|---|---|---|
| user op | `userop` | A `define pcodeop` name with its index | Name table for `CALLOTHER` input 0 |
| value | `value_sym` | A token field or context field used as a number | Operand: constant = field value; prints as hex |
| value map | `valuemap_sym` | Field with `attach values` | Constant = table[field]; `0xBADBEEF` marks an unusable entry |
| name | `name_sym` | Field with `attach names` | Prints table[field]; no value use; entry without a name is unusable |
| varnode | `varnode_sym` | A register or other fixed varnode (space, offset, size) | Operand handle = that varnode; the register map |
| context | `context_sym` | A context field: the context register varnode it lives in, `low`/`high` bit range within it, `flow` flag, and the field expression | As a value symbol; also registers the context variable (name, bit range) with the context database |
| varnode list | `varlist_sym` | Field with `attach variables` | Handle = the selected register; prints its name; a `null` entry is unusable |
| operand | `operand_sym` | One operand of one constructor (scope = that constructor's) | Section 1.5 |
| start, end, next2 | `start_sym`, `end_sym`, `next2_sym` | `inst_start`, `inst_next`, `inst_next2` | Handle = address in the current code space; print as hex |
| subtable | `subtable_sym` | A table: constructors and a decision tree | Section 1.4 |
| epsilon | `epsilon_sym` | The constant-0 symbol `epsilon` | Removed by the compiler's purge; never in a file [census] |

Compile-time-only kinds (never written): space, token, macro, section,
bitrange, label, and the two injection symbols `inst_dest`/`inst_ref`
(`FlowDestSymbol`, `FlowRefSymbol`, which have no `encode`).

[census] One file holds at most 20,356 operand symbols, 5,055 scopes, 3,273
varnodes, 1,711 user ops, 646 subtables, and a subtable at most 4,646
constructors. The loader's own limits are 0x100000 scopes and 0x1000000
symbols (`SymbolTable::MAX_TABLES`, `MAX_SYMBOLS`).

### 1.3 Tokens, fields and pattern expressions
A token (a named group of 1..n instruction bytes with an endianness) does
not survive compilation; its fields do, as self-contained `tokenfield`
expressions: `bigendian`, `signbit`, `startbit`/`endbit` (bit range within
the token, bit 0 least significant), and the precomputed `startbyte`/
`endbyte` (byte range to read, relative to the current constructor's
offset) and `shift` (`startbit % 8`). A `contextfield` is the same over the
context words: `signbit`, `startbit`/`endbit` in **most-significant-bit-
first** numbering over the whole context array (bit 0 is the top bit of
word 0), `startbyte = startbit/8`, `endbyte = endbit/8`,
`shift = 7 - endbit % 8`.

Pattern expressions (`PatternExpression`) are trees over 64-bit signed
integers: leaves `tokenfield`, `contextfield`, `intb` (constant),
`operand_exp` (the value of another operand of a named constructor:
`index`, `table` = subtable symbol id, `ct` = constructor index in it),
`start_exp`, `end_exp`, `next2_exp` (instruction addresses); binary
`plus_exp`, `sub_exp`, `mult_exp`, `lshift_exp`, `rshift_exp`, `and_exp`,
`or_exp`, `xor_exp`, `div_exp`; unary `minus_exp`, `not_exp`. They appear as
the defining expression of an operand, as the value of a context change,
and as the field of value/name/varlist symbols. [census] Expression
nesting is shallow (the whole stream nests at most 27 elements deep);
`next2_exp` never occurs, and **the C++ decoder has no case for it**
(`PatternExpression::decodeExpression`, `CPP/slghpatexpress.cc:465`), so a
file containing one fails to load there with "Invalid pattern expression
element".

### 1.4 Subtables, constructors, decision trees
A subtable has `numct` constructors, identified by their index (source
order), and one decision tree. The root table is the global symbol named
`instruction`.

A constructor has: `parent` (subtable id); `first` (index of the first
white-space print piece, −1 if none — the boundary between mnemonic and
operand text); `length` (minimum length in bytes of the bytes its own
pattern covers); `source`/`line` (index into the source-file table and line
of the constructor's `:`); its operand symbols in order (`oper`); its print
pieces in order, each literal text (`print`) or an operand reference
(`opprint`, index into the operand list); its context changes in order
(`context_op`, `commit`); a main p-code template unless the body is
`unimpl`; and zero or more named-section templates, each tagged with its
section number.

A decision node has `number` (how many pattern/constructor pairs reached
it during construction — informational), `context` (does it test context
bits or instruction bits), `startbit`, `size`. `size == 0` marks a leaf: an
ordered list of `pair`s (constructor index + a disjoint pattern), tried in
order, first match wins. Otherwise it has exactly `2^size` children,
indexed by the value of the `size`-bit field at `startbit` (most
significant bit first, relative to the current constructor's offset for
instruction bits). [census] trees are at most 19 levels deep, nodes have
at most 256 children (so `size` ≤ 8), leaves at most 16 pairs.

A disjoint pattern is `instruct_pat` (one pattern block over instruction
bytes), `context_pat` (one over the context words) or `combine_pat` (a
context block **then** an instruction block; both must match). A pattern
block is `off` (byte offset of its first word), `nonzero` (number of bytes
from `off` to the last byte with a mask bit; 0 = always true, −1 = always
false) and `mask_word`s (32-bit `mask` and `val`, big-endian byte order:
the first byte is the top 8 bits). [census] at most 3 words per block.

### 1.5 Operands
An operand symbol has: `index` (its position in the constructor's operand
list after the compiler reordered them — also its handle index); either
`subsym` (id of the defining symbol: a subtable, or any value/varnode
symbol) or a defining expression (second child); `off`/`base` (where the
operand's bytes start: `base == -1` means `off` bytes from the start of the
constructor, otherwise `off` bytes after the **end** of operand `base`);
`minlen` (minimum length in bytes of the operand's own pattern); `code`
(true when the operand is used as a code address — a branch or call
destination); and always, as first child, an `operand_exp` naming itself
(`localexp`), which is how other expressions refer to it. [census] 338,715
operands, 299,607 with `subsym`, 39,108 defined by an expression; 3,057
`code`; one constructor has up to 27 operands.

### 1.6 Context changes
`context_op`: assign an expression's value to a context field of the
**local** context copy while this instruction is being decoded:
`i` = word index, `shift` = left shift, `mask` = bits within the word;
`context[i] = (context[i] & ~mask) | ((value << shift) & mask)`.
`commit` (`globalset`): record that the bits `mask` of word `number` are to
be written to the context **database** at the address the symbol `id`
resolves to, with `flow` saying whether the change carries forward from
there (section 4.4).

### 1.7 P-code templates
`construct_tpl`: optional `section` (absent = main section), `delay`
(delay-slot byte count if the section contains a `delayslot` directive),
`labels` (number of local labels); first child the export — a
`handle_tpl`, or `null` when nothing is exported — then the `op_tpl`s.

`op_tpl`: `code` (opcode), then the output `varnode_tpl` or `null`, then
the inputs. Four opcodes are directives, not operations
(`CPP/semantics.hh:30-42`; names as `get_opname` prints them):

| Directive | Opcode value used | Inputs |
|---|---|---|
| `BUILD` | `MULTIEQUAL` (60) | one constant varnode whose offset is the operand index: emit that operand's constructor's p-code here |
| `DELAY_SLOT` | `INDIRECT` (61) | one constant whose offset is the byte count: emit the following instruction(s) here |
| `LABEL` | `PTRADD` (65) | one constant whose offset is the label number: a branch target at this position |
| `CROSSBUILD` | `PTRSUB` (66) | an address varnode and a constant section number: emit that section of the instruction at that address |

(`MACROBUILD` = `CAST` exists only inside the compiler.)

`varnode_tpl` = three constants: space, offset, size. `handle_tpl` = seven:
`space`, `size`, `ptrspace`, `ptroffset`, `ptrsize`, `temp_space`,
`temp_offset`. A constant (`ConstTpl`) is one of:

| Element | Meaning when resolved |
|---|---|
| `const_real val` | The number |
| `const_handle val s [plus]` | A part of operand `val`'s resolved handle: `s` = 0 space, 1 offset, 2 size, 3 offset-plus (`plus` packs a truncation: low 16 bits = byte offset to add for a non-constant, high bits = byte count to shift a constant right by) |
| `const_start`, `const_next`, `const_next2` | Offset of this instruction, the next, the one after |
| `const_curspace`, `const_curspace_size` | The space of the instruction's address; its address size |
| `const_spaceid space` | A fixed address space |
| `const_relative val` | A label number, to become a relative branch offset |
| `const_flowref`, `const_flowref_size`, `const_flowdest`, `const_flowdest_size` | Injection only (`inst_ref`, `inst_dest`); never in a `.sla` [census] |

[census] 816,132 op templates, 1,962,013 varnode templates; one section has
at most 571 ops; an op at most 10 inputs; a constructor at most 3 sections.

### 1.8 Source files
`sourcefiles` lists `(name, index)` pairs for the files that contain
constructors, indices dense from 0 in order of first use. [run] The name is
the base file name (`toyInstructions.sinc`), not a path.

## 2. The `.sla` file format (version 4)

Sources: `CPP/slaformat.cc`, `CPP/sleighbase.cc`, and each class's
`encode`/`decode`.

**Container.** Four bytes `s`, `l`, `a`, `0x04`, then one zlib stream
(deflate with zlib header; the compiler passes level −1, the library
default — [run] the stream starts `78 9c`). Inflated, it is Ghidra's packed
encoding (`features/core-marshal.md` §4.4) of one `<sleigh>` element, with
element and attribute ids from the **format scope** (scope 1), numbered
independently of the default scope. With `sleigh -y` the compiler writes
the same document as XML text instead, with no header [run]. Sizes [run]:
x86-64 is 501 kB on disk and 4.47 MB inflated; all 150 are 12.3 MB and
96.2 MB.

**Ids.** Attributes (scope 1): `val` 2, `id` 3, `space` 4, `s` 5, `off` 6,
`code` 7, `mask` 8, `index` 9, `nonzero` 10, `piece` 11, `name` 12,
`scope` 13, `startbit` 14, `size` 15, `table` 16, `ct` 17, `minlen` 18,
`base` 19, `number` 20, `context` 21, `parent` 22, `subsym` 23, `line` 24,
`source` 25, `length` 26, `first` 27, `plus` 28, `shift` 29, `endbit` 30,
`signbit` 31, `endbyte` 32, `startbyte` 33, `version` 34, `bigendian` 35,
`align` 36, `uniqbase` 37, `maxdelay` 38, `uniqmask` 39, `numsections` 40,
`defaultspace` 41, `delay` 42, `wordsize` 43, `physical` 44, `scopesize`
45, `symbolsize` 46, `varnode` 47, `low` 48, `high` 49, `flow` 50,
`contain` 51 (unused), `i` 52, `numct` 53, `section` 54, `labels` 55. Id 1
is reserved.

Elements (scope 1): `const_real` 1, `varnode_tpl` 2, `const_spaceid` 3,
`const_handle` 4, `op_tpl` 5, `mask_word` 6, `pat_block` 7, `print` 8,
`pair` 9, `context_pat` 10, `null` 11, `operand_exp` 12, `operand_sym` 13,
`operand_sym_head` 14, `oper` 15, `decision` 16, `opprint` 17,
`instruct_pat` 18, `combine_pat` 19, `constructor` 20, `construct_tpl` 21,
`scope` 22, `varnode_sym` 23, `varnode_sym_head` 24, `userop` 25,
`userop_head` 26, `tokenfield` 27, `var` 28, `contextfield` 29,
`handle_tpl` 30, `const_relative` 31, `context_op` 32, `sleigh` 33,
`spaces` 34, `sourcefiles` 35, `sourcefile` 36, `space` 37, `symbol_table`
38, `value_sym` 39, `value_sym_head` 40, `context_sym` 41,
`context_sym_head` 42, `end_sym` 43, `end_sym_head` 44, `space_other` 45,
`space_unique` 46, `and_exp` 47, `div_exp` 48, `lshift_exp` 49, `minus_exp`
50, `mult_exp` 51, `not_exp` 52, `or_exp` 53, `plus_exp` 54, `rshift_exp`
55, `sub_exp` 56, `xor_exp` 57, `intb` 58, `end_exp` 59, `next2_exp` 60,
`start_exp` 61, `epsilon_sym` 62, `epsilon_sym_head` 63, `name_sym` 64,
`name_sym_head` 65, `nametab` 66, `next2_sym` 67, `next2_sym_head` 68,
`start_sym` 69, `start_sym_head` 70, `subtable_sym` 71, `subtable_sym_head`
72, `valuemap_sym` 73, `valuemap_sym_head` 74, `valuetab` 75, `varlist_sym`
76, `varlist_sym_head` 77, `or_pat` 78, `commit` 79, `const_start` 80,
`const_next` 81, `const_next2` 82, `const_curspace` 83,
`const_curspace_size` 84, `const_flowref` 85, `const_flowref_size` 86,
`const_flowdest` 87, `const_flowdest_size` 88.

**Grammar.** Attributes are listed in the order the encoder writes them;
`s` = signed integer, `u` = unsigned, `b` = boolean, `str` = string, `spc` =
address-space reference; `[x]` = written only under the stated condition.
The value types matter for a byte-exact writer ([census] confirms each).

```
sleigh        version:s bigendian:b align:s uniqbase:u [maxdelay:u >0] [uniqmask:u !=0] [numsections:u !=0]
                { sourcefiles spaces symbol_table }
sourcefiles   { sourcefile* }            sourcefile  name:str index:s
spaces        defaultspace:str { (space_unique | space_other | space)* }      in space-index order
space*        name:str index:s bigendian:b delay:s size:s [wordsize:s >1] physical:b
symbol_table  scopesize:s symbolsize:s { scope{scopesize} head{symbolsize} body* }
scope         id:u parent:u                (the global scope has parent 0, itself)
<kind>_head   name:str id:u scope:u        (one per symbol, in id order)
userop        id:u index:s
value_sym     id:u { expr }
valuemap_sym  id:u { expr valuetab* }      valuetab  val:s
name_sym      id:u { expr nametab* }       nametab   [name:str]     (no attribute = unusable entry)
varnode_sym   id:u space:spc off:u size:s
context_sym   id:u varnode:u low:s high:s flow:b { expr }
varlist_sym   id:u { expr (var | null)* }  var  id:u
operand_sym   id:u [subsym:u] off:s base:s minlen:s [code:b =true] index:s { operand_exp [expr] }
start_sym, end_sym, next2_sym, epsilon_sym     id:u
subtable_sym  id:u numct:s { constructor{numct} decision }
constructor   parent:u first:s length:s source:s line:s
                { oper* (print | opprint)* (context_op | commit)* construct_tpl* }
oper          id:u            print  piece:str            opprint  id:s
context_op    i:s shift:s mask:u { expr }
commit        id:u number:s mask:u flow:b
construct_tpl [section:s >=0] [delay:s !=0] [labels:s !=0] { (handle_tpl | null) op_tpl* }
op_tpl        code:opcode { (varnode_tpl | null) varnode_tpl* }
varnode_tpl   { const const const }                       space, offset, size
handle_tpl    { const{7} }      space, size, ptrspace, ptroffset, ptrsize, temp_space, temp_offset
const_real val:u | const_handle val:s s:s [plus:u when s=3] | const_spaceid space:spc
  | const_relative val:u | const_start | const_next | const_next2 | const_curspace
  | const_curspace_size | const_flowref | const_flowref_size | const_flowdest | const_flowdest_size
decision      number:s context:b startbit:s size:s { pair* decision* }
pair          id:s { instruct_pat | context_pat | combine_pat }
instruct_pat  { pat_block }    context_pat { pat_block }    combine_pat { context_pat instruct_pat }
pat_block     off:s nonzero:s { mask_word* }              mask_word  mask:u val:u
expr          tokenfield bigendian:b signbit:b startbit:s endbit:s startbyte:s endbyte:s shift:s
  | contextfield signbit:b startbit:s endbit:s startbyte:s endbyte:s shift:s
  | intb val:s | operand_exp index:s table:u ct:u | start_exp | end_exp | next2_exp
  | (plus_exp|sub_exp|mult_exp|lshift_exp|rshift_exp|and_exp|or_exp|xor_exp|div_exp) { expr expr }
  | (minus_exp|not_exp) { expr }
```

Details that are easy to get wrong:

* The symbol table is written as: all scopes; then **every symbol's head**
  in id order; then every symbol's body in id order. The decoder creates
  empty symbols from the heads first so that bodies can refer to any id,
  then reads bodies until the element ends, finding each by its `id`
  attribute (bodies are not required to be in order or complete).
* `opcode` in the packed form is a non-negative integer attribute (the
  opcode's number); in XML it is the name `get_opname` gives, in which
  the four directive opcodes read `BUILD`, `DELAY_SLOT`, `LABEL`,
  `CROSSBUILD` (`bk_pcode::OpCode::name`).
* `spc` in the packed form is the space's index; in XML its name.
* The `bigendian` attribute of every space element repeats the language's
  endianness, not the space's. `space_unique` and `space_other` carry
  `name`, `delay`, `size` and `physical` but the C++ loader ignores them:
  the unique space is always named `unique`, 4-byte offsets, physical,
  language endianness; the other space is always `OTHER`, index 1, 8-byte
  offsets, little endian, delay 0. A `space` needs a non-zero `size`, a
  `delay` and a `name`, or the load fails ("Expecting size/delay/name
  attributes"); any space with `index` 0 fails ("Expecting index
  attribute"). The constant space (index 0) is not in the file; the loader
  creates it first.
* Java classifies a `space` with `delay > 0` as RAM-like and one with
  `delay == 0` as register-like (`SleighLanguage.parseSpaces`); the C++
  makes every `space` an `IPTR_PROCESSOR` space.
* A constructor has no id attribute; its id is its position in the
  subtable. `pair.id` and `operand_exp.ct` are such positions.
* A constructor whose only print piece is one operand "flows through":
  the decoder sets `flowthruindex` to that operand (section 6).
* `pat_block` is normalised after reading (leading zero mask bytes move
  into `off`, trailing zero words are dropped, `nonzero` recomputed), so a
  reader need not trust `off`/`nonzero` for a block with words; a writer
  must write the normalised form (section 10, b.1).
* The decoder of `operand_sym` skips the first attribute unconditionally
  (it must be `id`), and reads the rest in any order.

## 3. Loading a language (C++)

`Sleigh::initialize` (`CPP/sleigh.cc`) opens the file, checks the 4-byte
header ("Missing SLA format header"), inflates it in 4,096-byte reads and
decodes `<sleigh>` (`SleighBase::decode`): attributes; the `version`
attribute must be 4 (".sla file has wrong format"); source files; spaces
(constant space inserted first, then each in file order, then the default
code space by name: "Bad 'defaultspace' attribute: X"); the symbol table;
the root table = global symbol `instruction`. Then `buildXrefs` walks the
**global scope in name order** and builds:

* the register map `VarnodeData → name` from every varnode symbol; two
  symbols with the same (space, offset, size) make the load fail
  ("Duplicate register pairs");
* the user-op name list, indexed by the symbol's `index` (gaps are empty
  strings);
* for every context symbol, a context variable `name → (startbit, endbit)`
  registered with the context database, the bit range taken from its
  `contextfield`.

Register queries (`SleighBase`): `getRegister(name)` — the symbol must
exist and be a varnode symbol ("Unknown register name: X", "Symbol is not
a register: X"); `getExactRegisterName(space, off, size)`;
`getRegisterName(space, off, size)` — among map entries ordered by (space,
offset, size), take the last one not after (space, off, size); if it is in
the space and reaches `off+size` it is the answer; otherwise walk
backwards over entries **with the same offset as that first candidate**
and return the first that reaches `off+size`; otherwise none. (So a
containing register that starts at a lower offset than the candidate is
not found.) `getUserOpNames`, `getAllRegisters`.

After loading, the embedding program applies language set-up that is not
in the `.sla`: `<truncate_space>` from the `.ldefs`, and the `.pspec`
(`<context_data>` → section 4.3; the rest is the decompiler's and the
program model's). `Translate::setDefaultFloatFormats` installs the 4- and
8-byte IEEE formats when the `.pspec`/`.cspec` name none.

[run] Loading `x86-64.sla` this way (`Sleigh::initialize` alone, in
process) takes 32–43 ms on the reference build (best of 5 on a loaded
machine); with the `.ldefs` scan and `.pspec`, 41–48 ms (`PERF.md`).

## 4. Context

### 4.1 Context words
The context is an array of 32-bit words (`uintm`). The compiler lays every
`define context` field out in it; a field never straddles a word. Bit
numbering is most significant first: bit `b` lives in word `b / 32` at
position `31 - b % 32` from the bottom. A context **variable** registered
with the database is `(word, startbit, endbit, shift = 31 - endbit,
mask = (2^(endbit-startbit+1) - 1))`, value = `(word >> shift) & mask`
(`ContextBitRange`, `CPP/globalcontext.hh`).

### 4.2 The database (`ContextInternal`, `CPP/globalcontext.cc`, `partmap.hh`)
A map from split-point addresses (ordered by space index, then offset) to
a pair of word arrays (`value`, `mask`), plus a default value used before
the first split point. The value at an address is that of the last split
point at or before it. `mask` records which bits were *explicitly set
starting at that point*; a copy made by splitting carries the values but a
zero mask.

* `getContext(addr)` also returns the range `[first, last]` of offsets
  around `addr` over which the value is constant (0 and the space's
  highest offset where there is no neighbouring split point in the same
  space); `ContextCache` keeps the last answer and reuses it while lookups
  stay inside the range.
* `setContextChangePoint(addr, word, mask, value)` — the "flowing" set:
  split at `addr`; set the bits there and in every following split point
  **until one whose mask already has any of these bits** (a point where
  the variable was set explicitly before), marking the first point's mask.
* `setContextRegion(addr1, addr2, word, mask, value)` — split at both
  ends (`addr2` invalid = to the end of everything); set the bits in every
  split point in `[addr1, addr2)` and mark their masks.
* `setVariableDefault(name, value)` changes the default array;
  `setVariable(name, addr, value)` is the change-point form by name;
  `setVariableRegion(name, begin, end, value)` the region form.
* Variables may only be registered while the database is empty ("Cannot
  register new context variables after database is initialized"); a
  variable must fit one word ("Context variable does not fit in one
  word"); an unknown name is "Non-existent context variable: X".
* The same class holds **tracked sets** — per address range, a list of
  `(varnode, value)` the decompiler assumes on entry (`<tracked_set>`),
  with `getTrackedValue(varnode, addr)` extracting a contained register's
  value by endianness. They do not affect decoding.

### 4.3 `.pspec` defaults
`ContextInternal::decodeFromSpec` reads `<context_data>`: each child has a
range (`space`, optional `first`/`last`); `<context_set>` children
`<set name val>` are applied with the **region** form over that range (so
they are explicit sets, not the default array); `<tracked_set>` replaces
the tracked list over the range. `pcodedump` applies exactly this, and its
`--context NAME=VALUE` is `setVariableRegion` from offset 0 of the default
code space to the end. Java reads the same element into default register
values of the program context (`SleighLanguage.read`, `applyContextSettings`)
— a value that fails to parse silently becomes 0 there.

### 4.4 `globalset`
During the decode of one instruction each `commit` executed records
`(symbol, word, mask, value = local context[word] & mask at that moment,
flow, the constructor node it ran in)`. `ParserContext::applyCommits` —
called when p-code is requested for the instruction, **not** when it is
only disassembled — turns each into a database write:

1. The address: if the symbol is an operand, the fixed handle of that
   operand in the recorded node (space, offset); otherwise the symbol's
   own handle evaluated at the root (`inst_next`, `inst_start`, a varnode).
   If the result is in the constant space (a computed value), it is
   converted to an address in the instruction's space, scaled from
   addressable units to bytes by the space's word size.
2. `flow == true`: `setContextChangePoint(address, …)`.
3. `flow == false` (`noflow` fields): region set over `[address,
   address+1)`; if `address+1` wraps, the change-point form.

`ContextCache::allowSet(false)` turns all of this off (used while the
decompiler re-reads code it must not disturb).

Consequences worth knowing: a context change made by `[ field = … ]`
alone never leaves the instruction; an instruction that is only
disassembled never changes the database in C++; and the value committed
is the local context at the time the `commit` runs, so later `context_op`s
of the same constructor do not affect it.

## 5. Decoding an instruction (C++ `Sleigh::resolve`, `resolveHandles`)

State: a 16-byte buffer filled by `LoadImage::loadFill(buf, 16, addr)`
(the image decides what unbacked bytes read as; `pcodedump` gives zeros);
a local copy of the context words at `addr`; a tree of nodes
(`ConstructState`: constructor, parent, child per operand, `offset` =
absolute byte offset of the node's first byte within the instruction,
`length`, resolved handle).

**Bit and byte access** (`CPP/context.cc`), all big-endian packing into a
32-bit value: `getInstructionBytes(bytestart, size, off)` reads `size` ≤ 4
bytes at `off + bytestart`; `getInstructionBits(startbit, size, off)` reads
the bytes covering the field at `off + startbit/8` and returns the `size`
bits starting `startbit % 8` bits in. Both throw `BadDataError`
("Instruction is using more than 16 bytes") when the **first** byte index
is ≥ 16; later bytes are not checked (section 8). `getContextBytes` and
`getContextBits` do the same over the word array, reading across at most
two words and treating words past the end as absent.

**Resolve** (constructors and lengths):

1. Root node: offset 0; clear pending commits; load the context; walk the
   root table's decision tree; apply the chosen constructor's context
   changes in order (`context_op` updates the local words; `commit`
   records).
2. Visit operands depth-first, in operand order. For operand `i` of the
   current constructor: its offset is `base == -1 ? node.offset :
   child[base].offset + child[base].length`, plus `off`. Create its node
   with that offset. If it has a defining symbol, call the symbol's
   `resolve`:
   * a subtable walks its decision tree from this offset, and the chosen
     constructor's context changes are applied; descend into it;
   * a value map, name or varnode-list symbol evaluates its field and
     fails with `BadDataError` ("No corresponding entry in valuetable" /
     "nametable" / "varnode list") if the entry is out of range or
     unusable — unless the table is known to be completely filled, which
     is precomputed at load (`checkTableFill`: the field's minimum is ≥ 0,
     its maximum is below the table size, and no entry is unusable);
   * anything else resolves to nothing.
   A non-subtable operand's length is its `minlen`.
3. When all operands of a constructor are done, its length is
   `max(node.offset + ct.length, max over children (child.offset +
   child.length)) - node.offset`. If its main template has a `delay`
   count > 0, that becomes the instruction's delay-slot byte count (the
   last such constructor finished wins).
4. Instruction length = root length; next address = `addr + length`
   (wrapping in the space).

**Decision-tree walk.** At a node with `size > 0`: read `size` bits at
`startbit` from the context words or from the instruction bytes at the
current node's offset; go to that child. At a leaf: return the first pair
whose pattern matches, else `BadDataError` "`<addr>`: Unable to resolve
constructor" (`<addr>` = the space's shortcut character and the address,
`r0x00001002`). A pattern block matches when, for each of its words `k`,
`(mask[k] & bytes(off + 4k, 4)) == val[k]`; a block with `nonzero` ≤ 0
matches iff `nonzero == 0`.

**Expression values** (`getValue`), all in signed 64-bit:

* `tokenfield`: read bytes `startbyte..=endbyte` at the current node's
  offset as a big-endian number (in 4-byte groups), byte-swap it if the
  field is little-endian, shift right by `shift`, then sign- or
  zero-extend from bit `endbit - startbit`.
* `contextfield`: the same over the context bytes, shift, extend.
* `intb`: the constant. `start_exp`/`end_exp`/`next2_exp`: the offset of
  the instruction, the next, the one after (4.5 below).
* `operand_exp(table, ct, index)`: the value of that operand's defining
  expression (or its defining symbol's field), evaluated "out of band":
  walk up from the current node to the nearest node whose constructor is
  `ct` (give up and use the current position if none within the depth),
  and evaluate at the operand's offset there — computed from the
  constructor's offset when the operand is constructor-relative (its node
  may not exist yet: context changes run before operands are parsed),
  otherwise the already-parsed child's offset. An operand with neither
  expression nor field evaluates to 0.
* Operators are the C++ ones on `int64`: wrapping `+ - *`, `&`, `|`, `^`,
  unary `-` and `~`; `<<` and `>>` with an unchecked count; `/` with an
  unchecked divisor (section 8).

**Resolve handles** (only when p-code is wanted). A second depth-first
walk. For each non-subtable operand, the handle is the defining symbol's
`getFixedHandle`:

| Symbol | space | offset | size |
|---|---|---|---|
| value | const | field value | 0 |
| value map | const | table[field] | 0 |
| varnode | its space | its offset | its size |
| varnode list | selected register's | … | … |
| start / end / next2 | the instruction's space | that address's offset | the space's address size |
| defining expression | const | value | 0 |
| name | (a name symbol has no handle; the compiler gives such operands zero-size constant handles that templates never dereference) | | |

After a constructor's operands, if its main template has an export, the
`handle_tpl` is resolved into the node's handle (`HandleTpl::fix`):

* `ptrspace` is `const_real` (an ordinary export): `space` from the
  template; `size`; and the offset part — if `ptroffset` is a handle
  reference, copy that operand's whole offset description (so a dynamic
  operand stays dynamic); otherwise a static offset, wrapped to the space.
* otherwise (an exported dereference `*[space]:size ptr`): `space`,
  `size`, pointer = (`ptrspace`, `ptroffset`, `ptrsize`); **if the
  pointer's space turns out to be the constant space** the handle becomes
  static: offset = pointer value scaled by the target space's word size
  and wrapped; else it is dynamic and also records the temporary
  (`temp_space`, `temp_offset`) that will hold the loaded value.

A handle is *dynamic* when it has a pointer space. A subtable operand's
handle is its constructor's export.

### 5.1 `inst_next2`
`ParserContext::getN2addr` computes it on first use by asking the
translator for the length of the instruction at the next address
(`Translate::instructionLength`), which decodes that instruction with the
context the database holds for it at that moment. "inst_next2 not
available in this context" if there is no translator. [census] only the
Toy languages use it.

### 5.2 The parse cache
`DisassemblyCache` keeps 2 parses (8 when `maxdelay > 1` or `uniqmask !=
0`), found through a hash on the low address bits. A parse has a state:
uninitialised, disassembly (constructors resolved), p-code (handles
resolved). A cached parse is reused as long as its address matches, **even
if the context database has changed since**. With `pcodedump`'s linear
sweep this is observable in one situation only: instruction A evaluates
`inst_next2` (parsing B early, before A's commits are applied) *and*
commits context that changes how B decodes; B is then not re-decoded.
No shipped language does both [unverified beyond: `inst_next2` occurs only
in `Toy/data/languages/toyInstructions.sinc`].

## 6. Disassembly text

`Sleigh::printAssembly` prints the root constructor twice:
`printMnemonic` and `printBody` (`CPP/slghsymbol.cc`).

* If the constructor flows through (its only print piece is one operand)
  and that operand is a subtable, both functions recurse into that
  operand's constructor.
* Mnemonic = the print pieces before index `first` (all of them if `first`
  is −1). Body = the pieces after index `first` (the white-space piece
  itself is dropped); nothing if `first` is −1.
* A literal piece is written as is. An operand piece prints the operand:
  a subtable operand prints **all** pieces of its constructor (no
  mnemonic/body split below the root); another symbol prints itself; an
  operand defined by an expression prints the value.
* Numbers print as `0x` + lower-case hex of the value when it is ≥ 0, and
  `-0x` + hex of the negated value when negative (value, value-map and
  expression operands). `inst_start`/`inst_next`/`inst_next2` print the
  offset as `0x…` (never negative). A name symbol prints the table entry;
  a varnode list prints the selected register's **symbol name**; a varnode
  symbol used directly as an operand has no `print` in C++ (the compiler
  never emits an operand print piece for one; it writes the name as
  literal text) [unverified: no failing case found; all 150 languages will
  show in the differential test].
* [run] `pcodedump` output: `MOV` / `RAX,qword ptr [RBP + 0x8]`; `CALL` /
  `0x1009`; `MOVSB.REP` / `RDI,RSI`; `SYSCALL` / empty.

Java splits the same way but also exposes operands as objects
(`getOpObjects`, separators) — section 11.

## 7. P-code generation (`Sleigh::oneInstruction`, `SleighBuilder`, `PcodeCacher`)

### 7.1 Order of events
1. If `align != 1` and the address is not a multiple of it: `UnimplError`
   "Instruction address not aligned: …" with length 0.
2. Obtain the parse with handles; **apply its commits**.
3. If the parse has a delay-slot count: for each following instruction
   until that many bytes are covered — parse it at `addr + fallOffset`
   (with the context as it now is), apply its commits, add its length.
   The instruction's next address becomes the address after the delay
   slots, so `inst_next` and fall-through refer to it. The return value
   ("flow length") includes the delay-slot bytes.
4. Build the root constructor's main template into a list of ops
   (7.2–7.6), resolve relative branches (7.5), and hand each op to the
   emitter in order: `dump(addr, opcode, output or none, inputs)`.
5. A constructor without a main template anywhere in the build raises
   `UnimplError`; the engine replaces its text with "Instruction not
   implemented in pcode:\n `<addr>`: `<mnemonic>`  `<body>`" (of the
   instruction being built when it happened) and sets the length to the
   flow length. Nothing is emitted for the instruction.

### 7.2 Building a template (`PcodeBuilder::build`)
Labels: on entry the builder reserves `labels` label numbers for this
template (`labelbase` = labels issued so far in the instruction), and
restores the previous base on exit. Then for each op template in order:

* `BUILD i` → if operand `i` is a subtable, build its constructor's main
  template with that operand as the current node (in a named section: its
  template for that section, or — if it has none — treat every subtable
  operand of it as an implied build, recursively); otherwise nothing.
* `DELAY_SLOT` → 7.6. `LABEL n` → record that label `labelbase + n` is at
  the index of the next op to be issued. `CROSSBUILD` → 7.6.
* anything else → `dump` (7.3).

### 7.3 One op (`SleighBuilder::dump`)
For each input template in order: if its offset refers to a **dynamic**
handle, first issue `LOAD temp = *[space] pointer` — output = the
template resolved as a location (which yields the handle's temporary),
input 0 = the space-id constant of the handle's space, input 1 = the
pointer varnode — and use the temporary as the input; then, if the
template's offset is an offset-plus with a non-zero low 16 bits, the
`LOAD` is preceded by `INT_ADD ea = pointer + plus` where `ea` is the
fixed temporary at `uniqbase + 0x100` (`RUNTIME_BITRANGE_EA`), same size as
the pointer, and the `LOAD` reads through `ea`. Then the op itself. If the
output template is dynamic: the op writes the handle's temporary and a
`STORE *[space] pointer = temp` follows (with the same `INT_ADD`
adjustment, issued before the `STORE`).

If input 0 of the op is a `const_relative`, its offset gets `labelbase`
added and the varnode is remembered as a label reference together with
the index of the op about to be issued.

### 7.4 Resolving a varnode template (`generateLocation`)
`space` = the template's space constant resolved; `size` = its size
resolved; `offset`:

* in the constant space: the offset value masked to `size` bytes
  (`calc_mask`: sizes ≥ 8 keep 64 bits, size 0 gives 0);
* in the unique space: the offset value **OR**
  `(instruction address offset & uniqmask) << 8`;
* otherwise wrapped to the space's address range.

A constant resolves as in 1.7; for a handle reference: space = the
handle's space, or its temporary's space when the handle is dynamic;
offset = the handle's offset, or its temporary's offset when dynamic;
size = the handle's size; offset-plus on a non-constant handle = that
offset + low 16 bits of `plus`; on a constant handle = the value shifted
right by `8 × (plus >> 16)` bits. The pointer of a dynamic handle
(`generatePointer`) is `(offset_space, offset_offset, offset_size)`,
treated by the same three space rules.

Space-id constants (`LOAD`/`STORE` input 0, and `const_curspace`,
`const_spaceid` used as an offset) are, in C++, a varnode in the constant
space whose offset is the host pointer of the space and whose size is
`sizeof(pointer)`. `pcodedump` prints them as `(const,<index>,8,<name>)`.

### 7.5 Relative branches (`PcodeCacher::resolveRelatives`)
After the whole instruction is built, each remembered label reference is
replaced by `(label position − index of the referring op)` masked to the
varnode's size — a signed op-count displacement within this instruction's
p-code. A reference to a label that was never placed is "Reference to
non-existant sleigh label".

### 7.6 Delay slots and crossbuild
`DELAY_SLOT`: for each instruction after this one, until the delay-slot
byte count is covered, build **its whole root template** in place, with
that instruction's parse as the current one and the unique-offset bits
recomputed from its address; then continue with the outer instruction.
The parses were made in step 3 of 7.1 ("Could not obtain cached delay slot
instruction" if not). The delayed instruction's own labels are numbered
after the outer ones because the label counter is per instruction.

`CROSSBUILD addr, n` (only legal in a main section: "CROSSBUILD directive
within a named section"): resolve the address varnode; take the parse of
the instruction at that address (which must already be parsed with
handles: "Could not obtain cached crossbuild instruction"); build its
named section `n` (or implied builds if the root constructor has none)
with a walker that takes constructors and handles from that instruction
but `inst_start`/`inst_next`/… from the **current** one, and with the
unique-offset bits of that address. [census] one language (Hexagon).

### 7.7 What the emitter receives
`PcodeEmit::dump(addr, opc, outvar, vars, isize)`: the instruction's
address, one opcode of `bk_pcode::OpCode` (never a directive), an optional
output and `isize` inputs as `(space, offset, size)`. `CALLOTHER` input 0
is a constant whose value is the user op's index. [run] x86-64 over 147,953
instructions: 4.11 ops per instruction.

## 8. Undefined and host-dependent behaviour in the C++ runtime

| Where | C++ | Consequence for a port |
|---|---|---|
| Instruction bytes past index 15 | Only the first byte index of a read is checked against 16; a 4-byte read starting at byte 13–15 reads past the buffer (into the object's next fields) | When the bytes are masked out (pattern words) the result is unaffected; a token field that really extends past byte 15 reads garbage. A port must define this |
| `<<`, `>>` in expressions with a count ≥ 64 or negative | Undefined; x86-64 and AArch64 both use the count modulo 64 | ADR-021: modulo 64; `>>` is arithmetic |
| `/` by zero | Undefined: traps on x86-64 (the process dies), yields 0 on AArch64 | A port must define this. [census] `div_exp` occurs 32 times, always dividing an operand by a constant |
| Decision node child index | `children[val]` unchecked | A loader must check `2^size` children exist |
| Constructor with more than 20 operands | `ParserContext::MAX_OPERAND = 20` child slots per node; operand index ≥ 20 throws "SLEIGH parser out of state space" | [census] PowerPC `lmw`/`stmw` constructors have 24 and 27 operands, yet [run] `pcodedump` lifts `lmw r3,0x0(r1)` correctly — the guard is `i >= MAX_OPERAND` inside `allocateOperand`, and these operands evidently do not reach it [unverified why; the differential test over PowerPC decides] |
| Parse depth | More than 30 nested constructors: "SLEIGH exceeded maximum parse depth" | Keep as a limit |
| Varnodes per instruction | A single allocation of more than 4,096 varnodes: "Maximum parameters exceeded for a single p-code op" | Keep a bound |
| Space-id constants | Host pointer and pointer size | Use the space index; size 8 for parity with `pcodedump` |
| Recursion in `OperandValue::getValue`, `print` | Unbounded if a hostile file makes operands refer to each other | A loader must reject cycles or bound depth |

## 8a. Measured baselines [run]

`REF/src/cpp/libsla.a`, x86-64, 539 kB of compiled code (text sections of
four of Ghidra's own C++ files built for x86-64), 147,953 instructions,
1,331 undecodable positions; best of 5; the machine was heavily loaded
(load average over 40), so these are lower bounds on Ghidra's speed. The
program is kept in the session scratchpad, not in the repository; the
first implementing track re-measures on an idle machine and records the
result in `PERF.md`.

| What | Result |
|---|---|
| `.sla` load (`Sleigh::initialize`) | 32–43 ms |
| Decode only (`instructionLength`) | 2.87 M instructions/s (348 ns) |
| Decode + text (`printAssembly`) | 1.24 M/s (808 ns) |
| Decode + p-code (`instructionLength` + `oneInstruction`, null emitter) | 1.50 M/s (667 ns) — the `PERF.md` figure |
| Decode + text + p-code | 0.84 M/s (1,186 ns) |
