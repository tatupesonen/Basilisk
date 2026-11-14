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
* `first` may equal the number of print pieces: the compiler records
  the index of the first white-space piece and afterwards removes a
  trailing white-space piece, without adjusting `first` ([run] 39,921
  shipped constructors, e.g. a mnemonic followed by a space and nothing
  else). The mnemonic is then all pieces and the body is empty.
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
| name | const | field value | 0 (inherited from the value symbol; `NameSymbol` overrides only `print` and `resolve`) |

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
  symbol used directly as an operand prints its name
  (`VarnodeSymbol::print`, `CPP/slghsymbol.hh:260`).
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
| Constructor with more than 20 operands | `ParserContext::MAX_OPERAND = 20` child slots per node; operand index ≥ 20 throws `LowlevelError` "SLEIGH parser out of state space" | [census] PowerPC AltiVec has constructors with 24 and 27 operands (`altivec.sinc`: `vadduhm`, `vsubuhm` and two sub-tables). [run] `pcodedump` on `vadduhm` (`10 22 18 40`, `PowerPC:BE:32:default`) prints `E … error SLEIGH parser out of state space`: **Ghidra's C++ engine cannot decode these instructions.** A port should decode them and the differential test must expect the oracle's error |
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

## 9. The compiler, front half: from the parsed specification to constructors with templates

Sources: `CPP/slgh_compile.cc` (lines cited as SC), `CPP/slghparse.y`
(GR), `CPP/slghscan.l` (LX), `CPP/pcodecompile.cc` (PC),
`CPP/slghsymbol.cc` (SY), `CPP/semantics.cc` (SEM). Read in full for this
section. The C++ compiler does its work *inside grammar actions*, one
pass, with the lexer classifying identifiers by looking them up in the
symbol table as it goes. Everything below that says "in order" means the
order in which bison reduces, which for this grammar is: source order,
and within an expression, operands left to right, then the operator
(post-order). A port that works from a syntax tree must visit it in that
order, because symbol ids and temporary offsets are handed out as a side
effect and end up in the file.

### 9.1 Driver and command line
`main` (SC:3926-4091). Options are single arguments starting with `-`;
only the second character is examined; parsing stops at the first
argument without `-`:

| Option | Effect | Default |
|---|---|---|
| `-a` | compile every `*.slaspec` found recursively under the directory argument (default `.`), each to the same name with `.sla`; prints `Compiling N slaspec files in DIR` and `Compiling (i of N) FILE`; **stops at the first failure** | off |
| `-DNAME=VALUE` | preprocessor definition; without `=`: `Bad sleigh option: ARG`, exit 1 | — |
| `-u` | list each unnecessary extension/truncation | summary only |
| `-l` | report indistinguishable patterns as errors ("lenient conflict" off) | lenient |
| `-c` | list each operand collision | summary only |
| `-n` | list each NOP constructor | summary only |
| `-t` | list each dead temporary | summary only |
| `-e` | require `local` for temporaries | off |
| `-s` | register names are case sensitive (no duplicate check) | check on |
| `-y` | write the XML form | packed `.sla` |
| `-x` | parser debugging, only in a `YYDEBUG` build | — |

Anything else: `Unknown option: ARG`, exit 1. No arguments: the usage
text of [run] below, exit 2. Java adds `-f` (unused token fields), `-d
MODULE`, `-i FILE` (options from a file) and gives `-a` its own directory
argument; its all-mode continues after failures (`SM/pcodeCPort/slgh_compile/
SleighCompileLauncher.java`, `SleighCompileOptions.java`).

File names (single mode): if the input name contains `.slaspec` anywhere
it is used as is, otherwise `.slaspec` is appended; with an output
argument, `.sla` is appended unless the name contains `.sla` ([run]
`sleigh -y in.slaspec out` writes `out.sla`); without one, the output is
the input up to `.slaspec` plus `.sla`; an input without `.slaspec` and
without an output is treated as an XML job file (`run_xml`). More than two
names: `Too many parameters`, exit 1; none: `Missing input file name`.

`run_compilation` (SC:3774-3819): open the file (`Unable to open
specfile: F`, return 2); parse; if the parse succeeded run `process`; if
there are no errors write the output (XML with `XmlEncode` when `-y`,
else header + zlib level −1 + packed); otherwise print `No output
produced` and return 2. A `LowlevelError` escaping anywhere prints
`Unrecoverable error: TEXT` and returns 2.

Messages (SC:2403-2458). `reportError(loc, msg)` prefixes `FILE:LINE: `
when a location is known; every error is finally printed to standard
error as `CURFILE:CURLINE - ERROR TEXT` where `CURFILE`/`CURLINE` are the
lexer's current file (base name) and line at the time of the report, and
counted; more than 1,000,000 errors: `Too many errors: Aborting`, exit 2.
Warnings print `WARN  TEXT` (two spaces). [run] usage text:

```
USAGE: sleigh [-x] [-dNAME=VALUE] inputfile [outputfile]
   -a              scan for all slaspec files recursively where inputfile is a directory
   -x              turns on parser debugging
   -y              write .sla using XML debug format
   -u              print warnings for unnecessary pcode instructions
   -l              report pattern conflicts
   -n              print warnings for all NOP constructors
   -t              print warnings for dead temporaries
   -e              enforce use of 'local' keyword for temporaries
   -c              print warnings for all constructors with colliding operands
   -s              treat register names as case sensitive
   -DNAME=VALUE    defines a preprocessor macro NAME with value VALUE
```

`process` (SC:2479-2508) — the passes after parsing, each skipped when
errors exist: `checkNops`; `checkCaseSensitivity`; "No default space
specified"; `checkConsistency` (section 10 d); `checkLocalCollisions`
(10 c.5); `buildPatterns` (10 c.1); `buildDecisionTrees` (10 c.6);
`buildXrefs` ("Duplicate (offset,size) pair for registers: A and B");
`checkUniqueAllocation` (9.9); `symtab.purge()` (9.10).

### 9.2 Symbols, scopes, ids
A symbol gets the next id (its index in one list) when it is added, and
the id of the current scope (SY `SymbolTable::addSymbol`). A duplicate
name in the same scope is an error (`Duplicate symbol name: N`; for
sections, which always go to the global scope, `Duplicate symbol name
'N'`). Lookup walks from the current scope up through parents.

Scopes: the global scope (0) is created by `define endian` — which must
therefore come first; each constructor, each macro definition and each
named section of a constructor (child of the constructor's scope) opens a
new scope, numbered in creation order. `error '}'` recovery resets to the
global scope.

`define endian` (`setEndian` → `predefinedSymbols`, SC:1982-2012) creates,
in this order: subtable `instruction` (id 0); the constant space and its
space symbol `const`; the OTHER space (index 1) and `OTHER`; the unique
space (index 2) and `unique`; `inst_start`; `inst_next`; `inst_next2`;
`epsilon`. User spaces therefore start at index 3.

The lexer returns a different token for an identifier depending on the
kind of symbol it currently names (LX `find_symbol`), `STRING` when it
names nothing; the grammar's alternatives are written against those
tokens. Consequences a tree-based port must reproduce: a name is
resolved **at the point of use against the symbols defined so far**; a
use before the definition is the "unknown …" error of that position, not
a forward reference; local symbols shadow global ones.

### 9.3 Definitions (grammar actions GR:166-270)
* **alignment** — `setAlignment`.
* **space** (`newSpace`, SC:2713-2740): size 0 → "Space definition 'N'
  missing size attribute"; processor space, language endianness, given
  size and word size, index = number of spaces so far, physical, delay 0
  for `register_space`, 1 for `ram_space` (dead-code delay the same);
  `default` twice → "Multiple default spaces -- 'A', 'B'"; then the space
  symbol.
* **varnodes** (`defineVarnodes`): names in order at `offset`, `offset +
  size`, …; `_` skips a slot without a symbol.
* **bitrange** (`defineBitrange`, SC:2800-2831): size 0 → "'N': size of
  bitrange is zero"; outside the varnode → "'N': bad bitrange"; when
  offset and width are whole bytes it becomes an ordinary varnode symbol
  (big-endian: offset + (bits − bitoffset − numb)/8; little: offset +
  bitoffset/8); otherwise a bitrange symbol (compile-time only).
* **token** (`defineToken`, `addTokenField`, SC:2640-2688): size not a
  multiple of 8 → "'N': token size must be multiple of 8" (and size/8+1
  is used); endianness from the `endian=` clause or the language; a token
  symbol; each field a value symbol over a `tokenfield` — errors "Field
  'F' starts at L and ends at H" (H < L), "Field 'F' high must be less
  than token size". `hex`/`dec` are recorded and never used.
* **context** (`addContextField`, SC:2690-2711): the same two checks
  ("Context field …", "… high must be less than context size"); fields are
  *collected*, not created. After the layout is locked a further field is
  "All context definitions must come before constructors".
* **context layout** (`calcContextLayout`, `calcContextVarLayout`,
  SC:2025-2084, 2515-2545): locked — once — when the lexer first sees, at
  top level, a `:` (a constructor), `attach` or `with` (LX:494-502).
  Fields are stable-sorted by (context register **name**, low bit).
  Per register: its size must be a multiple of 4 bytes ("Invalid size of
  context register 'R': must be a multiple of 4 bytes"). Fields are taken
  in sorted order in groups of overlapping fields (a field joins the
  group while its low ≤ the group's running max high); a field wider than
  32 bits → "Size of bitfield 'F' larger than 32 bits" (the test is
  `high − low > 32`), beyond the register → "Scope of bitfield 'F' extends
  beyond the size of context register". A group needing `alloc = max −
  min + 1` bits is placed at the running bit counter, first bumped to the
  next multiple of 32 if it would straddle a word. Each field of the
  group becomes a context symbol (**added to the symbol table now, in
  this sorted order**) with `contextfield(signed, startbit = field.low −
  min + base, endbit = base + alloc − 1 − (max − field.high))`, the
  register symbol, the original `low`/`high`, and the `flow` flag
  (`noflow` clears it). The counter continues across registers.
* **pcodeop** (`addUserOp`): one user-op symbol per name, index = running
  count.
* **attach** (SC:2849-2966): duplicate symbols in the list → warning
  "'attach values' list contains duplicate entries: N" (`names`,
  `variables` alike) and the duplicates are ignored; list length must be
  the field's maximum value + 1 → "Attach value 'F' (range 0..M) is wrong
  size for list (of K entries)" (`Attach name`, `Attach varnode`);
  `attach variables` with different sizes → "Attach statement contains
  varnodes of different sizes -- A != B". The value symbol is **replaced
  in place** by a value-map, name or varnode-list symbol with the same id
  and scope (`SymbolTable::replaceSymbol`). `_` in a list: value
  `0xBADBEEF`, an unusable name, or a null varnode. Context fields can be
  attached too (the context symbol is replaced — it is then no longer a
  context symbol in the file).

### 9.4 `with` blocks (SC:120-212, 3676-3690)
`with TABLE : PATTERN [CONTEXT] {` pushes a record; `TABLE` may be empty,
an existing table or a new name (creating the table). For a constructor
inside: its table, when it names none, is that of the **outermost**
enclosing block that names one (the stack is searched from the bottom),
else `instruction`; its pattern becomes `outer₁ & (outer₂ & … (own))` —
built by wrapping from the outermost to the innermost, each as
`EquationAnd(with, sofar)` — hence the innermost block's equation ends up
outermost in the tree and leftmost; its context changes are clones of
every block's changes, outermost block first, followed by its own.
Definitions and macros may appear inside a block.

### 9.5 Constructors (GR:279-296, 386; SC:2984-3098, 3364-3382, 3698-3735)
`createConstructor`: the table (explicit, from `with`, or root); id =
index in the table; line = current line; source index =
`indexer.index(current file name)` (first use allocates the next index);
a new scope; label counter reset.

*Display section.* Pieces arrive in order. A quoted string or run of
punctuation characters is literal text; white space is one piece `" "`;
`^` separates without text; an identifier is an **operand** — a new
operand symbol in the constructor's scope, index = position, plus a
print piece referring to it — except that the first identifier directly
after the `:` of a **root-table** constructor is literal text (the
mnemonic). (`^` directly after `:` in a sub-table: "Unexpected '^' at
start of print pieces".) `Constructor::addSyntax` (SY:1454-1481): an
all-space string counts as `" "`; the first `" "` piece sets `first`;
consecutive spaces collapse; text is appended to the previous piece
unless that piece is an operand or a space or the new piece is a space.
After the body, one trailing `" "` piece is removed
(`removeTrailingSpace`).

*Pattern section* (GR:303-345) builds equations (section 10 a) and, as a
side effect in order of appearance:

| Atom | Effect |
|---|---|
| `field = expr` etc. on a value/context/value-map/name/varlist symbol | a constraint equation |
| `operand = expr` | if the operand is already defined by a family symbol: a constraint on that symbol's field; otherwise error "Constraining currently undefined operand N" |
| `operand` (an identifier that is an operand of this constructor) | `OperandEquation`; `selfDefine`: look the same name up in the enclosing scopes ("No matching global symbol 'N'"); a value or context symbol defines the operand by its field **expression**; any other symbol becomes its defining symbol. Twice: "Redefining operand" |
| `inst_start`, `inst_next`, `inst_next2`, a varnode | an unconstrained equation over the symbol's expression |
| a family symbol or table **not** in the display | an *invisible* operand: a new operand symbol with that name (no print piece), defined as above, and an `OperandEquation` |

*Context block* (GR:346-355): `ctxfield = expr;` → a `context_op` on the
field's bit range, unless the expression mentions `inst_next` or
`inst_next2` ("Cannot use 'inst_next' or 'inst_next2' to set context
variable: N"); a non-context family symbol in such an expression is
"Global symbol N is not allowed in action expression";
`globalset(sym, ctxfield);` → a `commit` (word and mask from the field's
bit range, flow from the field); `operand = expr;` → defines the operand
by the expression and marks its offset irrelevant; an unknown name:
"Expecting context symbol, not N". Mask and shift of both forms:
`calc_maskword` (SY:2416-2429) — word = startbit/32 (both ends must be in
it: "Context field not contained within one machine int"), shift = 31 −
endbit%32, mask = the field's bits in place.

*Body*: `unimpl` → no templates. Otherwise section 9.6–9.8, then
`buildConstructor`: `finalizeSections` (9.8); on success the main and
named templates, the equation (with the `with` prefixes) and the context
list are attached. The scope is popped in every case.

### 9.6 P-code templates (PC; GR:366-520)
An expression is a list of ops plus the varnode holding its value.
**Temporaries**: `buildTemporary` makes an *unnamed* varnode in the
unique space at the next offset with size 0 (unknown); offsets start at 0
and advance by 256 (`MAX_UNIQUE_SIZE`) per allocation, across the whole
specification (SC:2465-2470). The final counter is `uniqbase`.

| Source | Result |
|---|---|
| operator `a op b` | ops of `a`, ops of `b`, then `op(tmp ← a, b)`; `>`/`>=` and their signed and float forms swap operands and use the `<`/`<=` opcode |
| unary, built-in function of one argument | ops, then `op(tmp ← a)` |
| `carry`/`scarry`/`sborrow(a,b)`, `newobject(a[,b])` | as binary |
| `*[space]:n p`, `*:n p`, `*p` | `LOAD(tmp ← spaceconst, p)`, space constant of size 8; size `n` forced on the result when given; default space = the default code space |
| `userop(args…)` | args' ops in order, then `CALLOTHER(tmp ← const index:4, args…)`; as a statement, no output |
| `cpool(a, b, …)` | `CPOOLREF`, at least two inputs ("Must be at least two inputs to cpool") |
| integer `k`, `k:n` | constant, size 0 or `n`; `&v`, `&:n v`: constant = the varnode's offset (byte offset converted to addressable units for a fixed varnode), size `n` or the space's address size |
| `sym(k)` | `SUBPIECE(tmp ← sym, k)` |
| `sym:n` | bit range `[0, 8n)`; `sym[lo,len]`; a bitrange symbol — `createBitRange` (PC): an operand of unknown size and a byte-aligned range starting at 0 just takes the size; a byte-aligned range of a known-size or handle varnode is a *truncated varnode* (fixed varnode: offset adjusted by endianness; handle: an offset-plus constant with the byte offset); otherwise `INT_RIGHT` by the bit offset (if non-zero), `SUBPIECE` (if the result is narrower; a byte-aligned offset is folded into its constant), `INT_AND` mask (if the width is not whole bytes and does not reach the top). Errors: "Size of bitrange is zero", "Bitrange is bad", "Superfluous bitrange", "Illegal masked bitrange producing varnode larger than 64 bits: N", `Requested bit range out of bounds`, `Could not construct requested bit range` |
| `v = expr;` (existing symbol) | `setOutput`: if the expression's value is an unnamed temporary, the last op's output is replaced by `v`; otherwise `COPY(v ← value)` |
| `name = expr;`, `local name = expr;`, with `:n` | a new temporary (size `n`, else the expression's size if known) receives the value as above; **then** a varnode symbol `name` at that temporary is added to the current scope; without `local` and with `-e`: "Must use 'local' keyword to define symbol 'N'" |
| `local name;`, `local name:n;` | a new temporary and symbol; no op |
| `*[space]:n p = expr;` | ops of `p`, ops of `expr`, `STORE(spaceconst, p, value)`; size `n` forced on the value |
| `v[lo,len] = expr;`, bitrange symbol `= expr;` | `assignBitRange`: value forced to `(len+7)/8` bytes; a truncated varnode if possible (`COPY`), else `INT_AND(tmp ← v, mask)`, `INT_ZEXT` of the value if `v` is wider, `INT_LEFT` by `lo` if non-zero, `INT_OR(v ← …)`. Errors: "Size of bitrange is zero", "Assigned bitrange is bad", "Assigning to bitrange is superfluous", "Assigned bitrange extends past first 64 bits" |
| `goto dest;`, `call dest;` | `BRANCH`/`CALL`; `dest`: `inst_start`/`inst_next`/`inst_next2` → (current space, that address, address size); an integer → (current space, k, address size); `k[space]` → fixed; an operand → the operand's varnode, **and the operand is marked as a code address**; `<label>` → constant-space varnode with a `const_relative` label number, size 4 |
| `if (c) goto dest;` | ops of `c`, `CBRANCH(dest, c)` |
| `goto [e];`, `call [e];`, `return [e];` | `BRANCHIND`/`CALLIND`/`RETURN` |
| `<label>` | `LABEL` directive; labels are numbered per section in order of first appearance (use or placement); "Label 'L' is placed more than once" |
| `build operand;` | `BUILD` with the operand's index |
| `delayslot(n);` | `DELAY_SLOT`; a second in one section: "Multiple delayslot declarations" |
| `crossbuild v, section;` | `CROSSBUILD(v, const section id:4)`; sets the crossbuild flag (9.9); an unknown section name creates the section symbol |
| `macro(args…);` | 9.7 |
| `export v;` | export handle from the varnode (space, size, offset; not a pointer) |
| `export *[space]:n v;` | export of a dereference: handle (space, size n, pointer = v) plus **a newly allocated temporary** as its temporary storage |

Errors of this layer: "Unknown varnode parameter: N", "Unknown assignment
varnode: N", "Unknown export varnode: N", "Unknown pointer varnode: N",
"Unknown jump destination: N", "Subtable not attached to operand: N",
"Redefinition of symbol: N", "Illegal truncation on left-hand side of
assignment", "Illegal subpiece on left-hand side of assignment", "Must
specify an indirect parameter for return", "Parsed integer is too big
(overflow)", `Localtemp size mismatch`, `Expression has no output`.

A symbol used as a varnode yields (`getVarnode`, SY): a varnode symbol →
its fixed varnode; an operand → handle references (space, offset, size),
with size forced to constant 0 when the operand is defined by an
expression or by a value-map or name symbol; `inst_start` etc. →
(constant space, the address constant, size 0); `epsilon` → constant 0.
A section whose op list is empty and which exports nothing is recorded
as a NOP ("FILE:LINE: NOP detected").

### 9.7 Macros (SC:1785-1928, 3180-3255, 3397-3434, 3737-3756)
`macro name(p₁, …) { body }`: a macro symbol (index = number of macros so
far), a scope, an operand symbol per parameter (index i, no constructor);
the body is compiled like a section — parameters are handle references —
with its own label numbering. At the end: label check ("In definition of
macro 'N': …"), nested macros expanded ("Could not expand submacro in
definition of macro 'N'"), sizes propagated as far as possible. A macro
must be defined before use.

A use becomes a `MACROBUILD` placeholder op (inputs: constant macro
index, then each argument's value varnode, after the arguments' own ops).
Wrong argument count: "Invocation of macro 'N' passes too many (few)
parameters". If a macro's parameter is used as a code address in its
body, the caller's operand passed for it is marked as a code address.

Expansion (`expandMacros`, at the end of each section) replaces each
placeholder by a copy of the macro's ops, in order: label numbers (in
`LABEL` directives and relative branch constants) are offset by the
number of labels the section had before this expansion, and the
section's label count grows by the macro's; every handle reference to
parameter *i* is replaced by the corresponding part of the argument
(`VarnodeTpl::transfer`, `ConstTpl::transfer`): an offset-plus reference
to an argument that is a fixed varnode adds the byte offset; to a handle
argument stays an offset-plus on that handle; if the argument is a local
temporary or has unknown size, a `SUBPIECE` into a **newly allocated
temporary** is inserted before the op (needs a known size: "Problem with
bit range operator in macro"); such a truncation as an *output* is
"Cannot currently assign to bitrange of macro parameter that is a
temporary". **The macro body's own temporaries are not renamed**: every
expansion uses the offsets allocated when the macro was defined.

### 9.8 Finishing a constructor's sections (`finalizeSections`, SC:3436-3510)
For the main section, then each named section in section-id order:

1. Label check of the section's scope: "Label <L> was placed but not
   used", "Label <L> was referenced but never placed".
2. Macro expansion ("Could not expand macros").
3. `BUILD` completion (`fillinBuild`, SEM:864-891): a `build` of a
   non-subtable operand is "Unnecessary BUILD statements", two of the
   same operand "Duplicate BUILD statements"; for every subtable operand
   without one, a `BUILD` is inserted **at the front** of the section, in
   ascending operand order each at position 0 (so they end up in
   descending order).
4. Size propagation (`propagateSize`, PC:234-262): repeatedly, for every
   op that still has a zero-size varnode, `fillinZero` — same-size ops
   (COPY, arithmetic, logical, float arithmetic) take the size of the
   output if known else of the first sized input; comparisons and boolean
   ops force the output to 1 and inputs to each other's size; shifts tie
   output and first input, and force the shift amount to 4 if unknown…
   (note the missing `break`: a shift falls through into the `SUBPIECE`
   rule, which forces input 1 to size 4); `SUBPIECE` forces its constant
   to 4; `CPOOLREF` ties output and first input and forces the rest to 8.
   Setting the size of a local temporary sets it on every occurrence of
   that offset in the section. Until nothing changes; any op still
   unsized: "Could not resolve at least 1 variable size".
5. Main section only: an export in a root constructor is "Cannot have
   export statement in root constructor"; an export of unknown size takes
   the size of a use of that temporary in the section (`forceExportSize`),
   else "Size of export is unknown".
6. A `delayslot` outside the root table: warning "Delay slot used in
   non-root constructor table "T" constructor starting at line N";
   `maxdelay` = the largest count seen.

Errors are reported as "in table "T" constructor starting at line N"
followed by one line per problem prefixed with the section ("   Main
section: ", "   NAME section: "), all at the constructor's location.

Named sections: `<<name>>` between sections; the section symbol is global
and gets the next section id on first mention (by a section header or a
`crossbuild`); `numsections` = number of section symbols.

### 9.9 Unique offsets and crossbuild (`checkUniqueAllocation`, SC:3566-3674)
If any `crossbuild` was compiled: `uniqmask` = 0xff; in every template of
every constructor (root table, then tables in definition order), every
unique-space varnode offset, and the unique offsets in export handles,
gets 8 zero bits inserted at bit 8 (`(off >> 8) << 16 | (off & 0xff)`),
making room for the address bits the runtime ORs in; and `uniqbase`
becomes `(uniqbase + 0x100) << 8`.

### 9.10 What is written (`SymbolTable::purge`, `renumber`, SY:296-380)
Removed before writing: every symbol in a non-global scope except
operands (locals, labels); global space, token, epsilon, section,
bitrange and macro symbols (with the macro's parameter symbols); every
subtable that never got a pattern (unreachable from `instruction` —
warning "Unreferenced table 'T'"), with its constructors' operand
symbols. Scopes left empty are removed; scopes and symbols are then
renumbered densely in their old order. So ids in the file are the
creation order with the removed ones squeezed out, and a constructor
without operands has no scope in the file.

### 9.11 Other checks of this half
`checkNops` and `checkCaseSensitivity`: section 10 d.8. Label checks,
BUILD checks: 9.8. `-e`: 9.6.


## 10. The compiler, back half: patterns, operand offsets, decision trees, checks

Compiled from line-by-line reading notes of the C++ (nothing in this
section was run). Citations: **PE** = `CPP/slghpatexpress.cc`/`.hh`,
**PT** = `slghpattern.cc`/`.hh`, **SY** = `slghsymbol.cc`/`.hh`, **SC** =
`slgh_compile.cc`/`.hh`, **SEM** = `semantics.cc`/`.hh`. `uintm` is 32
bits, `intb` is a signed 64-bit integer. Spot-checked against the source
by the author of this inventory: `getScore`/`chooseOptimalField`
(SY:2110-2201), the start of `orderPatterns`, `OrPattern::doOr`
(PT:931-956) — one addition from that check: `OrPattern::doOr` with a
negative shift calls `shiftInstruction` on the **left operand's own
stored disjuncts** (not the copies), so it changes the pattern object it
was called on; anything that reads that pattern afterwards sees the
shifted blocks.

The order of the passes is in section 9.1 (`process`). P-code checks and
optimisation run **before** operand reordering, which happens inside
`buildPatterns`; templates are remapped afterwards (c.4).

### 10 (a) Pattern equations → patterns

#### a.1 TokenPattern data and constructors

Fields: `Pattern *pattern; vector<Token*> toklist; bool leftellipsis, rightellipsis` (PE.hh:23-27). Token size is in bytes (context.hh:29,34).

| Constructor | Result | Cite |
|---|---|---|
| `TokenPattern()` | `InstructionPattern(true)`, no tokens, no ellipsis | PE.cc:263-269 |
| `TokenPattern(bool tf)` | `InstructionPattern(tf)`, no tokens | PE.cc:271-277 |
| `TokenPattern(Token*)` | TRUE instruction pattern, `toklist=[tok]` | PE.cc:279-286 |
| `TokenPattern(tok,value,bitstart,bitend)` | `toklist=[tok]`; block from `buildBigBlock(tok->getSize(),bitstart,bitend,value)` if the token is big-endian, else `buildLittleBlock(...)`; wrapped in `InstructionPattern` | PE.cc:288-302 |
| `TokenPattern(value,startbit,endbit)` (context) | `size=(endbit/8)+1`; `buildBigBlock(size,size*8-1-endbit,size*8-1-startbit,value)`; wrapped in `ContextPattern`; no tokens | PE.cc:304-314 |
| private `TokenPattern(Pattern*)` | shell | PE.hh:32 |

- The copy constructor and `operator=` both store `tokpat.pattern->simplifyClone()` (PE.cc:316-335). Every assignment to an equation's `resultpattern` therefore simplifies (see b.6).
- Whether returning a `TokenPattern` by value triggers an extra `simplifyClone` depends on NRVO. This is harmless as far as I can tell, because `simplifyClone` looks idempotent (my reasoning, not tested).
- `alwaysTrue/alwaysFalse/alwaysInstructionTrue` delegate to the `Pattern` (PE.hh:52-54).
- `getMinimumLength()` = sum of `toklist[i]->getSize()` (PE.cc:448-455).

#### a.2 Bit-block builders

Bit numbering inside blocks: bit 0 is the most significant bit of byte 0 (PE.cc:157-161).

**`buildSingle(startbit,endbit,byteval)`** (PE.cc:155-175):
1. `size = endbit-startbit+1`.
2. `offset = 0`; while `startbit >= 8`: `offset += 1; startbit -= 8; endbit -= 8`.
3. `mask = 0xFFFFFFFF << (32-size)`.
4. `byteval = (byteval << (32-size)) & mask`.
5. `mask >>= startbit; byteval >>= startbit`.
6. Return `PatternBlock(offset,mask,byteval)`.

Only the low `size` bits of the value are used. Callers always pass pieces of at most 8 bits within one byte.

**`buildBigBlock(size,bitstart,bitend,value)`** (PE.cc:177-205):
1. `startbit = 8*size-1-bitend; endbit = 8*size-1-bitstart`.
2. While `endbit >= startbit`:
   - `tmpstart = endbit - (endbit & 7)`; if `tmpstart < startbit` then `tmpstart = startbit`.
   - `tmp = buildSingle(tmpstart,endbit,(uintm)value)`.
   - `block = (block==null) ? tmp : block->intersect(tmp)`.
   - `value >>= (endbit-tmpstart+1)` — a signed `intb` shift.
   - `endbit = tmpstart-1`.
3. Return `block`.

**`buildLittleBlock(size,bitstart,bitend,value)`** (PE.cc:207-261):
1. `startbit=(bitstart/8)*8; endbit=(bitend/8)*8; bitend%=8; bitstart%=8`.
2. If `startbit==endbit`: `startbit += 7-bitend; endbit += 7-bitstart; block = buildSingle(startbit,endbit,(uintm)value)`.
3. Otherwise:
   - `block = buildSingle(startbit,startbit+(7-bitstart),(uintm)value)`; `value >>= (8-bitstart)`; `startbit += 8`.
   - While `startbit != endbit`: intersect in `buildSingle(startbit,startbit+7,(uintm)value)`; `value >>= 8; startbit += 8`.
   - Finally intersect in `buildSingle(endbit+(7-bitend),endbit+7,(uintm)value)`.

The `size` argument is unused in the little-endian builder.

For context fields, the arithmetic at PE.cc:310-312 cancels inside `buildBigBlock`, so context bits `startbit..endbit` are used directly in MSB-first numbering.

#### a.3 `resolveTokens(tok1,tok2)` (PE.cc:21-153)

Sets the result's `toklist` and ellipsis flags and returns a shift `sa`. `len1`, `len2` are the token-list lengths.

1. `leftellipsis=rightellipsis=false; ressa=0; reversedirection=false; minsize=min(len1,len2)` (27-31).
2. If `minsize==0` (32-49):
   - If tok1 has no tokens and neither ellipsis: copy tok2's list and both flags, return 0.
   - Else if tok2 has no tokens and neither ellipsis: copy tok1's, return 0.
   - Otherwise fall through.
3. Case analysis (51-115):
   - **tok1.left**: `reversedirection=true`.
     - tok2.right → throw `"Right/left ellipsis"`.
     - else tok2.left → `leftellipsis=true`.
     - else if `len1 != minsize` → throw `"Mismatched pattern sizes -- <len1> != <minsize>"`.
     - else if `len1==len2` → throw `"Pattern size cannot vary (missing '...'?)"`.
     - Note: when tok2 has no ellipsis the result's left ellipsis stays false.
   - **else tok1.right**:
     - tok2.left → throw `"Left/right ellipsis"`.
     - else tok2.right → `rightellipsis=true`.
     - else the same two size checks and messages as above.
   - **else** (tok1 has no ellipsis):
     - tok2.left: `reversedirection=true`; if `len2 != minsize` → throw `"Mismatched pattern sizes -- <len2> != <minsize>"`; else if `len1==len2` → throw `"Pattern size cannot vary (missing '...'?)"`.
     - tok2.right: the same two checks, no reverse.
     - neither: if `len2 != len1` → throw `"Mismatched pattern sizes -- <len2> != <len1>"`.
4. If reversed (116-135):
   - Compare the last `minsize` tokens pairwise by pointer, from the end. On mismatch throw `"Mismatched tokens when combining patterns -- <p1> != <p2>"`. The operands printed are `Token*` pointers, so this text is pointer-dependent.
   - `ressa` = sum of sizes of the extra leading tokens of the longer list (tok2's if `len1<=len2`, else tok1's).
   - If `len1 < len2`: `ressa = -ressa`.
5. If not reversed: compare the first `minsize` tokens pairwise; same exception text (137-145).
6. `toklist = (len1 <= len2) ? tok2.toklist : tok1.toklist`; return `ressa` (148-152).

Meaning of `sa` (from PT.cc:543-554): `sa>0` shifts the second operand's instruction bits right by `sa` bytes; `sa<0` shifts the first operand's by `-sa`.

#### a.4 `doAnd`, `doOr`, `doCat`, `commonSubPattern`

**`doAnd(tokpat)`** — `sa = res.resolveTokens(*this,tokpat); res.pattern = pattern->doAnd(tokpat.pattern,sa)` (PE.cc:337-345).

**`doOr(tokpat)`** — same with `pattern->doOr` (347-355).

**`doCat(tokpat)`** (357-395):
1. `res` starts with this pattern's ellipsis flags and `toklist`.
2. If `rightellipsis || tokpat.leftellipsis`:
   - If `rightellipsis` and `!tokpat.alwaysInstructionTrue()` → throw `"Interior ellipsis in pattern"`.
   - If `tokpat.leftellipsis`: if `!alwaysInstructionTrue()` → throw the same; `res.leftellipsis=true`.
   - `sa=-1`. tokpat's tokens are not appended, and `res.rightellipsis` keeps this pattern's value.
3. Else: `sa` = sum of this pattern's token sizes; append tokpat's tokens; `res.rightellipsis = tokpat.rightellipsis`.
4. If `res.rightellipsis && res.leftellipsis` → throw `"Double ellipsis in pattern"`.
5. `res.pattern = pattern->doAnd(tokpat.pattern, sa<0 ? 0 : sa)`.

**`commonSubPattern(tokpat)`** (397-446):
1. If either has a left ellipsis: if either has a right ellipsis → throw `"Right/left ellipsis in commonSubPattern"`; `reverse=true`.
2. `res.left = l1||l2; res.right = r1||r2`.
3. `minnum`/`maxnum` = smaller/larger list length.
4. Reverse: for `i` in `0..minnum`, compare tokens from the end; while equal, insert at the front of `res.toklist`; break at the first mismatch. If `i<maxnum` afterwards: `res.left=true`.
5. Forward: the same from the front with `push_back`; if `i<maxnum`: `res.right=true`.
6. `res.pattern = pattern->commonSubPattern(tokpat.pattern,0)`. The shift is always 0, even in the reversed case with different lengths (line 444).

#### a.5 PatternExpression at compile time

| Class | genMinPattern(ops) | genPattern(v) | min / max | Cite |
|---|---|---|---|---|
| TokenField | `TokenPattern(tok)` | `TokenPattern(tok,v,bitstart,bitend)` | 0 / `zero_extend(~0,bitend-bitstart)` = 2^n−1 | PE.hh:102-105, PE.cc:597-602 |
| ContextField | `TokenPattern()` | `TokenPattern(v,startbit,endbit)` | 0 / 2^n−1 | PE.hh:122-125, PE.cc:656-660 |
| ConstantValue | `TokenPattern()` | `TokenPattern(val==v)` | val / val | PE.hh:136-139 |
| Start/End/Next2InstructionValue | `TokenPattern()` | `TokenPattern()` (TRUE) | 0 / 0 | PE.hh:149-152, 162-165, 175-178 |
| OperandValue | `ops[index]` | throws `"Operand used in pattern expression"` (also `minValue`/`maxValue`) | — | PE.hh:195, PE.cc:746-771 |
| Binary / Unary | `TokenPattern()` | n/a | n/a | PE.hh:213, 230 |

- The sign flag is ignored for min/max: `zero_extend` is at address.hh:615-620. A signed field's range at compile time is `[0, 2^n−1]`.
- TokenField constructor (PE.cc:565-582): big-endian `byteend=(size*8-bitstart-1)/8`, `bytestart=(size*8-bitend-1)/8`; little-endian `bytestart=bitstart/8`, `byteend=bitend/8`; `shift=bitstart%8`.
- ContextField constructor (PE.cc:633-642): `startbyte=startbit/8; endbyte=endbit/8; shift=7-(endbit%8)`.
- `listValues`: a PatternValue pushes itself (PE.hh:83); Binary does left then right (214-215); Unary recurses (231-232).
- `getMinMax`: a PatternValue pushes `minValue()`/`maxValue()` (84-85); Binary left then right (216-217); Unary recurses (233-235). An OperandValue leaf therefore throws.
- `getSubValue(replace,listpos)`: a PatternValue returns `replace[listpos++]` (PE.hh:86). Binary evaluates left first, then right, and applies `+ - * << >> & | ^ /` on `intb` (PE.cc:910-1108). Unary applies `-` or `~` (1125-1152). OperandValue forwards to its operand's defining expression (793-798), which is a null dereference if there is none; I did not check whether that is reachable.
- These are native C++ signed 64-bit operations. Overflow, shift counts ≥64 or negative, and division by zero are undefined behaviour in C++, so they are host-dependent.
- `inst_start`, `inst_next` and `inst_next2` behave as the constant 0 and contribute a TRUE pattern in constraints.

#### a.6 `genPattern` for each PatternEquation

Each stores into a mutable `resultpattern` (PE.hh:354).

- **OperandEquation**: `resultpattern = ops[index]` (PE.cc:1197-1201).
- **UnconstrainedEquation**: `resultpattern = patex->genMinPattern(ops)` (1243-1247).
- **EquationAnd / Or / Cat**: `left->genPattern(ops); right->genPattern(ops);` then `left.doAnd(right)`, `left.doOr(right)`, `left.doCat(right)` respectively (1483-1489, 1532-1538, 1581-1587).
- **EquationLeftEllipsis / RightEllipsis**: generate the child, copy its pattern, set the flag (1632-1638, 1658-1664).

**ValExpressEquation family** (`lhs` is a PatternValue, `rhs` an expression):

Helpers:
- `advance_combo(val,min,max)` (1162-1176): an odometer where index 0 varies fastest. `i=0; while i<n { val[i]+=1; if val[i]<=max[i] return true; val[i]=min[i]; i+=1 } return false`.
- static `buildPattern(lhs,lhsval,semval,val)` (1178-1187): `p = lhs->genPattern(lhsval)`; then for `i` ascending, `p = p.doAnd(semval[i]->genPattern(val[i]))`.

Common prologue (e.g. 1288-1298): `lhsmin=lhs->minValue(); lhsmax=lhs->maxValue(); rhs->listValues(semval); rhs->getMinMax(min,max); cur=min; count=0`.

**EqualEquation** (1285-1312):
1. `do {`
2. `val = rhs->getSubValue(cur)`.
3. If `val>=lhsmin && val<=lhsmax`: `P = buildPattern(lhs,val,semval,cur)`; if `count==0` then `resultpattern = P`, else `resultpattern = resultpattern.doOr(P)`; `count++`.
4. `} while(advance_combo(cur,min,max))`.
5. If `count==0` → throw `"Equal constraint is impossible to match"`.

**The other five** (1314-1467) use the same outer loop. Inside, `for(lhsval=lhsmin; lhsval<=lhsmax; ++lhsval)` in ascending order, with a skip condition, then the same assign-or-`doOr` step with `buildPattern(lhs,lhsval,semval,cur)`:

| Equation | Skip when | Exception text when `count==0` |
|---|---|---|
| NotEqual | `lhsval == val` | `"Notequal constraint is impossible to match"` |
| Less | `lhsval >= val` | `"Less than constraint is impossible to match"` |
| LessEqual | `lhsval > val` | `"Less than or equal constraint is impossible to match"` |
| Greater | `lhsval <= val` | `"Greater than constraint is impossible to match"` |
| GreaterEqual | `lhsval < val` | `"Greater than or equal constraint is impossible to match"` |

Consequences, all derived from the code above:
- `field = 5` gives one disjoint pattern: the lhs block ANDed with `TokenPattern(true)` from the constant.
- `field < 5` gives an OrPattern of 5 disjoint patterns (values 0..4, ascending). There is no mask merging or minimisation; each disjunct later becomes a separate decision-tree entry.
- `field = other + 1` enumerates `other` from 0 to its max. For each value whose result lies within `[0, lhsmax]`, it adds `lhs==val AND other==cur`.
- A constant outside `[0, 2^n−1]`, such as a negative literal compared against a signed field, never matches. I verified only this back end; the parser may normalise such values first (not checked).
- Disjunct order is: rhs combinations (first listed value fastest), then `lhsval` ascending. This holds except for the `doOr` reorderings in b.5.
- Every assignment simplifies: FALSE disjuncts are dropped and a TRUE disjunct collapses the whole pattern to TRUE.

#### a.7 `resolveOperandLeft` and `OperandResolve`

State: `operands&`, `base=-1`, `offset=0`, `cur_rightmost=-1`, `size=0` (PE.hh:339-347). `base==-2` means "no anchor".

- **OperandEquation** (PE.cc:1203-1219):
  1. `sym = state.operands[index]`.
  2. If `sym->isOffsetIrrelevant()`: `offsetbase=-1; reloffset=0; return true` (state untouched).
  3. If `state.base==-2` return false.
  4. `sym->offsetbase=state.base; sym->reloffset=state.offset; state.cur_rightmost=index; state.size=0; return true`.
- **UnconstrainedEquation / ValExpressEquation** (1249-1258, 1274-1283): `state.cur_rightmost=-1; state.size = (own resultpattern has either ellipsis) ? -1 : resultpattern.getMinimumLength(); return true`.
- **EquationAnd and EquationOr** (identical code; 1491-1509, 1540-1558):
  1. `cur_rightmost=-1; cur_size=-1`.
  2. Resolve the **right** child first; return false on failure.
  3. If `state.cur_rightmost!=-1 && state.size!=-1`: save both.
  4. Resolve the left child; return false on failure.
  5. If `state.cur_rightmost==-1 || state.size==-1`: restore the saved pair.
- **EquationCat** (1589-1623):
  1. Resolve left; return false on failure.
  2. `cur_base=state.base; cur_offset=state.offset`.
  3. If left's pattern has neither ellipsis: `state.offset += left.getMinimumLength()`. Else if `state.cur_rightmost!=-1`: `state.base=state.cur_rightmost; state.offset=state.size`. Else if `state.size!=-1`: `state.offset += state.size`. Else `state.base=-2`.
  4. `cur_rightmost=state.cur_rightmost; cur_size=state.size`.
  5. Resolve right; return false on failure.
  6. `state.base=cur_base; state.offset=cur_offset`.
  7. If `state.cur_rightmost==-1` and `state.size!=-1 && cur_rightmost!=-1 && cur_size!=-1`: `state.cur_rightmost=cur_rightmost; state.size += cur_size`.
- **EquationLeftEllipsis** (1640-1650): save base; `state.base=-2`; resolve child; restore base.
- **EquationRightEllipsis** (1666-1673): resolve child; `state.size=-1`.

#### a.8 `operandOrder`

- Default is a no-op (PE.hh:361).
- OperandEquation: `sym=ct->getOperand(index)`; if not marked, push and `setMark` (PE.cc:1221-1229).
- And/Or/Cat: left then right (1511-1516, 1560-1565, 1625-1630).
- Ellipsis nodes recurse (1652-1656, 1675-1679).

---

### 10 (b) slghpattern

#### b.1 PatternBlock representation

Fields: `offset` (byte index of the first stored mask byte), `nonzerosize`, `maskvec`, `valvec` (32-bit words) (PT.hh:24-28).

- Word `k` covers bytes `offset+4k .. offset+4k+3`, with the MSB as the first byte. This follows from `getMask` (PT.cc:405-435) and `isInstructionMatch` (464-475).
- `alwaysTrue ⇔ nonzerosize==0`; `alwaysFalse ⇔ nonzerosize==-1` (PT.hh:44-45).
- `getLength()=offset+nonzerosize` (PT.hh:41). For a FALSE block this is −1.

Constructors:
- `PatternBlock(off,msk,val)`: one word, `nonzerosize=4`, then `normalize()` (PT.cc:229-237).
- `PatternBlock(bool)`: `offset=0`, `nonzerosize = tf?0:-1` (239-247).
- `clone` copies verbatim (283-293).
- `shift(sa)`: `offset += sa; normalize()` (PT.hh:40).

**`normalize()`** (PT.cc:156-227):
1. If `nonzerosize<=0`: `offset=0`; clear both vectors; return. `nonzerosize` is kept.
2. Drop leading mask words equal to 0 (and the matching value words); `offset += 4` for each.
3. If non-empty:
   - `suboff` = number of leading zero bytes of `maskvec[0]`.
   - If `suboff != 0`: `offset += suboff`; shift both vectors left by `suboff` bytes as one big-endian bit string. For `i<n-1`: `v[i] = (v[i]<<(8*suboff)) | (v[i+1] >> (8*(4-suboff)))`; last word `<<= 8*suboff`.
   - Erase trailing all-zero mask words (and value words).
4. If the mask is empty: `offset=0; nonzerosize=0; return`.
5. `nonzerosize = 4*maskvec.size()` minus the number of trailing zero bytes of the last mask word.

Result: a canonical form. `offset` is the first nonzero mask byte, there are no trailing zero words, and `nonzerosize` is the byte span to the last nonzero mask byte. These fields and words are what `encode` writes (PT.cc:490-503), so they must match exactly.

**`getMask(startbit,size)` and `getValue`** (405-462):
- They return `size` bits (1..32), right-aligned, starting at absolute bit `startbit`.
- The code subtracts `8*offset`, then uses unsigned division and modulo by 32, relying on wraparound for negative values (comment at 409-412).
- By my analysis this is equivalent to: treat the stored words as a bit string that is zero outside `[0, 32*len)` and extract `size` bits at `startbit - 8*offset`. This is a host-`size_t` trick; implement the zero-extended semantics directly.

#### b.2 Block operations

- **`intersect(b)`** (323-355):
  1. If either is FALSE, return FALSE.
  2. `maxlength = max(getLength(), b->getLength())`.
  3. For byte `offset = 0,4,8,… < maxlength`: read 32-bit `mask1,val1,mask2,val2` at bit `offset*8`.
  4. `common = mask1&mask2`; if `(common&val1) != (common&val2)`, the result is FALSE.
  5. Push `mask1|mask2` and `(mask1&val1)|(mask2&val2)`.
  6. `nonzerosize=maxlength; normalize()`.
- **`commonSubPattern(b)`** (295-321): same loop with `resmask = mask1 & mask2 & ~(val1^val2)` and `resval = val1&val2&resmask`; `nonzerosize=maxlength; normalize()`.
  - There is no FALSE special case. FALSE with X yields TRUE; FALSE with FALSE yields FALSE (derived from `getLength()` being −1).
- **`specializes(op2)`** (357-378): over `8*op2->getLength()` bits in chunks of at most 32, require `(mask1&mask2)==mask2` and `(value1&mask2)==(value2&mask2)`.
- **`identical(op2)`** (380-403): over the max of the two lengths, require `mask1==mask2` and `(mask1&value1)==(mask2&value2)`.
- `PatternBlock(a,b)` and `PatternBlock(vector)` are intersect folds (249-281).

#### b.3 DisjointPattern helpers

`getBlock(context)` returns:
- Instruction: its block for `context=false`, null for `true` (PT.hh:87).
- Context: the reverse (109).
- Combine: `context->getBlock()` or `instr->getBlock()` (132).

Helpers:
- `getMask/getValue(startbit,size,context)`: the block's value, or 0 if null (PT.cc:21-37).
- `getLength(context)`: the block's length, or 0 if null (39-46).
- **`specializes(op2)`** (48-67): for the instruction block, then the context block: if op2's block is non-null and not alwaysTrue, this pattern's block must be non-null and `specializes` it.
- **`identical(op2)`** (69-103): per block kind:
  - If op2's block exists: when this pattern's is null, op2's must be alwaysTrue; otherwise the blocks must be `identical`.
  - If op2's block is null: this pattern's must be null or alwaysTrue.
- **`resolvesIntersect(op1,op2)`** (105-139): per block kind:
  1. `inter` = whichever of op1's/op2's blocks is non-null, or their `intersect` if both are.
  2. If `inter` is null: OK iff this pattern's block is null.
  3. Else if this pattern's block is null: false.
  4. Else `thisblock->identical(inter)`.
  - Both the instruction and context kinds must pass.
- `numDisjoint()` is 0 for disjoint patterns and `orlist.size()` for OrPattern (PT.hh:74,161). `getDisjoint(i)` is `orlist[i]` (162).

#### b.4 `doAnd(b,sa)`

- **Instruction** (PT.cc:523-556):
  1. If b is Or → `b->doAnd(this,-sa)`.
  2. If b is Combine → `b->doAnd(this,-sa)`.
  3. If b is Context → `CombinePattern(b clone, this clone)`, where this clone is shifted by `-sa` if `sa<0`.
  4. Else (Instruction): if `sa<0`, `(this shifted by -sa) ∩ b`; else `this ∩ (b shifted by sa)`.
- **Context** (638-647): if b is not Context → `b->doAnd(this,-sa)`; else Context of the block intersect.
- **Combine** (706-735):
  1. If b is Or → `b->doAnd(this,-sa)`.
  2. b Combine → `Combine(context.doAnd(b.context,0), instr.doAnd(b.instr,sa))`.
  3. b Instruction → `Combine(context clone, instr.doAnd(b,sa))`.
  4. b Context → `Combine(context.doAnd(b,0), instr clone shifted by -sa if sa<0)`.
- **Or** (884-908):
  1. b not Or → `[e.doAnd(b,sa) for e in orlist]`.
  2. b Or → nested loop, this pattern's list outer and b's inner: `e.doAnd(f,sa)`.
  3. Wrap in a new OrPattern; no simplification here.

#### b.5 `doOr(b,sa)` — operand order is not always preserved

- **Instruction** (591-609):
  1. If b is Or or Combine → `b->doOr(this,-sa)`. The result lists b's disjuncts first, then this one.
  2. Else `Or(this clone, b clone)`, with this clone shifted by `-sa` if `sa<0`, otherwise b's clone shifted by `sa`.
- **Context** (628-636):
  1. If b is not Context → `b->doOr(this,-sa)`. So Context OR Instruction gives `Or(instruction, context)`, reversed.
  2. Else `Or(this, b)`.
- **Combine** (761-775):
  1. If b is Or → `b->doOr(this,-sa)` (b's list first).
  2. Else `Or(this clone, b clone)` with the same shift rule as Instruction.
- **Or** (931-956):
  1. `newlist` = simplifyClones of this pattern's elements.
  2. If `sa<0`: `shiftInstruction(-sa)` is applied to the **original** elements of this pattern, not the clones in `newlist` (lines 940-942). Net effect: nothing in the result is shifted.
  3. Append b's clone, or the clones of b's elements in order.
  4. If `sa>0`: shift **every** element of `newlist` by `sa`, including this pattern's own (950-952).
  5. Return `OrPattern(newlist)`.

Steps 2 and 4 look like upstream bugs. Nonzero `sa` in `doOr` only arises from left-ellipsis alignment, but the behaviour must be reproduced as written.

Summary of disjunct order for `A.doOr(B)`:

| A | B | Result order |
|---|---|---|
| Instruction | Instruction or Context | [A, B] |
| Instruction | Combine | [B, A] |
| Instruction | Or | [B…, A] |
| Context | Context | [A, B] |
| Context | Instruction | [B, A] |
| Context | Combine | [B, A] |
| Context | Or | [B…, A] |
| Combine | Instruction, Context or Combine | [A, B] |
| Combine | Or | [B…, A] |
| Or | anything | [A…, B…] |

This order feeds the decision-tree list order.

#### b.6 `commonSubPattern(b,sa)`, `simplifyClone`, miscellany

**commonSubPattern**
- Instruction (558-589):
  1. b Or or Combine → `b->commonSubPattern(this,-sa)`.
  2. b Context → `InstructionPattern(true)`.
  3. b Instruction → shift as in `doAnd`, then block `commonSubPattern`.
- Context (649-658): b not Context → delegate with `-sa`; else Context of the block common.
- Combine (737-759):
  1. b Or → delegate.
  2. b Combine → `Combine(context common, instr common with sa)`.
  3. b Instruction → `instr->commonSubPattern(b,sa)` (an InstructionPattern).
  4. b Context → `context->commonSubPattern(b,0)` (a ContextPattern).
- Or (910-929):
  1. `res = orlist[0]->commonSubPattern(b,sa)`.
  2. If `sa>0` then `sa=0`.
  3. For each later element `e`: `res = e->commonSubPattern(res,sa)`.

**simplifyClone**
- Instruction and Context: clone (PT.hh:94,115).
- Combine (PT.cc:777-788), in this order:
  1. If context alwaysTrue → `instr->simplifyClone()`.
  2. If instr alwaysTrue → `context->simplifyClone()`.
  3. If either alwaysFalse → `InstructionPattern(false)`.
  4. Else a Combine of clones.
- Or (958-977):
  1. If any element alwaysTrue → `InstructionPattern(true)`.
  2. Keep the simplifyClones of non-alwaysFalse elements, in order.
  3. Empty → `InstructionPattern(false)`; one left → that element; else `OrPattern`.

**shiftInstruction**: Instruction shifts its block (PT.hh:95); Context is a no-op (116); Combine shifts `instr` (139); Or shifts all elements (PT.cc:835-842).

**alwaysTrue / alwaysFalse / alwaysInstructionTrue**
- Instruction: block true / block false / block true (PT.hh:100-102).
- Context: block true / block false / always `true` (121-123).
- Combine: both true / either false / instr's (PT.cc:694-704, PT.hh:143).
- Or: any true / all false / all instruction-true (PT.cc:853-882).

---

### 10 (c) buildPatterns, operand offsets, decision trees

#### c.1 `SleighCompile::buildPatterns` (SC.cc:2122-2144)

1. If `root==0`: `reportError(null,"No patterns to match.")`; return.
2. `ostringstream msg; root->buildPattern(msg)`. This recursion reaches every table reachable from root.
3. If `root->isError()`: `reportError(getLocation(root), msg.str()); errors += 1`.
   - Root is added with `symtab.addSymbol`, not `SleighCompile::addSymbol` (SC.cc:1988-1989), so it has no location and the message has no `file:line:` prefix.
4. For each `tables[i]` in definition order (`newTable` pushes, SC.cc:2968-2976):
   - If `isError()`: `reportError(loc(table), "Problem in table '"+name+"':"+msg.str()); errors += 1`. `msg` is the whole accumulated stream for all tables.
   - If `getPattern()==null`: `reportWarning(loc, "Unreferenced table '"+name+"'")`. Such tables get no decision tree (SY.cc:1977) and are not encoded (SY.cc:1932).

#### c.2 `SubtableSymbol::buildPattern(s)` (SY.cc:1991-2026)

1. If `pattern` is non-null, return it.
2. `errors=false; beingbuilt=true; pattern=new TokenPattern()` (TRUE).
3. If there are no constructors: write `"Error: There are no constructors in table: "+name` and a newline to `s`; `errors=true`; return. `beingbuilt` is left true.
4. Build `construct.front()` in a try block. On `SleighError`, write `"Error: " << explain << ": for "`, then `printInfo`, then a newline; `errors=true`.
   - `printInfo` text is `table "<name>" constructor starting at line <lineno>` (SY.cc:1893-1899).
5. `*pattern = *construct.front()->getPattern()`.
6. For `i=1..n-1`: build constructor `i` with the same catch; then `*pattern = construct[i]->getPattern()->commonSubPattern(*pattern)`. The receiver is constructor `i`; the argument is the accumulator.
7. `beingbuilt=false`; return.

Notes:
- A constructor that threw still has a non-null TRUE pattern, because it is allocated before anything can throw (SY.cc:1809).
- `commonSubPattern` at step 6 is outside the try. Its `"Right/left ellipsis in commonSubPattern"` exception propagates to the enclosing constructor's catch, or for root becomes an unrecoverable error.
- The table's common pattern is what a parent sees as the operand's pattern, and it is ANDed or concatenated into the parent's pattern via OperandEquation (PE.cc:1200).

#### c.3 `Constructor::buildPattern(s)` (SY.cc:1804-1891)

1. If `pattern` is non-null, return it. `pattern = new TokenPattern()`.
2. For each operand `i` in current (parse) order, with `triple=getDefiningSymbol()` and `defexp=getDefiningExpression()`:
   - Triple is a SubtableSymbol:
     - If `isBeingBuilt()` (recursion): if `recursion` is already true → throw `"Illegal recursion"`; else `recursion=true` and push a default TRUE TokenPattern with no tokens.
     - Else push a copy of `*subsym->buildPattern(s)` (recursive).
   - Triple is something else: push `triple->getPatternExpression()->genMinPattern(oppattern)`.
     - `getPatternExpression` is: ValueSymbol family → `patval` (SY.hh:209); PatternlessSymbol (varnode, epsilon) → `ConstantValue(0)` (SY.cc:425-437); Start/End/Next2 → their value objects (SY.cc:1137-1273); FlowDest/FlowRef throw `"Cannot use symbol in pattern"` (SY.hh:421,433).
   - Else if `defexp` is non-null: push `defexp->genMinPattern(oppattern)`.
   - Else throw `<opname>+": operand is undefined"`.
   - Then `sym->minimumlength = oppattern.back().getMinimumLength()`; if that pattern has either ellipsis, `sym->setVariableLength()` (1839-1842). The flag is never cleared.
3. If `pateq==null` → throw `"Missing equation"`.
4. `pateq->genPattern(oppattern); *pattern = pateq->getTokenPattern()`; if `alwaysFalse()` → throw `"Impossible pattern"`.
5. If `recursion`: `pattern->setRightEllipsis(true)`.
6. `minimumlength = pattern->getMinimumLength()` (1855). This is encoded as the constructor's length (SY.cc:1629). `Constructor::setMinimumLength` exists (SY.hh:504) but is never called (grep). There is no `Constructor::buildOperands`.
7. `OperandResolve resolve(operands)`; if `!pateq->resolveOperandLeft(resolve)` → throw `"Unable to resolve operand offsets"`.
8. Unravel relative offsets (1862-1883). For each operand `i` in index order:
   - If offset-irrelevant: `offsetbase=-1; reloffset=0`; continue.
   - `base=offsetbase; offset=reloffset`.
   - While `base>=0`:
     - `sym=operands[base]`; if `sym->isVariableLength()` break.
     - `base=sym->offsetbase; offset += sym->minimumlength; offset += sym->reloffset`.
     - If `base<0`: `operands[i]->offsetbase=base; operands[i]->reloffset=offset`.
   - An operand's fields are only rewritten when the chain reaches −1 without crossing a variable-length operand.
9. `context[i]->validate()` for each context change (1886-1887). `ContextOp::validate` throws `<opname>+": cannot be used in context expression"` for any OperandValue in the expression whose operand has `offsetbase != -1` (SY.cc:2447-2463, PE.cc:800-805).
10. `orderOperands()`; return `pattern`.

How operand flags are set:
- Offset-irrelevant: set by `SleighCompile::defineOperand(sym,patexp)` (the `name = expr` form), SC.cc:3022-3030.
- `selfDefine` and `defineInvisibleOperand`: if the global is a `value_symbol` or `context_symbol`, the operand gets `defexp = glob->getPatternExpression()`; otherwise `triple = glob` (SC.cc:3044-3091).
- `OperandSymbol`'s constructor leaves `reloffset`, `offsetbase` and `minimumlength` uninitialised (SY.cc:974-983).

#### c.4 `Constructor::orderOperands` (SY.cc:1730-1802)

1. `pateq->operandOrder(this,patternorder)` — left-to-right equation order, marking each operand.
2. For `i` over `operands`: if not marked, append to `patternorder` and mark.
3. Repeat until a pass adds nothing. For each `sym` in `patternorder` order:
   - Skip if unmarked (already placed) or offset-irrelevant.
   - If `sym->offsetbase==-1 || !operands[sym->offsetbase]->isMarked()`: append to `newops` and clear its mark.
   - A base placed earlier in the same pass counts immediately.
4. For each `sym` in `patternorder`: if offset-irrelevant, append and clear its mark.
5. If `newops.size() != operands.size()` → throw `"Circular offset dependency between operands"`.
6. For each `i`: `newops[i]->hand=i; newops[i]->localexp->changeIndex(i)`.
7. `handmap[old] = operands[old]->hand`.
8. For each new operand with `offsetbase != -1`: `offsetbase = handmap[offsetbase]`.
9. Apply `changeHandleIndex(handmap)` to `templ` and each non-null named section; remap operand references in `printpiece`; `operands=newops`.

#### c.5 Other operand helpers

- `markSubtableOperands(check)` (SY.cc:1577-1588): `check[i]=0` if operand `i`'s defining symbol is a subtable, else 2. It is used at parse time by `finalizeSections` with `fillinBuild` (SC.cc:3455-3461, SEM.cc:864-891). Errors: `"Duplicate BUILD statements"` for result 1, `"Unnecessary BUILD statements"` for result 2. Missing BUILDs are inserted at the front of the op vector, one per unchecked operand in ascending index order, each inserted at `vec.begin()` (so the final order is descending index).
- `collectLocalExports(results)` (SY.cc:1590-1611):
  1. Return if `templ` is null or has no result handle.
  2. Return if the handle's space is the const space.
  3. If `ptrspace` type is not `real`: if `temp_space` is unique, push `temp_offset.getReal()`; return.
  4. If the space is unique: push `ptroffset.getReal()`; return.
  5. If the space type is `handle`: call `getOperand(handleIndex)->collectLocalValues(results)`.
- `collectLocalValues`: Operand → its triple's (SY.cc:1065-1070); Subtable → every constructor's `collectLocalExports` in order (1922-1927); VarnodeSymbol → push `fix.offset` if the space type is `IPTR_INTERNAL` (751-756); others no-op (SY.hh:161). I did not check whether recursive tables can loop here.
- `checkLocalCollisions` / `checkLocalExports` (SC.cc:2217-2273), root then tables in order:
  - Skip a constructor with no template, a build-only template, or fewer than 2 operands.
  - For operands in order, collect values and insert into a `map<uintb,int4>` (offset → operand index). The first offset already owned by a different operand is a collision; stop at the first one.
  - With `-c`: warn `"Possible operand collision between symbols 'A' and 'B'"` (A is the earlier operand).
  - Summary warning `"<N> constructors with local collisions between operands"`, plus `"Use -c switch to list each individually"` if not `-c`.

#### c.6 `buildDecisionTrees` and `SubtableSymbol::buildDecisionTree`

`SleighCompile::buildDecisionTrees` (SC.cc:2086-2118):
1. One `DecisionProperties props` is shared across all tables.
2. `root->buildDecisionTree(props)`, then `tables[i]` in order.
3. For each identical pair `(A,B)` in recorded order:
   - `errors += 1`.
   - `reportError(locA, "Constructor has identical pattern to constructor at " + locB->format())`.
   - `reportError(locB, "Constructor has identical pattern to constructor at " + locA->format())`.
4. Only when `!lenientconflicterrors` (i.e. `-l`): the same structure with `"Constructor pattern cannot be distinguished from constructor at "`.
5. Without `-l`, conflicts are silently ignored; the leaf order is still whatever `orderPatterns` produced.

`SubtableSymbol::buildDecisionTree` (SY.cc:1974-1989):
1. Return if `pattern==null`.
2. `decisiontree = new DecisionNode(null)`.
3. For constructors in id order: `pat = construct[i]->getPattern()->getPattern()`.
   - If `numDisjoint()==0`: `addConstructorPair(pat, ct)`.
   - Else for `j` ascending: `addConstructorPair(pat->getDisjoint(j), ct)`.
4. `decisiontree->split(props)`.

`addConstructorPair` stores `pat->simplifyClone()` and does `num += 1` (2071-2077). `num` is encoded (2370).

A new node starts with `num=0, startbit=0, bitsize=0, contextdecision=false` (2050-2058).

#### c.7 `DecisionNode::split` (SY.cc:2221-2257)

1. If `list.size() <= 1`: `bitsize=0`; return. This is a leaf, and `orderPatterns` is not called.
2. `chooseOptimalField()`.
3. If `bitsize==0`: `orderPatterns(props)`; return (leaf).
4. If `parent != null && list.size() >= parent->num` → throw `LowlevelError("Child has as many Patterns as parent")`. This surfaces as an unrecoverable error. By my analysis of `getScore` it should be unreachable, since a positive score needs at least two distinct fully specified values.
5. Create `1<<bitsize` children in index order.
6. For each list entry `i` in order: `consistentValues(vals, pat)`; for each `v` in `vals` order: `children[v]->addConstructorPair(pat, ct)`; delete the original.
   - Children receive unmodified clones (not narrowed), in parent list order.
7. `list.clear()`; `children[i]->split(props)` for `i` ascending.

`consistentValues` (2203-2219):
- `m=(1<<bitsize)-1`.
- `commonMask = m & pat->getMask(startbit,bitsize,contextdecision)`.
- `commonValue = commonMask & pat->getValue(...)`.
- `dontCare = m ^ commonMask`.
- For `i=0..=dontCare` ascending: if `(i&dontCare)==i`, push `commonValue|i`.

#### c.8 `chooseOptimalField` and scoring (SY.cc:2079-2201)

- `getMaximumLength(context)`: max over the list of `pat->getLength(context)`, starting from 0 (2079-2091).
- `getNumFixed(low,size,context)`: count of patterns with `(getMask(low,size,context) & m)==m`, where `m=(1<<size)-1` (2093-2108).
- `getScore(low,size,context)` (2110-2138):
  1. `numBins=1<<size`; `count[]` zeroed; `total=0`.
  2. For each pattern in list order: skip unless fully specified; `val=getValue(...)`; `total++; count[val]++`.
  3. If `total<=0` return −1.0.
  4. `sc=0.0`; for `i=0..numBins-1` ascending: skip if `count[i]<=0`; if `count[i] >= list.size()` return −1.0; `p=(double)count[i]/total; sc -= p*log(p)`.
  5. Return `sc/log(2.0)`.

Algorithm:
1. `score=0.0; maxfixed=1`.
2. **Single-bit pass**, for `context=true` first, then `context=false` (the `do…while(!context)` loop at 2152-2180):
   - `maxlength = 8*getMaximumLength(context)`.
   - For `sbit=0..maxlength-1`:
     - `numfixed=getNumFixed(sbit,1,context)`; if `numfixed < maxfixed` continue.
     - `sc=getScore(sbit,1,context)`.
     - If `numfixed > maxfixed && sc > 0.0`: set `score=sc; maxfixed=numfixed; startbit=sbit; bitsize=1; contextdecision=context`; continue. This resets `score` even if `sc` is lower than the old score.
     - If `sc > score`: set `score=sc; startbit=sbit; bitsize=1; contextdecision=context`.
3. **Multi-bit pass**, again context first then instruction (2182-2198):
   - For `size=2..8`; for `sbit=0; sbit < maxlength-size+1; ++sbit`:
     - If `getNumFixed(sbit,size,context) < maxfixed` continue.
     - `sc=getScore(...)`; if `sc > score`: set `score, startbit=sbit, bitsize=size, contextdecision=context`.
   - `maxfixed` carries over from pass 2 unchanged.
4. If `score <= 0.0`: `bitsize=0` (leaf).

Constants and tie-breaks:
- Field width is 1..8 bits, so at most 256 children.
- All comparisons are strict `>`. On equal score the earliest candidate wins: 1-bit before wider; context before instruction; in the multi-bit pass, context(all sizes, all sbits) before instruction; within one stream, smaller size then lower `sbit`.
- Preference for bits fixed by more patterns comes only from `maxfixed`, which is raised only in the single-bit pass.
- Leaf nodes keep `startbit=0, contextdecision=false`, since those are only assigned together with a positive score.

**Floating-point hazard.** Scores are doubles built from libm `log`, summed in ascending bin order. Two fields with mathematically equal entropy can differ in the last ulp (different summation order or a different libm), which flips a strict `>` tie. The implementer must reproduce the exact arithmetic order (`p = count/total` as double; `sc -= p*ln(p)`; a final division by `ln(2.0)`). Exact agreement with the platform `log` that Ghidra's build used is a host dependency I cannot eliminate.

#### c.9 `orderPatterns` — leaf ordering (SY.cc:2259-2342)

1. Identical check, on the original order. For `i=0..n-1`, for `j=0..i-1`: if `list[i].pat->identical(list[j].pat)` → `props.identicalPattern(list[i].ct, list[j].ct)` (later entry first).
2. `newlist = list` (copy). Insertion pass, for `i=0..n-1`:
   - For `j=0..i-1`, comparing `ipat=newlist[i].pat` with `jpat=list[j].pat` (`list[0..i)` is the sorted prefix):
     - If `ipat->specializes(jpat)`: break.
     - Else if `!jpat->specializes(ipat)` and the two constructors differ: push `(ipat,iconst)` then `(jpat,jconst)` onto `conflictlist`. The same constructor means an OR within one constructor, which is not a conflict.
   - Shift `list[j..i-1]` up by one and set `list[j]=newlist[i]`.
   - Net effect: each pattern is inserted before the first already-placed pattern it specializes; otherwise it stays at the end. Because `specializes` is true for equal patterns, a later identical pattern is placed before the earlier one.
3. Conflict resolution. For each recorded pair `(pat1,const1),(pat2,const2)`:
   - Scan the final `list` from the front.
   - Stop when the entry is `(pat1,const1)` or `(pat2,const2)`, compared by object identity.
   - If an earlier entry has `tpat->resolvesIntersect(pat1,pat2)`, the pair is resolved.
   - If unresolved: `props.conflictingPattern(const1,const2)`.

`DecisionProperties` (SY.cc:2028-2048):
- Both `identicalPattern(a,b)` and `conflictingPattern(a,b)` record the pair only if neither `a->isError()` nor `b->isError()`, and then set `inerror` on both.
- The flag is shared between the two kinds and across all tables, so each constructor is reported at most once in total.
- `a==b` (the same constructor with two identical disjuncts) is recorded and reported against itself.

Encoding (SY.cc:2366-2383): `number=num`, `context`, `startbit`, `size`; then pairs in final list order (constructor id + pattern); then children in index order.

---

### 10 (d) ConsistencyChecker and `checkConsistency`

#### d.1 Driver order (SC.cc:2148-2181)

1. Construct `checker(this, root, warnunnecessarypcode, warndeadtemps)`.
2. `testSizeRestrictions()`; if false: `errors += 1; return`.
3. `testTruncations()`; if false: `errors += 1; return`.
4. If not `-u` and `getNumUnnecessaryPcode() > 0`: two warnings, `"<N> unnecessary extensions/truncations were converted to copies"` and `"Use -u switch to list each individually"`.
5. `optimizeAll()`.
6. If `getNumReadNoWrite() > 0`: `errors += 1; return`.
7. If not `-t` and `getNumWriteNoRead() > 0`: two warnings, `"<N> operations wrote to temporaries that were not read"` and `"Use -t switch to list each individually"`.
8. `testLargeTemporary()`.

All four passes iterate `postorder`, which contains only tables reachable from root. Unreferenced tables are never checked or optimised.

#### d.2 Post-order (SC.cc:1187-1235)

`setPostOrder(root)` is an iterative depth-first search:
1. Clear `postorder` and `sizemap`; `sizemap[root]=-1`.
2. Push `(root, ctor index 0, operand index 0)`.
3. Loop on the top of the stack:
   - If the constructor index is past the end: pop and append the table to `postorder`.
   - Else if the operand index is past the end of that constructor: advance to the next constructor and reset the operand index.
   - Else advance the operand index. If the operand's defining symbol is a SubtableSymbol not yet in `sizemap`: set `sizemap[sub]=-1` and push it.
4. Constructors are visited in id order and operands in current (parse) order; dependencies come first.

`sizemap` is a `map<SubtableSymbol*,int4>` (SC.hh:198). It is used only via `find` and `operator[]`, never iterated, so there is no pointer-order dependence. The same holds for `ctorLocationMap` and `symbolLocationMap` (SC.hh:322-323).

#### d.3 `recoverSize(sizeconst,ct)` (SC.cc:320-350)

- `real` → `(int4)getReal()`.
- `handle` → `size = ct->getOperand(handleIndex)->getSize()`.
  - If that is −1: the defining symbol must be a SubtableSymbol, else throw `"Could not recover varnode template size"`; look it up in `sizemap`, throwing `"Subtable out of order"` if absent; use the stored value.
- Any other type → throw `"Bad constant type as varnode template size"`.
- These throws are not caught and become unrecoverable errors.

`OperandSymbol::getSize` = `triple->getSize()`, or 0 if there is no triple (SY.cc:1037-1043). Per symbol: Subtable −1 (SY.hh:600); Varnode `fix.size` (259); VarnodeList = the first non-null entry's size, else throw `"No register attached to: "+name` (SY.cc:904-913); default 0 (SY.hh:159).

Size 0 means unknown/wildcard. Size −1 means a subtable with no export, or a recursive reference not yet computed.

#### d.4 `checkSubtable(sym)` (SC.cc:1115-1178)

State: `tablesize=-1`, `seenemptyexport=false`, `seennonemptyexport=false`.

For each constructor in id order:
1. `checkConstructorSection(ct, main)`, then each named section `j=0..getNumSections()-1`. A null section passes.
   - Within a section, for each op in order, call `sizeRestriction` and then `checkOpMisuse`; both always run (987-1003).
2. If the main template is null (unimplemented): continue.
3. If the constructor has an export handle:
   - If `seenemptyexport && !seennonemptyexport`: error `"Table '<name>' exports inconsistently; Constructor starting at line <N> is first inconsistency"`.
   - `seennonemptyexport=true`.
   - `exsize=recoverSize(export size, ct)`; if `tablesize==-1` then `tablesize=exsize`.
   - If `exsize != tablesize`: error `"Table '<name>' has inconsistent export size; Constructor starting at line <N> is first conflict"`.
4. Else (no export):
   - If `seennonemptyexport && !seenemptyexport`: the same "exports inconsistently" error.
   - `seenemptyexport=true`.

After the loop:
- If `seennonemptyexport`: when `tablesize==0`, warn `"Table '<name>' exports size 0"`; then `sizemap[sym]=tablesize`.
- Else `sizemap[sym]=-1`.

#### d.5 `sizeRestriction(op,ct)` (SC.cc:427-690) — all violations are errors

Throughout, `vnout`/`vn0`/`vn1` are `recoverSize` of the output, input 0 and input 1. Any that equals −1 gives `printOpError(op,ct,slot,slot,"Using subtable with exports in expression")` and returns false, with slot −1 for the output, 0 or 1 for inputs. Checks happen in the order listed.

| Opcodes | Rule (in order) | Error slots and message |
|---|---|---|
| COPY, INT_2COMP, INT_NEGATE, FLOAT_NEG, FLOAT_ABS, FLOAT_SQRT, FLOAT_CEIL, FLOAT_FLOOR, FLOAT_ROUND (435-457) | out, in0; OK if equal or either is 0 | (−1,0) `"Input and output sizes must match"` |
| INT_ADD, SUB, XOR, AND, OR, MULT, DIV, SDIV, REM, SREM, FLOAT_ADD, DIV, MULT, SUB (458-499) | out, in0, in1; pairwise equal ignoring zeros, tested out/in0, out/in1, in0/in1 | (−1,0), (−1,1), (0,1) `"The output and all input sizes must match"` |
| FLOAT_NAN (500-510) | out must be 1 | (−1,−1) `"Output must be a boolean (size 1)"` |
| INT_EQUAL, NOTEQUAL, SLESS, SLESSEQUAL, LESS, LESSEQUAL, CARRY, SCARRY, SBORROW, FLOAT_EQUAL, NOTEQUAL, LESS, LESSEQUAL (511-548) | out must be 1; then in0, in1; OK if either is 0; else must be equal | (−1,−1) `"Output must be a boolean (size 1)"`; (0,1) `"Inputs must be the same size"` |
| BOOL_XOR, AND, OR (549-570) | out must be 1; in0 must be 1; in1 is not checked | (−1,−1) `"Output must be a boolean (size 1)"`; (0,0) `"Input must be a boolean (size 1)"` |
| BOOL_NEGATE (571-590) | out must be 1; in0 must be 1 | same two messages |
| INT_LEFT, RIGHT, SRIGHT (593-611) | out, in0; OK if either is 0; else must be equal | (−1,0) `"Output and first input must be the same size"` |
| INT_ZEXT, SEXT (612-633) | out, in0; OK if either is 0; if equal → `dealWithUnnecessaryExt`, return true; if out < in0 → error | (−1,0) `"Output size must be strictly bigger than input size"` |
| CBRANCH (634-644) | in1 must be 1 | (1,1) `"Input must be a boolean (size 1)"` |
| LOAD, STORE (645-659) | if in0's offset is not a `spaceid`, return true; else in1 must be 0 or equal the space's address size | (1,1) `"Pointer size must match size of space"` |
| SUBPIECE (660-685) | out, in0; `vn1 = in1 offset real`; OK if out or in0 is 0; if `out==in0 && vn1==0` → `dealWithUnnecessaryTrunc`, return true; else if `out>=in0` → error; if `out > in0-vn1` → error | (−1,0) `"Output must be strictly smaller than input"`; (−1,0) `"Too much truncation"` |
| everything else | no check | — |

- `dealWithUnnecessaryExt` (359-370): with `-u`, warn `"Unnecessary " + opname`; change the opcode to COPY; `unnecessarypcode++`.
- `dealWithUnnecessaryTrunc` (379-391): the same, and additionally `removeInput(1)`.
- `checkOpMisuse` (401-417): for INT_LESS whose input 1 is in the const space with a literal-zero offset, warn `"Unsigned comparison with zero is always false"`. It always returns true (warning only).

`printOpError` (949-977) builds this error text:

```
Size restriction error in table '<table>'\n
  Problem with operands '<a>' and '<b>'      (both slots map to operands)
  Problem with operand 1 '<a>'               (only the first)
  Problem with operand 2 '<b>'               (only the second)
  Problem                                    (neither)
 in <opname> operator\n  <msg>
```

- The lead-in line is one of the four alternatives, followed directly by `" in "`, the op name, `" operator"`, a newline, two spaces and the message.
- A slot maps to an operand only if that varnode's size ConstTpl is of `handle` type (914-936).
- When `err1==err2`, the second operand is forced to null.
- Op names come from the switch at SC.cc:697-902, e.g. `"Copy(=)"`, `"Zero extension(zext)"`, `"Signed extension(sext)"`, `"Truncation(:)"`, `"Addition(+)"`, `"Less than(<)"`. Copy that table verbatim, including `"Float subtractions(f-)"`. Opcodes not in the switch print nothing.

#### d.6 Truncations (SC.cc:1053-1106, 1704-1731)

`testTruncations` iterates postorder tables, constructors in id order, and sections `k=-1..numSections-1` (skipping null). Endianness comes from the global `slgh->isBigEndian()` (1708).

`checkSectionTruncations`: for each op, the output (if any, slot −1) and then each input are passed to `checkVarnodeTruncation`:
1. If the offset is not of `handle` type, or its select is not `v_offset_plus`: OK.
2. If the size type is neither `real` nor `handle`: error (slot,slot) `"Bad truncation expression"`.
3. `sz = recoverSize(offset ConstTpl, ct)` (the operand's size); if `sz<=0`: error `"Could not recover size"`.
4. `vn->adjustTruncation(sz,isbigendian)`; if false: error `"Truncation operator out of bounds"`.

`adjustTruncation` (SEM.cc:555-577):
1. If the size is not `real`, return false.
2. `numbytes=size; byteoffset=(int4)offset.getReal()`; if `numbytes+byteoffset > sz` return false.
3. `val = byteoffset<<16`; OR in `sz-(numbytes+byteoffset)` if big-endian, else `byteoffset`.
4. `offset = ConstTpl(handle, sameIndex, v_offset_plus, val)`.

#### d.7 Optimisation (`optimizeAll` → `optimize(ct)`)

`optimizeAll` iterates postorder tables and constructors in id order (1760-1772).

`optimize(ct)` (1666-1683):
1. Clear the state.
2. For `i=-1..numSections-1`: `optimizeGather1(ct,state,i)`, then `optimizeGather2(ct,state,i)`.
3. `rec = findValidRule(ct,state)`.
4. If found: `applyOptimization(ct,*rec)` and go back to step 1.
5. Otherwise: `checkUnusedTemps(ct,state)` using the final state.

**OptimizeRecord** (SC.hh:149-175, SC.cc:215-289):
- Fields and initial values: `offset`, `size`, `writeop=-1`, `readop=-1`, `inslot=-1`, `writecount=0`, `readcount=0`, `writesection=-2`, `readsection=-2`, `opttype=-1`.
- `updateRead(i,inslot,sec)`: set `readop`, `inslot`, `readsection`; `readcount++`.
- `updateWrite(i,sec)`: set `writeop`, `writesection`; `writecount++`.
- `updateExport()`: `writeop=0; readop=0; writecount=2; readcount=2; readsection=-2; writesection=-2`.
- Merging constructor: `offset` = minimum offset; `size` = (maximum end) − minimum; then for each source record in vector order call `updateCombine`. That takes `writeop`/`writesection` from any source with `writecount != 0` (the last one wins), likewise `readop`/`inslot`/`readsection`, and sums both counts.

**UniqueState** — `map<uintb,OptimizeRecord> recs`, kept disjoint (SC.hh:178-188).

`getDefinitions(result,offset,size)` (SC.cc:1269-1301):
1. If `size==0` then `size=1`.
2. `iter` = last record with key < `offset` (`lesserIter`, 1239-1251); `cursor=offset`.
3. If such a record exists and its end > `offset`: push it; `cursor = its end`.
4. `end=offset+size`; iterate from `lower_bound(offset)` while key < `end`:
   - If key > `cursor`: insert a fresh gap record `(cursor, key-cursor)` and push it.
   - Push the record; `cursor = its end`.
5. If `end > cursor`: insert and push a fresh record `(cursor, end-cursor)`.

Inserted keys go through `pair<uint4,OptimizeRecord>`, so they are truncated to 32 bits (lines 1263, 1288, 1298).

`set(rec)` (1255-1264):
1. `records = getDefinitions(rec.offset, rec.size)`; push `&rec` last.
2. `coalesced = OptimizeRecord(records)`.
3. Erase `[lower_bound(coalesced.offset), lower_bound(coalesced.offset+coalesced.size))`.
4. Insert `coalesced`.

**`examineVn(state,vn,i,inslot,secnum)`** (1401-1422):
- Ignore null varnodes, non-unique space, or an offset that is not `real`.
- `offset = offset.getReal(); size = (int4)size.getReal()`.
- Read (`inslot>=0`): `updateRead(i,inslot,secnum)` on every record from `getDefinitions`.
- Write: build a fresh record, `updateWrite(i,secnum)`, then `state.set(rec)`.

**`optimizeGather1`** (1431-1451): section −1 is the main template, otherwise the named section; skip if null. For each op index `i` in order: all inputs `j` ascending first, then the output with slot −1.

**`optimizeGather2`** (1461-1500): let `hand` be the section's result; return if null.
- If `hand.ptrspace` is the unique space and `ptroffset` is `real`: `updateExport()` on `getDefinitions(ptroffset, ptrsize.getReal())`.
- If `hand.space` is the unique space and both `ptrspace` and `ptroffset` are of `real` type: `updateExport()` on `getDefinitions(ptroffset, hand.size.getReal())`.

**`findValidRule`** (1513-1575): iterate records in ascending key order. For a record with `writecount==1 && readcount==1 && readsection==writesection`:
1. Get the section's ops (main if `readsection<0`).
2. If `writeop >= readop` → throw `SleighError("Read of temporary before write")` (uncaught, so unrecoverable).
3. `writevn = ops[writeop]->getOut(); readvn = ops[readop]->getIn(inslot)`. If `*writevn != *readvn`, continue.
   - VarnodeTpl equality compares space, offset and size ConstTpls (SEM.cc:603-607, 91-108).
4. If the read op is COPY: `opttype=0`; `vn` = the read op's output. If no op strictly between `writeop` and `readop` has `readWriteInterference(vn, op, true)`, return this record.
5. If the write op is COPY: `opttype=1`; `vn` = the write op's input 0. Same loop with `checkread=false`; return on success.
6. If nothing matches, return null.

**`readWriteInterference(vn,op,checkread)`** (1352-1389):
- Always true for BUILD, CROSSBUILD, DELAY_SLOT, MACROBUILD, LOAD, STORE, BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, CALLOTHER, RETURN, LABELBUILD. The directive opcodes are aliases defined at SEM.hh:30-42.
- Otherwise: if `checkread`, true when any input has `possibleIntersection(vn,in)`.
- Always: true when the output is non-null and `possibleIntersection(vn,out)`.

**`possibleIntersection(vn1,vn2)`** (1310-1340), in order:
1. Either in the const space → false.
2. `isUniqueSpace` differs between them → false.
3. Either space ConstTpl is not of `spaceid` type → true.
4. Different `AddrSpace` → false.
5. vn2's offset or size not `real` → true; vn1's offset or size not `real` → true.
6. Unsigned range test: `off2+size2-1 < off1` → false; `off2 > off1+size1-1` → false; else true.

`isUniqueSpace`/`isConstSpace` are false for non-`spaceid` ConstTpls (SEM.cc:72-86). So a handle-space varnode against a unique varnode gives "no intersection" at step 2.

**`applyOptimization`** (1587-1612), on the section given by `rec.readsection`:
- `opttype==0`: copy the COPY's output varnode; `setOutput(copy, rec.writeop)`; delete the op at `readop`.
- `opttype==1`: copy the COPY's input 0; `setInput(copy, rec.readop, rec.inslot)`; delete the op at `writeop`.
- `deleteOps` compacts the vector while preserving order (SEM.cc:957-974).

**`checkUnusedTemps`** (1620-1638), over records in ascending key order:
- `readcount==0`: with `-t`, warn `"Temporary is written but not read"`; `writenoread++`.
- else `writecount==0`: error `"Temporary is read but not written"`; `readnowrite++`.

**Large temporaries** (1011-1037, 1647-1659, 1735-1758):
- Iterate postorder tables, constructors, and sections −1 upward.
- For each section, the first op with an output or input in the unique space whose `size.getReal() > 256` produces `reportError(loc(ct), "Constructor uses temporary varnode larger than 256 bytes.")`, then moves to the next section.
- `MAX_UNIQUE_SIZE` is 256 (sleighbase.cc:20).
- This is an error (it uses `reportError`), despite the doc comment calling it a warning.

#### d.8 Other post-parse checks

- `checkNops` (SC.cc:2277-2291): if `noplist` is non-empty:
  - With `-n`, each stored message is emitted as a warning. They were formatted at parse time as `"<file>:<line>: NOP detected"` (3758-3764); the trigger is an empty op vector and no export (slghparse.y:355).
  - Always: `"<N> NOP constructors found"`.
  - Without `-n`: `"Use -n switch to list each individually"`.
- `checkCaseSensitivity` (2297-2327): active unless `-s`. For varnode symbols in `IPTR_PROCESSOR` spaces, an uppercase-name collision is an error: `"Name collision: <sym> --- Duplicate symbol <old>"`, plus `" defined at <loc>"` when the old symbol has a location.

#### d.9 Command-line flags (SC.cc:3926-4009)

Only `argv[i][1]` is examined; parsing stops at the first argument not starting with `-`.

| Flag | Effect | Default |
|---|---|---|
| `-a` | compile all `.slaspec` files under a directory | off |
| `-DNAME=VALUE` | preprocessor define; a missing `=` prints `"Bad sleigh option: <arg>"` and exits 1 | — |
| `-u` | `warnunnecessarypcode=true` (individual "Unnecessary …" warnings) | false |
| `-l` | `lenientconflicterrors=false` (pattern conflicts become errors) | true (lenient) |
| `-c` | `warnalllocalcollisions=true` | false |
| `-n` | `warnallnops=true` | false |
| `-t` | `warndeadtemps=true` | false |
| `-e` | enforce the `local` keyword; error `"Must use 'local' keyword to define symbol '<name>'"` (pcodecompile.cc:384-385) | false |
| `-s` | `failinsensitivedups=false` (case-sensitive register names) | true (duplicates fail) |
| `-y` | write the XML debug format instead of binary `.sla` | false |
| `-x` | parser debug; only compiled under `YYDEBUG` | — |

- Anything else prints `"Unknown option: <arg>"` and exits 1.
- **There are no `-o`, `-f` or `-i` options in this C++ `main`.**
- Defaults are at SC.cc:1960-1977 and 3958-3965; the mapping is `setAllOptions` (3901-3918).

---

### 10 (e) Hazards and unverified items

1. **Float tie-breaks** in `chooseOptimalField` (c.8). This is the only place I found where a host library (`log`) can change the output. A second host dependence, measured later: the compiler's floating-point contraction of `sc -= p * log(p)` in `getScore` (fused on AArch64, unfused on x86-64) decides 25 ties and changes 14 of the 150 `.sla` (ADR-032, `docs/research/sla-host-dependence.md`).
2. **Undefined-behaviour-dependent arithmetic** in constraint expressions (`<<`, `>>`, `/` on `intb`, a.5).
3. **Pointer-dependent text only**: the token-mismatch exception prints `Token*` values (PE.cc:120-125, 139-144). Pointer-keyed maps are lookup-only. There is no `std::sort` in the back half; the only sort in these files is `stable_sort` on the context table (SC.cc:2523), outside my scope.
4. **`doOr` operand reversal and the Or-shift quirks** (b.5) affect disjunct order, and therefore the decision-tree list order.
5. **Uninitialised fields**: `OperandSymbol`'s `reloffset`/`offsetbase`/`minimumlength` (SY.cc:974-983), and `Constructor::flowthruindex` in the parsing constructor (SY.cc:1408-1417; only the decode constructor sets it). I did not check whether the encoder reads `flowthruindex`.
6. **`errors` is over-counted**: several sites do `errors += 1` in addition to `reportError`'s own increment. This is harmless, since only `errors > 0` matters.
7. **Not verified**:
   - the value of `lineno.back()` at EOF (affects the error-line prefix);
   - parser-side normalisation of negative constants;
   - whether named sections can carry a result handle;
   - whether `collectLocalValues` can recurse infinitely on recursive tables;
   - the behaviour of `PcodeCompile::propagateSize` and `forceExportSize`;
   - idempotence of `simplifyClone` (reasoned, not tested);
   - unreachability of the `"Child has as many Patterns as parent"` guard (reasoned, not tested).

## 11. Java and C++: where they differ, and which to follow

Verified by reading the Java lines cited (2026-11-12/13). The Java
runtime was not run. Items marked [unverified] were not read.

**Format and loading.** Both require version 4, in the header byte and in
the `version` attribute (`SM/pcode/utils/SlaFormat.java:39,202-203`,
`SL/SleighLanguage.java:876-878`; `SL` =
`SM/app/plugin/processors/sleigh/`). Java caps the inflated size at 2 GiB
(`SlaFormat.java:44`). Java's expression decoder handles `next2_exp`
(`SL/expression/PatternExpression.java:60`); the C++ one does not
(section 1.3). Java distinguishes RAM-type and register-type spaces by
`delay`, applies `<truncate_space>` only to RAM-type spaces, requires the
`.slaspec` to exist, and checks the `.sla`'s endianness against the
`.ldefs` (`SleighLanguage.java:146-148, 879-885, 896-1001`). Only Java
recompiles a missing or stale `.sla` (`SL/SleighLanguageFile.java:315-429`).

**Expressions.** Same operators on `long`: `<<` and `>>` use the count
modulo 64 by the language definition, `>>` is arithmetic, `/` by zero
throws (`SL/expression/LeftShiftExpression.java:40`,
`RightShiftExpression.java:40`, `DivExpression.java:39`). C++ is
undefined in exactly these cases (section 8), so the port follows Java
there.

**P-code generation.** Java's `PcodeEmit` is the same algorithm as
`SleighBuilder` (same `generateLocation`: constants masked for sizes up
to 8, unique offsets ORed with `(address & uniqmask) << 8`;
`SL/PcodeEmit.java:436-449`) plus what C++ lacks: flow overrides,
fall-through overrides, overriding references, and a final `BRANCH` for
a fall-through override (`PcodeEmit.java:183-260, 770-894`). A failed
emission yields one `UNIMPLEMENTED` op. See `features/sleigh-language.md`.

**Instruction information.** Flow type, fall-through, operand types and
objects, the `_` mnemonic prefix in delay slots, prototype sharing by
hash: Java only (`SL/SleighInstructionPrototype.java`).

**Context.** C++: section 4. Java keeps context as values of the context
register in the program (`ProgramContext`), and the disassembler decides
how a committed value flows along the instructions it follows; `noflow`
fields are register bits flagged `TYPE_DOES_NOT_FOLLOW_FLOW`. That
machinery belongs to M5 and was not read [unverified].

**Compiler.** The Java compiler (`SM/pcodeCPort/**`, ANTLR front end) is
a port of the C++ one. Ghidra's `SleighCompileRegressionTest`
(`Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/pcodeCPort/
slgh_compile/regression/`) compiles every `.slaspec` with both, with
`-y`, and requires the two XML texts to be equal line by line, except
that lines consisting of `<print piece=" "/>` are skipped on either side
(the two differ in white-space print pieces at the end of a display
section). Front-end differences are recorded in
`features/sleigh-syntax.md` §8. Option differences: section 9.1. Whether
the Java back end differs from the C++ in anything else observable
(messages, order of diagnostics) was not read [unverified]; the port
follows the C++, which is the runnable oracle.

**P-code snippets.** C++ `PcodeSnippet` (`CPP/pcodeparse.y`) and Java
`PcodeParser` (`SM/program/model/lang/PcodeParser.java`) compile the
`<pcode>` bodies of `.cspec`/`.pspec` files against a loaded language.
C++: temporaries advance by 16 per allocation from a base
(`pcodeparse.cc:3133`), which the injection library starts at `uniqbase +
0x200` and carries from snippet to snippet, and sets to 0x2000 for
executable p-code (`CPP/inject_sleigh.cc:377, 422-465`). Java
(`PcodeParserTest`): temporaries at `uniqueBase + n·0x100`. The two
therefore number temporaries differently [the Java side is from the
test's expectations, not from reading `PcodeParser`].

## 12. Corpus facts (census of the 150 reference `.sla` files)

Method: `docs/agents/spec-sleigh.md`. Totals over all files.

| Elements | Count | | Elements | Count |
|---|---:|---|---|---:|
| `const_real` | 3,274,472 | | `constructor` | 131,955 |
| `varnode_tpl` | 1,962,013 | | `construct_tpl` | 129,783 |
| `const_spaceid` | 1,682,002 | | `scope` | 118,196 |
| `const_handle` | 1,083,260 | | `varnode_sym` | 84,032 |
| `op_tpl` | 816,132 | | `tokenfield` | 59,776 |
| `mask_word` | 518,292 | | `userop` | 24,845 |
| `pat_block` | 489,230 | | `handle_tpl` | 23,658 |
| `print` / `opprint` | 410,430 / 273,693 | | `value_sym` | 20,653 |
| `decision` | 361,879 | | `subtable_sym` | 15,323 |
| `operand_sym` | 338,715 | | `context_op` / `commit` | 13,636 / 1,323 |
| `pair` | 312,280 | | `varlist_sym` | 7,381 |
| `context_pat` / `instruct_pat` / `combine_pat` | 68,183 / 67,147 / 176,950 as pair patterns | | `context_sym` / `name_sym` / `valuemap_sym` | 1,089 / 323 / 17 |

Never present: `epsilon_sym`, `next2_exp`, `or_pat`, `const_flowref`,
`const_flowref_size`, `const_flowdest`, `const_flowdest_size`; attribute
`contain`. Present once per file: `start_sym`, `end_sym`, `next2_sym`.
`const_next2` occurs 13 times (Toy), `const_relative` 3,042,
`const_curspace` 2,099. `construct_tpl` attributes: `delay` on 685,
`labels` on 1,824, `section` on 553. `constructor.first` is negative
(−1) on 5,412. Expression operators: `lshift_exp` 4,596, `plus_exp`
4,012, `or_exp` 2,667, `mult_exp` 2,416, `sub_exp` 1,749, `and_exp` 773,
`minus_exp` 404, `rshift_exp` 378, `not_exp` 262, `xor_exp` 151,
`div_exp` 32 (always an operand divided by a constant).

Per-file maxima: 20,356 operand symbols; 5,055 scopes; 4,646 constructors
in one table; 3,273 varnode symbols; 1,711 user ops; 646 tables; 1,024
entries in one varnode list; 571 ops in one template; 27 operands, 19
print pieces, 16 context changes and 4 commits in one constructor; 10
inputs to one op; 256 children and 16 pairs in one decision node;
decision depth 19; element nesting 27; 3 mask words in a block; 24 source
files; 9 `space` elements.

Language features by spec source: `delayslot` in 10 source files (26
compiled languages have `maxdelay`), `globalset` in 22 source files,
`crossbuild` in Hexagon only, `inst_next2` in Toy only.
