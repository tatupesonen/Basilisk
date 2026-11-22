# Runs (D07 and the plan comparison)

Mac: the reference directory beside the checkout (Darwin arm64, Apple
clang 17, libc++). Host: the build host's reference
(`$BASILISK_REFERENCE_DIR`, Debian g++ 14.2, libstdc++), through
`scripts/remote.sh run -- bash -c '…'`. Every run with `LC_ALL=C`. `DT` =
the data-test directory of the Ghidra tree, `REF` = the reference
directory. Console scripts are run as `echo | SLEIGHHOME=REF
REF/bin/decomp_bk -i SCRIPT` after `load test file DT/elseif.xml` unless
another file is named.

## X1. The six root actions (Mac)

`option setaction <root>` then `bk list actions`, for `decompile`,
`jumptable`, `normalize`, `paramid`, `register`, `firstpass`
(`list-actions.txt`). Line counts: 243, 157, 179, 183, 140, 16. A pool or
group with no member in the root's groups is absent (`firstpass` has no
`oppool1`); a group keeps its flags and nesting.

## X2. Option quirks in the console (Mac)

| Script | Result |
|---|---|
| `option togglerule earlyremoval off`, `bk list actions`, `option currentaction decompile splitcopy off`, `bk list actions` | `D` on `earlyremoval` in the first list, gone in the second (242 lines): the root was derived again and every rule is enabled |
| `floatprint.xml`: `option nanignore none`, list, `option splitdatatype struct`, list, `option nanignore none`, list | `D` on `ignorenan`; then no `D` although both NaN flags are off; the third command prints `NaN ignore configuration unchanged` and disables the rule again |
| `option setaction firstpass`, `option currentaction firstpass base off`, then `list action` | exit 139 (SIGSEGV): the root is empty, `getCurrent()` is null. Same with `option nanignore all`, `option warning earlyremoval on`, and `decompile` after `load function`. `option togglerule earlyremoval off` prints `Low-level ERROR: Missing current action` |
| `option currentaction nosuch base on` | `Low-level ERROR: Action group does not exist: nosuch` |
| `option maxlinewidth abc` | `Low-level ERROR: Bad maximum line size` (the value read is 0; not the option's own `Must specify integer linewidth`) |
| `option extrapop abc` | `Global extrapop set` (extrapop 0) |
| `option baddatacount abc`, `option maxinstruction abc` | accepted, value 0 |
| `option jumptablemax abc` | `Must specify integer maximum` |
| `option jumptablemax 0x10` | accepted (16) |
| `option maxinstruction -5` | `Bad maxinstruction parameter` |
| `option braceformat same function` | `Unknown brace style: function` (the code reads category then style; the comment in `options.cc` 588–597 says the reverse) |
| `option braceformat function next` | `Brace formatting for function set to next` |
| `option nosuchoption`, `option addr` | `Unknown option` |
| `option readonly` | `Read-only option must be set "on" or "off"` |
| `option commentheader header` | `Header comment type header turned on` |

## X3. `ActionGroup::printState` past the end (Mac, Ghidra's own console)

`REF/bin/decomp` (not the extension's console): `load test file
DT/condmulti.xml`, `execute test command 1-6`, `break action mainloop`,
`decompile`, then `continue` six times. Output: `Break at
universal:fullloop:mainloop:redundbranch start`, `…constantptr start`,
`…determinedbranch start`, `Break at universal:fullloop:mainloop`,
`…stackstall start`, `…redundbranch start`, then exit 139 on the next
`continue`. Cause (read, `action.cc` 517–519 and 444–454; seen in the
action oracle as the state `<past-the-end>`, 125 rows of 10,398): an
action breakpoint on a group fires after a member made a change and
advances `state`; when that member was the last one `state` is
`list.end()`, the group's status is `status_mid`, and `printState` — which
the console calls to print `Break at …` — dereferences it.

## X4. `action_oracle` (Mac and host)

`sh build.sh REF action_oracle.cc OUT; OUT REF DT/elseif.xml 0x1006ca 1
2000`: 4.4 s on the Mac, 136,527 rows (647 `F`, 23,999 `N`, 29,960 `L`,
8,000 `S`, 2,000 `K`, 2,528 `B`, 410 `J`, 6,410 `C`, 10,398 `P`, 378 `W`,
47,802 `E`, 3,988 `Z`, 6 `!case`). Of the `P` rows 2,448 are breaks, 2,717
return a positive count. 205 performs contain a restart; 126 rounds end
with the header warning `Exceeded maximum restarts with more pending`; the
6 `!case` rows are `Function processing already started` (a root without
`rule_onceperfunc` performed a second time without a reset). Two runs
identical on each machine; Mac and host identical (sha256 `5745473d…`).

## X5. `option_oracle` (Mac and host)

`OUT REF DT/elseif.xml 0x1006ca 1 3000`: 74,055 rows; 30,350 commands
(2,450 `ok`, 16,433 `parse`, 5,469 `recov`, 5,998 `lowlevel`) over 42
names (the 38 registered options, and `hideextensions`, `structalign`,
`nosuchoption`, `addr`, which all answer `Unknown option`). Two runs
identical on each machine. **Mac and host differ in 49 rows, one cause**:
a numeric parameter of decimal digits followed by letters that are
hexadecimal digits (`12abc`) is read as 12 by libstdc++ and fails (value
0) with libc++, in `extrapop`, `indentincrement`, `commentindent`,
`baddatacount`, `jumptablemax`, `maxinstruction` (39 command rows and 10
`R`/`U` rows that follow from them). sha256 `bf9fba70…` (Mac),
`fa98b70e…` (host).

What the table shows besides (all rows equal on both machines): an empty
numeric parameter leaves the variable at its sentinel (`extrapop` with no
parameter: `Bad extrapop adjustment parameter`), any other text that is
not a number gives 0; a failed `setaction <name>` (and the three-parameter
`currentaction`) leaves `root=<name>` behind while the action object is
unchanged; `resetDefaults` does not restore the extrapop of a model, the
default model, the current evaluation model, the properties of a function,
the selected print language, the list of print languages, the Java
type-operator table or `allowcontextset` (`U` rows).

## X6. `plan_graph.py`

`python3 plan_graph.py CPP > plan_graph.txt` (text scan; the method and
its limits are in the script's head comment).

## X7. `normalizesetup` runs once per root instance (Mac, Ghidra's own console)

`REF/bin/decomp`: `load test file DT/elseif.xml`, `option setaction
normalize`, `map fun r0x1006ca testElseIf`, `load function testElseIf`,
`decompile` three times, `print actionstats`: `universal Tested=3`,
`start Tested=3`, `defaultparams Tested=3`, `extrapopsetup Tested=3`, but
`normalizesetup Tested=1`. Cause (read, `coreaction.hh:646`):
`ActionNormalizeSetup::reset` does not call `Action::reset`, so the status
`status_end` that `rule_onceperfunc` leaves is never cleared.
